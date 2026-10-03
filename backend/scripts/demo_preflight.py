"""
ASTRA Demo Preflight Verification Script
Runs end-to-end verification of demo manifest samples, API health, statistics,
STIX feed, and certificate pivot endpoints.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional
import requests


def request_with_retry(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    """Sends HTTP request with automatic single retry on HTTP 429 after 10 seconds."""
    resp = session.request(method, url, **kwargs)
    if resp.status_code == 429:
        time.sleep(10)
        resp = session.request(method, url, **kwargs)
    return resp


def verify_pdf_xref(pdf_bytes: bytes) -> tuple[bool, str]:
    """Validates PDF start header and cross-reference table pointer."""
    if not pdf_bytes.startswith(b"%PDF"):
        return False, "PDF content does not start with %PDF"
    last_sx = pdf_bytes.rfind(b"startxref")
    if last_sx == -1:
        return False, "startxref token not found in PDF bytes"
    after_sx = pdf_bytes[last_sx + len(b"startxref"):].strip()
    if not after_sx:
        return False, "No data after startxref token"
    xref_offset_str = after_sx.split()[0]
    try:
        xref_offset = int(xref_offset_str)
    except ValueError:
        return False, f"Invalid startxref offset string: {xref_offset_str!r}"
    if xref_offset < 0 or xref_offset >= len(pdf_bytes):
        return False, f"startxref offset {xref_offset} is out of bounds (length: {len(pdf_bytes)})"
    if not pdf_bytes[xref_offset:].startswith(b"xref"):
        return False, f"Byte offset {xref_offset} does not point to xref block"
    return True, ""


def main():
    parser = argparse.ArgumentParser(description="Run ASTRA demo preflight checks.")
    parser.add_argument("--base-url", default="http://localhost:5000", help="Base URL of ASTRA backend service")
    parser.add_argument("--force", action="store_true", help="Force re-scan bypass of cache")
    parser.add_argument("--timeout", type=int, default=300, help="Per-scan completion timeout in seconds")
    parser.add_argument("--no-pace", action="store_true", help="Disable pacing for VirusTotal rate limits")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    api_base = f"{base_url}/api/v1"

    session = requests.Session()
    api_key = os.environ.get("MASTER_API_KEY", "dev-master-key")
    session.headers.update({"X-API-Key": api_key})

    backend_dir = Path(__file__).resolve().parent.parent
    manifest_path = backend_dir / "demo_manifest.json"
    samples_dir = backend_dir / "demo_samples"

    overall_pass = True

    # 1. Health check
    print(f"Step 1: Checking health at {base_url}/health ...")
    try:
        health_resp = request_with_retry(session, "GET", f"{base_url}/health")
        if health_resp.status_code != 200:
            print(f"Health check failed with HTTP {health_resp.status_code}: {health_resp.text}")
            overall_pass = False
        else:
            health_json = health_resp.json()
            if health_json.get("status") != "healthy":
                print(f"Health check status is '{health_json.get('status')}', expected 'healthy'")
                overall_pass = False
            else:
                print("Health check passed: healthy")
    except Exception as e:
        print(f"Health check request error: {e}")
        overall_pass = False

    # Load manifest
    if not manifest_path.is_file():
        print(f"Error: manifest file not found at {manifest_path}")
        print("PREFLIGHT: FAIL")
        sys.exit(1)

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        print(f"Error reading manifest: {e}")
        print("PREFLIGHT: FAIL")
        sys.exit(1)

    samples: List[Dict[str, Any]] = manifest.get("samples", [])
    results = []
    completed_scans = []
    submission_202_timestamps = []

    # 2 & 3. Process each sample
    for sample in samples:
        filename = sample.get("file", "")
        is_required = sample.get("required", False)
        scan_type = sample.get("scan_type", "quick")
        expect_verdict = sample.get("expect_verdict", [])
        expect_impersonation = sample.get("expect_impersonation")
        expect_takedown = sample.get("expect_takedown", False)

        apk_path = samples_dir / filename
        row = {
            "sample": filename,
            "seconds": 0.0,
            "cached": "-",
            "verdict": "-",
            "risk": "-",
            "impersonation": "-",
            "vt": "-",
            "takedown": "-",
            "status": "PASS",
            "reason": ""
        }

        if not apk_path.is_file():
            if is_required:
                row["status"] = "FAIL"
                row["reason"] = "required sample missing"
                overall_pass = False
            else:
                row["status"] = "SKIP"
                row["reason"] = f"File missing: {apk_path}"
            results.append(row)
            continue

        # Pacing check before upload
        if not args.no_pace:
            now = time.time()
            recent_202s = [t for t in submission_202_timestamps if now - t < 60]
            if len(recent_202s) >= 3:
                oldest = min(recent_202s)
                sleep_needed = 61.0 - (now - oldest)
                if sleep_needed > 0:
                    print(f"pacing for the VirusTotal limit (sleeping {sleep_needed:.1f}s)")
                    time.sleep(sleep_needed)

        start_time = time.time()
        try:
            with open(apk_path, "rb") as f:
                file_bytes = f.read()

            data = {"scan_type": scan_type}
            if args.force:
                data["force"] = "true"

            files = {"file": (filename, file_bytes, "application/vnd.android.package-archive")}
            submit_resp = request_with_retry(session, "POST", f"{api_base}/scan/submit", data=data, files=files)

            if submit_resp.status_code not in (200, 202):
                raise RuntimeError(f"Submit returned HTTP {submit_resp.status_code}: {submit_resp.text}")

            if submit_resp.status_code == 202:
                submission_202_timestamps.append(time.time())

            submit_data = submit_resp.json().get("data", {})
            scan_id = submit_data.get("scan_id")
            if not scan_id:
                raise RuntimeError(f"No scan_id in submit response: {submit_resp.text}")

            is_cached = bool(submit_data.get("cached", False))
            row["cached"] = is_cached

            scan_status = submit_data.get("status")
            if not is_cached and scan_status != "complete":
                # Poll status
                poll_url = f"{api_base}/scan/{scan_id}/status"
                poll_start = time.time()
                while True:
                    if time.time() - poll_start > args.timeout:
                        raise TimeoutError(f"Scan {scan_id} timed out after {args.timeout}s")
                    time.sleep(2)
                    status_resp = request_with_retry(session, "GET", poll_url)
                    if status_resp.status_code == 200:
                        st_data = status_resp.json().get("data", {})
                        scan_status = st_data.get("status")
                        if scan_status == "complete":
                            break
                        if scan_status == "failed":
                            err_msg = st_data.get("error_message") or "Scan failed on worker"
                            raise RuntimeError(f"Scan {scan_id} marked as failed: {err_msg}")
                    elif status_resp.status_code == 429:
                        continue
                    else:
                        raise RuntimeError(f"Poll returned HTTP {status_resp.status_code}: {status_resp.text}")

            elapsed = round(time.time() - start_time, 2)
            row["seconds"] = elapsed

            # Fetch scan details
            detail_resp = request_with_retry(session, "GET", f"{api_base}/scan/{scan_id}")
            if detail_resp.status_code != 200:
                raise RuntimeError(f"Get scan detail returned HTTP {detail_resp.status_code}: {detail_resp.text}")

            scan_result = detail_resp.json().get("data", {})
            completed_scans.append(scan_result)

            verdict = scan_result.get("verdict")
            risk = scan_result.get("risk_score")
            imp_dict = scan_result.get("impersonation") or {}
            imp_verdict = imp_dict.get("verdict", "NONE")
            vt_status = scan_result.get("vt_status") or "-"

            row["verdict"] = verdict
            row["risk"] = risk
            row["impersonation"] = imp_verdict
            row["vt"] = vt_status

            if vt_status in ("rate_limited", "unavailable"):
                raise AssertionError("VirusTotal data missing during scan, rerun with --force after a minute")
            elif vt_status == "disabled":
                if row["status"] != "FAIL":
                    row["status"] = "WARN"

            if expect_verdict and verdict not in expect_verdict:
                raise AssertionError(f"Verdict '{verdict}' not in expected {expect_verdict}")

            if expect_impersonation is not None and imp_verdict not in expect_impersonation:
                raise AssertionError(f"Impersonation '{imp_verdict}' not in expected {expect_impersonation}")

            # Step 3: Takedown verification
            td_resp = request_with_retry(session, "GET", f"{api_base}/scan/{scan_id}/takedown")
            if expect_takedown:
                if td_resp.status_code != 200:
                    raise AssertionError(f"Expected takedown 200, got HTTP {td_resp.status_code}")

                pdf_resp = request_with_retry(session, "GET", f"{api_base}/scan/{scan_id}/takedown/pdf")
                if pdf_resp.status_code != 200:
                    raise AssertionError(f"Expected takedown PDF 200, got HTTP {pdf_resp.status_code}")

                valid_pdf, pdf_err = verify_pdf_xref(pdf_resp.content)
                if not valid_pdf:
                    raise AssertionError(f"Invalid PDF generated: {pdf_err}")
                row["takedown"] = "PASS"
            else:
                if td_resp.status_code != 409:
                    raise AssertionError(f"Expected takedown 409, got HTTP {td_resp.status_code}")
                row["takedown"] = "PASS"

        except Exception as e:
            elapsed = round(time.time() - start_time, 2)
            row["seconds"] = elapsed
            row["status"] = "FAIL"
            row["reason"] = str(e)
            overall_pass = False

        results.append(row)

    # Step 4: System endpoints
    print("\nStep 4: Checking system endpoints ...")
    # stats
    try:
        stats_resp = request_with_retry(session, "GET", f"{api_base}/stats")
        if stats_resp.status_code != 200:
            print(f"Stats check failed with HTTP {stats_resp.status_code}")
            overall_pass = False
        else:
            stats_data = stats_resp.json().get("data", {})
            if "total_scans" in stats_data and "malicious_count" in stats_data:
                print(f"Stats check passed: total_scans={stats_data['total_scans']}, malicious_count={stats_data['malicious_count']}")
            else:
                print("Stats check failed: missing total_scans or malicious_count")
                overall_pass = False
    except Exception as e:
        print(f"Stats request error: {e}")
        overall_pass = False

    # feed/iocs
    try:
        feed_resp = request_with_retry(session, "GET", f"{api_base}/feed/iocs")
        if feed_resp.status_code != 200:
            print(f"IOC feed check failed with HTTP {feed_resp.status_code}")
            overall_pass = False
        else:
            feed_data = feed_resp.json().get("data", {})
            if feed_data.get("type") == "bundle":
                objects_count = len(feed_data.get("objects", []))
                print(f"IOC feed check passed: type=bundle ({objects_count} objects)")
            else:
                print(f"IOC feed check failed: type is '{feed_data.get('type')}', expected 'bundle'")
                overall_pass = False
    except Exception as e:
        print(f"IOC feed request error: {e}")
        overall_pass = False

    # certificate pivot
    cert_hash_to_pivot = None
    for res in completed_scans:
        h = ((res.get("impersonation") or {}).get("evidence") or {}).get("cert_hash")
        if h:
            cert_hash_to_pivot = h
            break

    if cert_hash_to_pivot:
        try:
            p_resp = request_with_retry(session, "GET", f"{api_base}/certificate/{cert_hash_to_pivot}/pivot")
            if p_resp.status_code == 200:
                print(f"Certificate pivot check passed for {cert_hash_to_pivot[:16]}...: HTTP 200")
            else:
                print(f"Certificate pivot check failed with HTTP {p_resp.status_code}")
                overall_pass = False
        except Exception as e:
            print(f"Certificate pivot request error: {e}")
            overall_pass = False
    else:
        print("Certificate pivot check: SKIP (no completed scan had impersonation.evidence.cert_hash)")

    # metrics (INFO only)
    try:
        metrics_resp = request_with_retry(session, "GET", f"{base_url}/metrics")
        print(f"[INFO] /metrics status: {metrics_resp.status_code}")
    except Exception as e:
        print(f"[INFO] /metrics check exception: {e}")

    # Step 5: Print table
    print("\nPreflight Results Summary:")
    col_sample = 32
    col_sec = 9
    col_cached = 8
    col_verdict = 12
    col_risk = 7
    col_imp = 18
    col_vt = 14
    col_td = 10
    col_status = 8

    header = (
        f"{'Sample':<{col_sample}} | "
        f"{'Seconds':<{col_sec}} | "
        f"{'Cached':<{col_cached}} | "
        f"{'Verdict':<{col_verdict}} | "
        f"{'Risk':<{col_risk}} | "
        f"{'Impersonation':<{col_imp}} | "
        f"{'VT':<{col_vt}} | "
        f"{'Takedown':<{col_td}} | "
        f"{'Status':<{col_status}}"
    )
    separator = "-" * len(header)
    print(separator)
    print(header)
    print(separator)

    for r in results:
        cached_str = str(r["cached"])
        sec_str = f"{r['seconds']:.2f}s" if r["seconds"] > 0 else "-"
        risk_str = str(r["risk"]) if r["risk"] != "-" else "-"
        row_str = (
            f"{r['sample']:<{col_sample}} | "
            f"{sec_str:<{col_sec}} | "
            f"{cached_str:<{col_cached}} | "
            f"{str(r['verdict']):<{col_verdict}} | "
            f"{risk_str:<{col_risk}} | "
            f"{str(r['impersonation']):<{col_imp}} | "
            f"{str(r['vt']):<{col_vt}} | "
            f"{str(r['takedown']):<{col_td}} | "
            f"{r['status']:<{col_status}}"
        )
        print(row_str)
    print(separator)

    # Any sample error details or skips
    failures = [r for r in results if r["status"] == "FAIL"]
    skips = [r for r in results if r["status"] == "SKIP"]
    if failures:
        print("\nFailures:")
        for r in failures:
            print(f"  - {r['sample']}: {r['reason']}")
    if skips:
        print("\nSkipped samples:")
        for r in skips:
            print(f"  - {r['sample']}: {r['reason']}")

    # Condition lines
    if any(r["seconds"] > 90 for r in results if r["status"] != "SKIP"):
        print("SLOW")
    if args.force:
        print("NOT CACHED")

    found_samples = [r for r in results if r["status"] != "SKIP"]
    if not found_samples:
        print("Zero samples found in demo_samples directory.")
        overall_pass = False

    if any(r["status"] == "FAIL" for r in results):
        overall_pass = False

    print("\nRun this after your LAST code or registry change. Any change gives a new engine version and invalidates saved results.")

    if overall_pass:
        print("\nPREFLIGHT: PASS")
        sys.exit(0)
    else:
        print("\nPREFLIGHT: FAIL")
        sys.exit(1)


if __name__ == "__main__":
    main()
