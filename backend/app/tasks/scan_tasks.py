"""
ASTRA Scan Tasks Module
Orchestrates the async analysis pipeline for uploaded APKs.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
import structlog

from app.extensions import celery, db, redis_client
from app.models.scan import ScanRecord, CertificateRecord
from app.analysis.androguard_extractor import (
    APKParseError,
    extract,
    extract_static_features,
    load_apk,
)
from app.analysis.ml_engine import predict_static, static_feature_names
from app.analysis.vt_client import get_file_report, get_sandbox_report, submit_file
from app.analysis.correlation import correlate
from app.analysis.cert_lookup import lookup
from app.analysis.impersonation import assess_impersonation
from app.version import ENGINE_VERSION

logger = structlog.get_logger()
CACHE_TTL = 86400  # 24 hours


def _safe_delete_file(apk_path: str, scan_id: str) -> None:
    try:
        if apk_path and os.path.exists(apk_path):
            os.remove(apk_path)
            logger.info("uploaded_apk_deleted", scan_id=scan_id)
    except Exception as cleanup_exc:
        logger.warning(
            "apk_cleanup_failed",
            scan_id=scan_id,
            error=str(cleanup_exc)
        )


def _mark_scan_failed(scan_id: str, error_message: str) -> None:
    try:
        with db.session() as session:
            stmt = select(ScanRecord).where(
                ScanRecord.id == uuid.UUID(scan_id)
            )
            record = session.execute(stmt).scalar_one_or_none()
            if record:
                record.status = "failed"
                record.error_message = error_message
                session.commit()
    except Exception as db_exc:
        logger.warning(
            "mark_scan_failed_db_error",
            scan_id=scan_id,
            error=str(db_exc)
        )


@celery.task(
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    soft_time_limit=int(os.environ.get("SCAN_SOFT_TIME_LIMIT", 240)),
    time_limit=int(os.environ.get("SCAN_SOFT_TIME_LIMIT", 240)) + 60,
)
def run_scan(self, scan_id: str, apk_path: str, scan_type: str = "deep", force_refresh: bool = False):
    """Full async APK analysis pipeline.

    Updates ScanRecord status throughout execution.
    """
    start_time = datetime.now(timezone.utc)

    try:
        # Step 1: Update status to processing
        with db.session() as session:
            stmt = select(ScanRecord).where(
                ScanRecord.id == uuid.UUID(scan_id)
            )
            record = session.execute(stmt).scalar_one_or_none()
            if not record:
                raise ValueError(f"ScanRecord {scan_id} not found")
            record.status = "processing"
            session.commit()

        logger.info("scan_started", scan_id=scan_id, scan_type=scan_type)

        load_start = datetime.now(timezone.utc)
        analysis = load_apk(apk_path)
        load_elapsed = (datetime.now(timezone.utc) - load_start).total_seconds()
        logger.info(
            "apk_loaded",
            scan_id=scan_id,
            seconds=round(load_elapsed, 2)
        )

        # Step 2: Static analysis
        androguard_data = extract(apk_path, analysis=analysis)
        logger.info(
            "static_analysis_complete",
            scan_id=scan_id,
            package=androguard_data.get("package_name")
        )

        # Step 3: Certificate lookup
        cert_hash = androguard_data.get("certificate", {}).get("cert_hash", "")
        cert_result = lookup(cert_hash)
        signature_verdict = cert_result["verdict"]
        logger.info("cert_lookup_complete", scan_id=scan_id, verdict=signature_verdict)

        # Step 3.2: Brand Impersonation Assessment
        try:
            imp = assess_impersonation(
                androguard_data.get("app_name"),
                androguard_data.get("package_name"),
                cert_hash,
                (androguard_data.get("extracted_iocs") or {}).get("secrets")
            )
        except Exception as imp_exc:
            logger.warning("impersonation_assessment_failed", scan_id=scan_id, error=str(imp_exc))
            imp = {
                "verdict": "NONE",
                "confidence": None,
                "brand_id": None,
                "brand_name": None,
                "reasons": [],
                "evidence": {}
            }

        logger.info(
            "impersonation_assessed",
            scan_id=scan_id,
            verdict=imp.get("verdict"),
            brand_id=imp.get("brand_id"),
            confidence=imp.get("confidence")
        )

        # Step 3.5: Static ML classification
        static_feature_vector = extract_static_features(
            apk_path, static_feature_names, analysis=analysis
        )
        del analysis
        static_ml_result = predict_static(static_feature_vector)
        logger.info(
            "static_ml_complete",
            scan_id=scan_id,
            class_name=static_ml_result["class_name"],
            confidence=static_ml_result["confidence"]
        )

        # Step 4: VirusTotal AV report
        apk_hash = androguard_data["apk_hash"]
        vt_report = get_file_report(apk_hash, refresh=force_refresh)

        allow_upload = os.environ.get("VT_ALLOW_UPLOAD", "false").lower() == "true"
        if scan_type == "deep" and vt_report.get("status") == "not_found" and allow_upload:
            submit_file(apk_path)
        elif vt_report.get("status") == "not_found" and not allow_upload:
            vt_report["note"] = "File not uploaded to VirusTotal (privacy default)."

        logger.info(
            "vt_report_fetched",
            scan_id=scan_id,
            found=vt_report.get("found"),
            status=vt_report.get("status"),
            ratio=vt_report.get("detection_ratio")
        )

        # Step 5: Sandbox report (deep scan only)
        if scan_type == "deep":
            sandbox_report = get_sandbox_report(apk_hash, refresh=force_refresh)
        else:
            sandbox_report = {
                "sandbox_count": 0,
                "sandbox_names": [],
                "files_written": [],
                "files_deleted": [],
                "permissions_requested": [],
                "processes_created": [],
                "tls_fingerprints": [],
                "mitre_attacks": [],
                "threats": [],
                "severity_score": 0,
                "has_network_activity": False,
                "has_file_activity": False
            }

        logger.info(
            "sandbox_report_fetched",
            scan_id=scan_id,
            sandbox_count=sandbox_report.get("sandbox_count", 0)
        )

        # Step 6: Correlation - combine all signals
        final_result = correlate(
            androguard_data=androguard_data,
            static_ml_result=static_ml_result,
            vt_report=vt_report,
            sandbox_report=sandbox_report,
            signature_verdict=signature_verdict,
            impersonation=imp
        )

        logger.info(
            "correlation_complete",
            scan_id=scan_id,
            risk_score=final_result["risk_score"],
            verdict=final_result["verdict"]
        )

        # Step 8: Update or create CertificateRecord
        if cert_hash:
            with db.session() as session:
                cert_stmt = select(CertificateRecord).where(
                    CertificateRecord.cert_hash == cert_hash
                )
                cert_record = session.execute(
                    cert_stmt
                ).scalar_one_or_none()

                is_malicious = final_result["verdict"] in [
                    "MALICIOUS", "SUSPICIOUS"
                ]

                if cert_record:
                    cert_record.scan_count += 1
                    if is_malicious:
                        cert_record.malicious_count += 1
                    session.commit()
                else:
                    issuer = androguard_data.get(
                        "certificate", {}
                    ).get("issuer", "Unknown")
                    subject = androguard_data.get(
                        "certificate", {}
                    ).get("subject", "Unknown")
                    cert_record = CertificateRecord(
                        cert_hash=cert_hash,
                        issuer=issuer,
                        subject=subject,
                        scan_count=1,
                        malicious_count=1 if is_malicious else 0
                    )
                    from sqlalchemy.exc import IntegrityError
                    try:
                        session.add(cert_record)
                        session.commit()
                    except IntegrityError:
                        session.rollback()
                        cert_record = session.execute(
                            cert_stmt
                        ).scalar_one_or_none()
                        if cert_record:
                            cert_record.scan_count += 1
                            if is_malicious:
                                cert_record.malicious_count += 1
                            session.commit()

        # Step 9: Update ScanRecord with all results
        elapsed = (
            datetime.now(timezone.utc) - start_time
        ).total_seconds()

        try:
            extracted_iocs = androguard_data.get("extracted_iocs", {})
            network = extracted_iocs.get("network", {})
            secrets = extracted_iocs.get("secrets", {})
            entropy = extracted_iocs.get("entropy_candidates", {})

            ioc_summary = {
                "urls_found": network.get("counts", {}).get("urls", 0),
                "ips_found": network.get("counts", {}).get("ips", 0),
                "domains_found": network.get("counts", {}).get("domains", 0),
                "secrets_found": secrets.get("counts", {}).get("total", 0),
                "entropy_candidates_found": entropy.get("counts", {}).get(
                    "candidates_found", 0
                ),
                "entropy_candidates_shown": entropy.get("counts", {}).get(
                    "truncated_to", 0
                ),
                "total_ioc_count": (
                    network.get("counts", {}).get("urls", 0)
                    + network.get("counts", {}).get("ips", 0)
                    + network.get("counts", {}).get("domains", 0)
                    + secrets.get("counts", {}).get("total", 0)
                ),
            }
        except Exception as summary_exc:
            logger.warning("ioc_summary_computation_failed", scan_id=scan_id, error=str(summary_exc))
            ioc_summary = {
                "urls_found": 0,
                "ips_found": 0,
                "domains_found": 0,
                "secrets_found": 0,
                "entropy_candidates_found": 0,
                "entropy_candidates_shown": 0,
                "total_ioc_count": 0,
            }

        with db.session() as session:
            stmt = select(ScanRecord).where(
                ScanRecord.id == uuid.UUID(scan_id)
            )
            record = session.execute(stmt).scalar_one_or_none()

            record.status = "complete"
            record.file_hash = apk_hash
            record.risk_score = float(final_result["risk_score"])
            record.risk_floor = final_result.get("risk_floor_applied")
            record.verdict = final_result["verdict"]
            record.threat_summary = final_result.get("threat_summary")
            record.confidence_level = final_result.get("confidence_level")
            record.signals_used = final_result.get("signals_used")
            record.ml_class = None
            record.ml_confidence = None
            record.static_ml_class = static_ml_result["class_name"]
            record.static_ml_confidence = static_ml_result["confidence"]
            record.signal_scores = final_result.get("signal_scores")
            record.model_agreement = None
            record.signature_verdict = signature_verdict
            record.vt_detection_ratio = vt_report.get(
                "detection_ratio", "0/0"
            )
            record.androguard_data = androguard_data
            record.ioc_summary = ioc_summary
            record.vt_data = vt_report
            record.sandbox_data = sandbox_report
            record.ml_explanation = {
                "top_features": [],
                "all_probabilities": {},
                "static_top_features": static_ml_result.get(
                    "top_features", []
                )
            }
            record.cert_hash = cert_hash or None
            record.package_name = androguard_data.get("package_name")
            record.impersonation = imp
            record.engine_version = ENGINE_VERSION
            record.completed_at = datetime.now(timezone.utc)
            session.commit()

            # Extract all values INSIDE session before it closes
            r_file_name = record.file_name
            r_package_name = record.package_name
            r_ml_explanation = record.ml_explanation
            r_impersonation = record.impersonation
            r_vt_ratio = record.vt_detection_ratio
            r_completed_at = record.completed_at.isoformat()
            r_signal_scores = record.signal_scores
            r_static_ml_class = record.static_ml_class
            r_static_ml_confidence = record.static_ml_confidence
            r_ioc_summary = record.ioc_summary

        # Step 10: Cache result in Redis
        # Use local variables extracted inside session - NOT record.attribute
        cache_key = f"scan:{scan_id}"
        cache_data = {
            "scan_id": scan_id,
            "status": "complete",
            "file_name": r_file_name,
            "apk_hash": apk_hash,
            "package_name": r_package_name,
            "risk_score": final_result["risk_score"],
            "risk_floor": final_result.get("risk_floor_applied"),
            "verdict": final_result["verdict"],
            "confidence_level": final_result["confidence_level"],
            "signals_used": final_result["signals_used"],
            "signals_total": final_result["signals_total"],
            "malware_family": final_result["malware_family"],
            "threat_summary": final_result["threat_summary"],
            "signal_scores": r_signal_scores,
            "impersonation": r_impersonation,
            "ml_explanation": r_ml_explanation,
            "mitre_attacks": final_result["mitre_attacks"],
            "iocs": final_result["iocs"],
            "static_ml_result": {
                "class_name": r_static_ml_class,
                "confidence": r_static_ml_confidence,
                "top_features": static_ml_result.get("top_features", [])
            },
            "dangerous_permissions": final_result[
                "dangerous_permissions"
            ],
            "sensitive_apis": final_result["sensitive_apis"],
            "vt_detection_ratio": r_vt_ratio,
            "vt_intel": vt_report.get("intel"),
            "vt_status": vt_report.get("status"),
            "vt_data": vt_report,
            "signature_verdict": signature_verdict,
            "cert_lookup": cert_result,
            "scan_duration_seconds": elapsed,
            "completed_at": r_completed_at,
            "ioc_summary": r_ioc_summary,
            "extracted_iocs": androguard_data.get("extracted_iocs", {})
        }

        redis_client.setex(
            cache_key,
            CACHE_TTL,
            json.dumps(cache_data)
        )

        logger.info(
            "scan_complete_cached",
            scan_id=scan_id,
            duration=elapsed,
            verdict=final_result["verdict"]
        )

        _safe_delete_file(apk_path, scan_id)

    except APKParseError as exc:
        logger.error(
            "scan_failed_permanent",
            scan_id=scan_id,
            error=str(exc)
        )
        _mark_scan_failed(
            scan_id,
            "Could not parse APK (file may be corrupt or not a valid Android package)"
        )
        _safe_delete_file(apk_path, scan_id)
        return

    except SoftTimeLimitExceeded as exc:
        logger.error(
            "scan_timeout",
            scan_id=scan_id,
            error=str(exc)
        )
        _mark_scan_failed(
            scan_id,
            "Analysis timed out. The APK may be too large or malformed."
        )
        _safe_delete_file(apk_path, scan_id)
        return

    except Exception as exc:
        if self.request.retries < self.max_retries:
            logger.warning(
                "scan_failed_retry",
                scan_id=scan_id,
                attempt=self.request.retries + 1,
                max_retries=self.max_retries,
                error=str(exc)
            )
            raise self.retry(exc=exc)
        else:
            logger.error(
                "scan_failed_final",
                scan_id=scan_id,
                error=str(exc)
            )
            _mark_scan_failed(
                scan_id,
                "Analysis failed after retries. Please try again."
            )
            _safe_delete_file(apk_path, scan_id)
            return