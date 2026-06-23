"""
ASTRA Scan Tasks Module
Orchestrates the async analysis pipeline for uploaded APKs.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import select
import structlog

from app.extensions import celery, db, redis_client
from app.models.scan import ScanRecord, CertificateRecord
from app.analysis.androguard_extractor import extract
from app.analysis.ml_engine import predict, feature_names
from app.analysis.vt_client import get_file_report, get_sandbox_report, submit_file
from app.analysis.correlation import correlate
from app.analysis.cert_lookup import lookup

logger = structlog.get_logger()
CACHE_TTL = 86400  # 24 hours (Task 2)


@celery.task(bind=True, max_retries=3, default_retry_delay=60)
def run_scan(self, scan_id: str, apk_path: str, scan_type: str = "deep"):
    """Full async APK analysis pipeline.
    
    Updates ScanRecord status throughout execution.
    """
    start_time = datetime.now(timezone.utc)

    try:
        # Step 1: Update status to processing (Task 2)
        with db.session() as session:
            stmt = select(ScanRecord).where(ScanRecord.id == uuid.UUID(scan_id))
            record = session.execute(stmt).scalar_one_or_none()
            if not record:
                raise ValueError(f"ScanRecord {scan_id} not found")
            record.status = "processing"
            session.commit()

        logger.info("scan_started", scan_id=scan_id, scan_type=scan_type)

        # Step 2: Static analysis (Task 2)
        androguard_data = extract(apk_path)
        logger.info("static_analysis_complete", scan_id=scan_id, package=androguard_data.get("package_name"))

        # Step 3: Certificate lookup (Task 2)
        cert_hash = androguard_data.get("certificate", {}).get("cert_hash", "")
        cert_result = lookup(cert_hash)
        signature_verdict = cert_result["verdict"]
        logger.info("cert_lookup_complete", scan_id=scan_id, verdict=signature_verdict)

        # Step 4: ML classification (Task 2)
        feature_vector = {name: 0 for name in feature_names}

        # Map available static signals to known features
        androguard_permissions = androguard_data.get("permissions", [])
        dangerous_count = androguard_data.get("dangerous_count", 0)
        sensitive_api_count = androguard_data.get("sensitive_api_count", 0)

        # Populate overlapping feature names where possible
        if "open" in feature_vector:
            feature_vector["open"] = len(androguard_data.get("activities", []))
        if "read" in feature_vector:
            feature_vector["read"] = dangerous_count * 10
        if "write" in feature_vector:
            feature_vector["write"] = sensitive_api_count * 5
        if "getDeviceId" in feature_vector:
            feature_vector["getDeviceId"] = (
                1 if "android.permission.READ_PHONE_STATE" in androguard_permissions else 0
            )
        if "sendTextMessage" in feature_vector:
            feature_vector["sendTextMessage"] = (
                1 if "android.permission.SEND_SMS" in androguard_permissions else 0
            )
        if "READ_SMS____" in feature_vector:
            feature_vector["READ_SMS____"] = (
                1 if "android.permission.READ_SMS" in androguard_permissions else 0
            )
        if "SMS_SEND____" in feature_vector:
            feature_vector["SMS_SEND____"] = (
                1 if "android.permission.SEND_SMS" in androguard_permissions else 0
            )
        if "ACCESS_PERSONAL_INFO___" in feature_vector:
            feature_vector["ACCESS_PERSONAL_INFO___"] = dangerous_count
        if "NETWORK_ACCESS____" in feature_vector:
            feature_vector["NETWORK_ACCESS____"] = (
                1 if "android.permission.INTERNET" in androguard_permissions else 0
            )

        ml_result = predict(feature_vector)
        logger.info("ml_classification_complete", scan_id=scan_id, class_name=ml_result["class_name"], confidence=ml_result["confidence"])

        # Step 5: VirusTotal AV report (Task 2)
        apk_hash = androguard_data["apk_hash"]
        vt_report = get_file_report(apk_hash)

        if not vt_report.get("found") and scan_type == "deep":
            submit_file(apk_path)
            vt_report = {
                "found": False,
                "detection_ratio": "0/0",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "engine_verdicts": []
            }

        logger.info("vt_report_fetched", scan_id=scan_id, found=vt_report.get("found"), ratio=vt_report.get("detection_ratio"))

        # Step 6: Sandbox report (deep scan only) (Task 2)
        if scan_type == "deep":
            sandbox_report = get_sandbox_report(apk_hash)
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

        logger.info("sandbox_report_fetched", scan_id=scan_id, sandbox_count=sandbox_report.get("sandbox_count", 0))

        # Step 7: Correlation (Task 2)
        final_result = correlate(
            androguard_data=androguard_data,
            ml_result=ml_result,
            vt_report=vt_report,
            sandbox_report=sandbox_report,
            signature_verdict=signature_verdict
        )

        logger.info("correlation_complete", scan_id=scan_id, risk_score=final_result["risk_score"], verdict=final_result["verdict"])

        # Step 8: Update or create CertificateRecord (Task 2)
        if cert_hash:
            with db.session() as session:
                cert_stmt = select(CertificateRecord).where(CertificateRecord.cert_hash == cert_hash)
                cert_record = session.execute(cert_stmt).scalar_one_or_none()

                is_malicious = final_result["verdict"] in ["MALICIOUS", "SUSPICIOUS"]

                if cert_record:
                    cert_record.scan_count += 1
                    if is_malicious:
                        cert_record.malicious_count += 1
                else:
                    issuer = androguard_data.get("certificate", {}).get("issuer", "Unknown")
                    subject = androguard_data.get("certificate", {}).get("subject", "Unknown")
                    cert_record = CertificateRecord(
                        cert_hash=cert_hash,
                        issuer=issuer,
                        subject=subject,
                        scan_count=1,
                        malicious_count=1 if is_malicious else 0
                    )
                    session.add(cert_record)
                session.commit()

        # Step 9: Update ScanRecord with all results (Task 2)
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        with db.session() as session:
            stmt = select(ScanRecord).where(ScanRecord.id == uuid.UUID(scan_id))
            record = session.execute(stmt).scalar_one_or_none()

            record.status = "complete"
            record.file_hash = apk_hash
            record.risk_score = int(final_result["risk_score"])
            record.verdict = final_result["verdict"]
            record.ml_class = final_result["malware_family"]
            record.ml_confidence = final_result["ml_confidence"]
            record.signature_verdict = signature_verdict
            record.vt_detection_ratio = vt_report.get("detection_ratio", "0/0")
            record.androguard_data = androguard_data
            record.vt_data = vt_report
            record.sandbox_data = sandbox_report
            record.ml_explanation = {
                "top_features": ml_result.get("top_features", []),
                "all_probabilities": ml_result.get("all_probabilities", {})
            }
            record.cert_hash = cert_hash or None
            record.package_name = androguard_data.get("package_name")
            record.completed_at = datetime.now(timezone.utc)
            session.commit()

        # Step 10: Cache result in Redis (Task 2)
        cache_key = f"scan:{scan_id}"
        cache_data = {
            "scan_id": scan_id,
            "status": "complete",
            "file_name": record.file_name,
            "apk_hash": apk_hash,
            "package_name": record.package_name,
            "risk_score": final_result["risk_score"],
            "verdict": final_result["verdict"],
            "confidence_level": final_result["confidence_level"],
            "malware_family": final_result["malware_family"],
            "threat_summary": final_result["threat_summary"],
            "signal_scores": final_result["signal_scores"],
            "ml_explanation": record.ml_explanation,
            "mitre_attacks": final_result["mitre_attacks"],
            "iocs": final_result["iocs"],
            "dangerous_permissions": final_result["dangerous_permissions"],
            "sensitive_apis": final_result["sensitive_apis"],
            "vt_detection_ratio": record.vt_detection_ratio,
            "signature_verdict": signature_verdict,
            "cert_lookup": cert_result,
            "scan_duration_seconds": elapsed,
            "completed_at": record.completed_at.isoformat()
        }

        redis_client.setex(
            cache_key,
            CACHE_TTL,
            json.dumps(cache_data)
        )

        logger.info("scan_complete_cached", scan_id=scan_id, duration=elapsed, verdict=final_result["verdict"])

    except Exception as exc:
        logger.error("scan_failed", scan_id=scan_id, error=str(exc), exc_info=True)
        try:
            with db.session() as session:
                stmt = select(ScanRecord).where(ScanRecord.id == uuid.UUID(scan_id))
                record = session.execute(stmt).scalar_one_or_none()
                if record:
                    record.status = "failed"
                    session.commit()
        except Exception:
            pass
        raise self.retry(exc=exc)
