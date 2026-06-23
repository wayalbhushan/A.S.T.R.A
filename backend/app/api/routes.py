"""
ASTRA REST API Blueprint Routes
Defines HTTP handlers for APK scan submissions, reports, certificate tracking, and STIX IOC feeds.
"""

from datetime import datetime, timezone
import json
import os
import uuid
from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import func, select
from werkzeug.utils import secure_filename
import structlog

from app.api.auth import generate_api_key, require_api_key, store_api_key
from app.extensions import db, limiter, redis_client
from app.models.scan import CertificateRecord, ScanRecord
from app.tasks.scan_tasks import run_scan

logger = structlog.get_logger()
api_bp = Blueprint("api", __name__)

ALLOWED_EXTENSION = ".apk"


def allowed_file(filename: str) -> bool:
    """Checks if the uploaded file has a valid APK extension."""
    return filename.lower().endswith(ALLOWED_EXTENSION)


@api_bp.route("/scan/submit", methods=["POST"])
@limiter.limit("20 per hour")
@require_api_key
def submit_scan():
    """Submits an APK file for async scan processing.
    
    Verifies file extension, saves to upload directory, and enqueues Celery task.
    """
    scan_type = request.form.get("scan_type", "deep")
    if scan_type not in ["quick", "deep"]:
        scan_type = "deep"

    if "file" not in request.files:
        return jsonify({
            "status": "error",
            "message": "No file provided. Send APK as multipart/form-data with key 'file'",
            "code": 400
        }), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({
            "status": "error",
            "message": "Empty filename",
            "code": 400
        }), 400

    if not allowed_file(file.filename):
        return jsonify({
            "status": "error",
            "message": "Only .apk files accepted",
            "code": 400
        }), 400

    scan_id = str(uuid.uuid4())
    safe_name = f"{scan_id}.apk"
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)
    apk_path = os.path.join(upload_folder, safe_name)
    file.save(apk_path)

    # Insert initial scan record into DB
    record = ScanRecord(
        id=uuid.UUID(scan_id),
        file_name=secure_filename(file.filename),
        file_hash="pending",
        status="pending"
    )
    db.session.add(record)
    db.session.commit()

    # Enqueue task to Celery
    run_scan.delay(scan_id, apk_path, scan_type)

    logger.info("scan_submitted", scan_id=scan_id, filename=file.filename, scan_type=scan_type)

    return jsonify({
        "status": "success",
        "data": {
            "scan_id": scan_id,
            "status": "pending",
            "scan_type": scan_type,
            "message": "Scan queued. Poll status endpoint.",
            "poll_url": f"/api/v1/scan/{scan_id}/status"
        }
    }), 202


@api_bp.route("/scan/<scan_id>/status", methods=["GET"])
@require_api_key
def get_scan_status(scan_id: str):
    """Retrieves the status of an ongoing or completed scan.
    
    Checks Redis cache first, falling back to PostgreSQL.
    """
    cache_key = f"scan:{scan_id}"
    cached = redis_client.get(cache_key)
    if cached:
        data = json.loads(cached)
        return jsonify({
            "status": "success",
            "data": {
                "scan_id": scan_id,
                "status": data.get("status", "complete"),
                "verdict": data.get("verdict"),
                "risk_score": data.get("risk_score")
            }
        })

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return jsonify({
            "status": "error",
            "message": "Invalid scan ID format",
            "code": 400
        }), 400

    stmt = select(ScanRecord).where(ScanRecord.id == scan_uuid)
    record = db.session.execute(stmt).scalar_one_or_none()

    if not record:
        return jsonify({
            "status": "error",
            "message": "Scan not found",
            "code": 404
        }), 404

    return jsonify({
        "status": "success",
        "data": {
            "scan_id": scan_id,
            "status": record.status,
            "verdict": record.verdict,
            "risk_score": record.risk_score
        }
    })


@api_bp.route("/scan/<scan_id>", methods=["GET"])
@require_api_key
def get_scan_result(scan_id: str):
    """Retrieves full detailed report results of a scan.
    
    Checks Redis cache first, falling back to PostgreSQL.
    """
    cache_key = f"scan:{scan_id}"
    cached = redis_client.get(cache_key)
    if cached:
        return jsonify({
            "status": "success",
            "data": json.loads(cached)
        })

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return jsonify({
            "status": "error",
            "message": "Invalid scan ID format",
            "code": 400
        }), 400

    stmt = select(ScanRecord).where(ScanRecord.id == scan_uuid)
    record = db.session.execute(stmt).scalar_one_or_none()

    if not record:
        return jsonify({
            "status": "error",
            "message": "Scan not found",
            "code": 404
        }), 404

    if record.status in ["pending", "processing"]:
        return jsonify({
            "status": "success",
            "data": {
                "scan_id": scan_id,
                "status": record.status,
                "message": "Scan in progress. Try again shortly."
            }
        })

    return jsonify({
        "status": "success",
        "data": {
            "scan_id": str(record.id),
            "status": record.status,
            "file_name": record.file_name,
            "apk_hash": record.file_hash,
            "package_name": record.package_name,
            "risk_score": record.risk_score,
            "verdict": record.verdict,
            "ml_class": record.ml_class,
            "ml_confidence": record.ml_confidence,
            "signature_verdict": record.signature_verdict,
            "vt_detection_ratio": record.vt_detection_ratio,
            "androguard_data": record.androguard_data,
            "vt_data": record.vt_data,
            "sandbox_data": record.sandbox_data,
            "ml_explanation": record.ml_explanation,
            "created_at": record.created_at.isoformat(),
            "completed_at": record.completed_at.isoformat() if record.completed_at else None
        }
    })


@api_bp.route("/certificate/<cert_hash>/pivot", methods=["GET"])
@require_api_key
def certificate_pivot(cert_hash: str):
    """Pivots database to find all APK scans sharing the same certificate signature."""
    stmt = select(ScanRecord).where(ScanRecord.cert_hash == cert_hash).order_by(ScanRecord.created_at.desc())
    records = db.session.execute(stmt).scalars().all()

    malicious_count = sum(1 for r in records if r.verdict in ["MALICIOUS", "SUSPICIOUS"])
    total = len(records)
    
    if total == 0:
        campaign_confidence = "NO DATA"
    elif total > 3 and (malicious_count / total) > 0.7:
        campaign_confidence = "HIGH"
    elif malicious_count > 1:
        campaign_confidence = "MEDIUM"
    else:
        campaign_confidence = "LOW"

    return jsonify({
        "status": "success",
        "data": {
            "cert_hash": cert_hash,
            "total_apks_scanned": total,
            "malicious_count": malicious_count,
            "campaign_confidence": campaign_confidence,
            "apks": [
                {
                    "scan_id": str(r.id),
                    "file_name": r.file_name,
                    "package_name": r.package_name,
                    "verdict": r.verdict,
                    "risk_score": r.risk_score,
                    "scanned_at": r.created_at.isoformat()
                }
                for r in records
            ]
        }
    })


@api_bp.route("/feed/iocs", methods=["GET"])
@require_api_key
def ioc_feed():
    """Generates threat intelligence feed structured in STIX 2.1 format."""
    limit = min(int(request.args.get("limit", 100)), 500)

    stmt = select(ScanRecord).where(
        ScanRecord.verdict.in_(["MALICIOUS", "SUSPICIOUS"])
    ).order_by(ScanRecord.created_at.desc()).limit(limit)
    
    records = db.session.execute(stmt).scalars().all()

    indicators = []
    for r in records:
        if not r.file_hash or r.file_hash == "pending":
            continue
        indicators.append({
            "type": "indicator",
            "id": f"indicator--{str(r.id)}",
            "spec_version": "2.1",
            "created": r.created_at.isoformat(),
            "modified": r.completed_at.isoformat() if r.completed_at else r.created_at.isoformat(),
            "name": r.file_name or "Unknown APK",
            "pattern_type": "stix",
            "pattern": f"[file:hashes.SHA256 = '{r.file_hash}']",
            "labels": [
                r.ml_class or "malware",
                r.verdict.lower() if r.verdict else "unknown"
            ],
            "extensions": {
                "x-astra-ext": {
                    "cert_hash": r.cert_hash,
                    "package_name": r.package_name,
                    "risk_score": r.risk_score,
                    "mitre_techniques": (r.sandbox_data or {}).get("mitre_attacks", [])
                }
            }
        })

    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{str(uuid.uuid4())}",
        "spec_version": "2.1",
        "created": datetime.now(timezone.utc).isoformat(),
        "objects": indicators
    }

    return jsonify({
        "status": "success",
        "data": stix_bundle
    })


@api_bp.route("/stats", methods=["GET"])
@require_api_key
def platform_stats():
    """Collects system-wide classification statistics and recent scan indexes."""
    total_scans = db.session.execute(select(func.count()).select_from(ScanRecord)).scalar() or 0
    malicious_count = db.session.execute(select(func.count()).select_from(ScanRecord).where(ScanRecord.verdict == "MALICIOUS")).scalar() or 0
    suspicious_count = db.session.execute(select(func.count()).select_from(ScanRecord).where(ScanRecord.verdict == "SUSPICIOUS")).scalar() or 0
    clean_count = db.session.execute(select(func.count()).select_from(ScanRecord).where(ScanRecord.verdict == "CLEAN")).scalar() or 0
    cert_count = db.session.execute(select(func.count()).select_from(CertificateRecord)).scalar() or 0

    recent_stmt = select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(10)
    recent = db.session.execute(recent_stmt).scalars().all()

    detection_rate = round((malicious_count + suspicious_count) / total_scans * 100, 1) if total_scans > 0 else 0.0

    return jsonify({
        "status": "success",
        "data": {
            "total_scans": total_scans,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "clean_count": clean_count,
            "detection_rate_percent": detection_rate,
            "certificates_tracked": cert_count,
            "trusted_certs_in_db": 34,
            "recent_scans": [
                {
                    "scan_id": str(r.id),
                    "file_name": r.file_name,
                    "package_name": r.package_name,
                    "verdict": r.verdict,
                    "risk_score": r.risk_score,
                    "scanned_at": r.created_at.isoformat()
                }
                for r in recent
            ]
        }
    })


@api_bp.route("/auth/generate", methods=["POST"])
def generate_key():
    """Generates a secure API key. No authentication is required for this route."""
    key = generate_api_key()
    store_api_key(key)
    logger.info("api_key_generated", ip=request.remote_addr)
    return jsonify({
        "status": "success",
        "data": {
            "api_key": key,
            "message": "Store this key safely. It will not be shown again.",
            "usage": "Header: X-API-Key: <your_key>"
        }
    }), 201
