"""
ASTRA REST API Blueprint Routes
Defines HTTP handlers for APK scan submissions, reports, certificate tracking, and STIX IOC feeds.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import uuid
import zipfile
from flask import Blueprint, current_app, jsonify, request, Response
from sqlalchemy import func, select
from werkzeug.utils import secure_filename
import structlog

from app.api.auth import generate_api_key, require_api_key, store_api_key
from app.extensions import db, limiter, redis_client
from app.models.scan import CertificateRecord, ScanRecord
from app.tasks.scan_tasks import run_scan
from app.analysis.cert_lookup import TRUSTED_HASHES
from app.analysis.takedown import build_takedown_data, is_eligible
from app.analysis.takedown_pdf import build_takedown_pdf
from app.version import ENGINE_VERSION

logger = structlog.get_logger()
api_bp = Blueprint("api", __name__)

ALLOWED_EXTENSION = ".apk"
STALE_SCAN_SECONDS = int(os.environ.get("STALE_SCAN_SECONDS", 600))


def _expire_if_stale(record: ScanRecord) -> bool:
    """Marks a scan as failed if it has remained pending or processing past STALE_SCAN_SECONDS."""
    if not record or record.status not in ["pending", "processing"]:
        return False

    ts = record.updated_at or record.created_at
    if not ts:
        return False

    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    now_utc = datetime.now(timezone.utc)
    if (now_utc - ts).total_seconds() > STALE_SCAN_SECONDS:
        try:
            record.status = "failed"
            record.error_message = "Scan did not finish (worker stopped). Please re-submit."
            db.session.commit()
            logger.info("scan_stale_marked_failed", scan_id=str(record.id))
            return True
        except Exception as e:
            db.session.rollback()
            logger.error("scan_stale_expire_failed", scan_id=str(record.id), error=str(e))
            return False

    return False


def allowed_file(filename: str) -> bool:
    """Checks if the uploaded file has a valid APK extension."""
    return filename.lower().endswith(ALLOWED_EXTENSION)


def validate_apk_archive(path: str) -> tuple[bool, str]:
    """Validates APK archive structure without relying on libmagic header guesses.
    
    Checks ZIP validity, presence of AndroidManifest.xml, absence of nested bundles,
    and sanity checks entry count and total uncompressed size. Never raises.
    """
    try:
        if not zipfile.is_zipfile(path):
            return False, "This file is not a valid ZIP or APK archive."

        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()
                if "AndroidManifest.xml" not in names:
                    if "manifest.json" in names or any(n.lower().endswith(".apk") for n in names):
                        return False, "This looks like a bundle (XAPK or split APK). Upload the base APK from inside it."
                    return False, "No AndroidManifest.xml found. This does not look like an Android APK."

                # Cheap sanity check only: entry count over 100000 or sum of file_size over MAX_UNCOMPRESSED_MB
                # Note: this is a sanity check, not full zip bomb protection.
                max_uncompressed_mb = int(os.environ.get("MAX_UNCOMPRESSED_MB", 2048))
                max_uncompressed_bytes = max_uncompressed_mb * 1024 * 1024

                infolist = zf.infolist()
                if len(infolist) > 100000:
                    return False, "The archive expands to an unusually large size and was rejected."

                total_uncompressed = sum(info.file_size for info in infolist)
                if total_uncompressed > max_uncompressed_bytes:
                    return False, "The archive expands to an unusually large size and was rejected."

                return True, ""
        except zipfile.BadZipFile:
            return False, "The archive is corrupt and could not be read."
        except Exception:
            return False, "The archive is corrupt and could not be read."
    except Exception:
        return False, "This file is not a valid ZIP or APK archive."


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

    force = request.form.get("force", "false").lower() == "true"

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

    file_size_bytes = os.path.getsize(apk_path)

    # Validate by zip structure instead of libmagic header guessing
    is_valid, validation_reason = validate_apk_archive(apk_path)
    if not is_valid:
        magic_type = "unknown"
        try:
            import magic
            with open(apk_path, "rb") as f_diag:
                magic_type = magic.from_buffer(f_diag.read(2048), mime=True)
        except Exception:
            magic_type = "error"

        if os.path.exists(apk_path):
            os.remove(apk_path)

        logger.warning(
            "upload_rejected",
            reason=validation_reason,
            size_bytes=file_size_bytes,
            libmagic_type=magic_type,
            filename=file.filename
        )
        return jsonify({
            "status": "error",
            "message": validation_reason,
            "code": 400
        }), 400

    logger.info("upload_accepted", size_bytes=file_size_bytes, filename=file.filename)

    # Compute SHA-256 of the saved file
    sha256 = hashlib.sha256()
    with open(apk_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    sha256_hash = sha256.hexdigest()

    SCAN_TYPE_RANKS = {"quick": 1, "deep": 2}
    requested_rank = SCAN_TYPE_RANKS.get(scan_type, 2)

    if not force:
        existing_record = db.session.execute(
            select(ScanRecord)
            .where(ScanRecord.file_hash == sha256_hash)
            .order_by(ScanRecord.created_at.desc())
        ).scalars().first()

        if existing_record and existing_record.status in ["pending", "processing"]:
            if _expire_if_stale(existing_record):
                existing_record = None

        if existing_record and existing_record.engine_version == ENGINE_VERSION:
            existing_rank = SCAN_TYPE_RANKS.get(existing_record.scan_type, 0)

            # a. Existing record with status "complete" AND rank >= requested rank
            # (or its scan_type is NULL and requested type is quick)
            is_satisfied = (
                existing_rank >= requested_rank or
                (existing_record.scan_type is None and scan_type == "quick")
            )
            if existing_record.status == "complete" and is_satisfied:
                if os.path.exists(apk_path):
                    os.remove(apk_path)
                logger.info("scan_dedup_hit", sha256=sha256_hash, scan_id=str(existing_record.id))
                return jsonify({
                    "status": "success",
                    "data": {
                        "scan_id": str(existing_record.id),
                        "status": "complete",
                        "scan_type": existing_record.scan_type,
                        "cached": True,
                        "message": "Identical APK already analyzed. Returning existing result.",
                        "poll_url": f"/api/v1/scan/{existing_record.id}/status"
                    }
                }), 200

            # b. Existing record with status "pending" or "processing" AND rank >= requested rank
            elif existing_record.status in ["pending", "processing"] and existing_rank >= requested_rank:
                if os.path.exists(apk_path):
                    os.remove(apk_path)
                logger.info("scan_dedup_inflight", sha256=sha256_hash, scan_id=str(existing_record.id))
                return jsonify({
                    "status": "success",
                    "data": {
                        "scan_id": str(existing_record.id),
                        "status": existing_record.status,
                        "scan_type": existing_record.scan_type,
                        "cached": False,
                        "message": "Identical APK is already being analyzed.",
                        "poll_url": f"/api/v1/scan/{existing_record.id}/status"
                    }
                }), 202

    # c. Otherwise (no match, failed scan, lower scan_type, or force=true):
    record = ScanRecord(
        id=uuid.UUID(scan_id),
        file_name=secure_filename(file.filename),
        file_hash=sha256_hash,
        scan_type=scan_type,
        engine_version=ENGINE_VERSION,
        status="pending"
    )
    db.session.add(record)
    db.session.commit()

    # Enqueue task to Celery
    run_scan.delay(scan_id, apk_path, scan_type, force)

    logger.info("scan_submitted", scan_id=scan_id, filename=file.filename, scan_type=scan_type)

    return jsonify({
        "status": "success",
        "data": {
            "scan_id": scan_id,
            "status": "pending",
            "scan_type": scan_type,
            "cached": False,
            "message": "Scan queued. Poll status endpoint.",
            "poll_url": f"/api/v1/scan/{scan_id}/status"
        }
    }), 202


@api_bp.route("/scan/<scan_id>/status", methods=["GET"])
@limiter.limit("600 per hour")
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
                "risk_score": data.get("risk_score"),
                "error_message": data.get("error_message")
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

    _expire_if_stale(record)

    return jsonify({
        "status": "success",
        "data": {
            "scan_id": scan_id,
            "status": record.status,
            "verdict": record.verdict,
            "risk_score": record.risk_score,
            "error_message": record.error_message
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

    _expire_if_stale(record)

    if record.status in ["pending", "processing"]:
        return jsonify({
            "status": "success",
            "data": {
                "scan_id": scan_id,
                "status": record.status,
                "error_message": record.error_message,
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
            "threat_summary": record.threat_summary,
            "confidence_level": record.confidence_level,
            "signals_used": record.signals_used,
            "signals_total": 4,
            "error_message": record.error_message,
            "ml_class": record.ml_class,
            "ml_confidence": record.ml_confidence,
            "static_ml_class": record.static_ml_class,
            "static_ml_confidence": record.static_ml_confidence,
            "static_ml_result": {
                "class_name": record.static_ml_class,
                "confidence": record.static_ml_confidence,
                "top_features": (record.ml_explanation or {}).get(
                    "static_top_features", []
                )
            },
            "signal_scores": record.signal_scores,
            "model_agreement": record.model_agreement,
            "signature_verdict": record.signature_verdict,
            "vt_detection_ratio": record.vt_detection_ratio,
            "vt_intel": (record.vt_data or {}).get("intel"),
            "vt_status": (record.vt_data or {}).get("status"),
            "androguard_data": record.androguard_data,
            "ioc_summary": record.ioc_summary,
            "extracted_iocs": (record.androguard_data or {}).get(
                "extracted_iocs", {}
            ),
            "vt_data": record.vt_data,
            "sandbox_data": record.sandbox_data,
            "ml_explanation": record.ml_explanation,
            "impersonation": record.impersonation,
            "risk_floor": record.risk_floor,
            "risk_floor_reason": record.risk_floor_reason,
            "created_at": record.created_at.isoformat(),
            "completed_at": record.completed_at.isoformat() if record.completed_at else None
        }
    })


def _get_eligible_takedown_scan(scan_id: str):
    """Validates scan UUID, checks record existence, completeness, and eligibility.
    Returns (scan_dict, None) on success, or (None, (json_response, status_code)) on failure.
    """
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return None, (jsonify({
            "status": "error",
            "message": "Invalid scan ID format",
            "code": 400
        }), 400)

    stmt = select(ScanRecord).where(ScanRecord.id == scan_uuid)
    record = db.session.execute(stmt).scalar_one_or_none()

    if not record:
        return None, (jsonify({
            "status": "error",
            "message": "Scan not found",
            "code": 404
        }), 404)

    _expire_if_stale(record)

    if record.status != "complete":
        return None, (jsonify({
            "status": "error",
            "message": "Scan is not complete.",
            "code": 409
        }), 409)

    vt_threat_label = (((record.vt_data or {}).get("intel") or {}).get("threat") or {}).get("label")
    scan_dict = {
        "id": str(record.id),
        "file_name": record.file_name,
        "file_hash": record.file_hash,
        "package_name": record.package_name,
        "verdict": record.verdict,
        "risk_score": record.risk_score,
        "risk_floor": record.risk_floor,
        "risk_floor_reason": record.risk_floor_reason,
        "confidence_level": record.confidence_level,
        "threat_summary": record.threat_summary,
        "signals_used": record.signals_used,
        "signal_scores": record.signal_scores,
        "signature_verdict": record.signature_verdict,
        "vt_detection_ratio": record.vt_detection_ratio,
        "vt_threat_label": vt_threat_label,
        "impersonation": record.impersonation,
        "androguard_data": record.androguard_data,
        "engine_version": record.engine_version,
        "completed_at": record.completed_at.isoformat() if record.completed_at else None,
    }

    eligible, reason = is_eligible(scan_dict)
    if not eligible:
        return None, (jsonify({
            "status": "error",
            "message": reason,
            "code": 409
        }), 409)

    return scan_dict, None


@api_bp.route("/scan/<scan_id>/takedown", methods=["GET"])
@limiter.limit("30 per hour")
@require_api_key
def get_scan_takedown(scan_id: str):
    """Generates a structured takedown evidence pack for a completed scan."""
    scan_dict, err = _get_eligible_takedown_scan(scan_id)
    if err:
        return err

    takedown_data = build_takedown_data(scan_dict)
    return jsonify({
        "status": "success",
        "data": takedown_data
    }), 200


@api_bp.route("/scan/<scan_id>/takedown/pdf", methods=["GET"])
@limiter.limit("20 per hour")
@require_api_key
def get_scan_takedown_pdf(scan_id: str):
    """Generates a downloadable takedown evidence pack PDF for a completed scan."""
    scan_dict, err = _get_eligible_takedown_scan(scan_id)
    if err:
        return err

    try:
        takedown_data = build_takedown_data(scan_dict)
        pdf_bytes = build_takedown_pdf(takedown_data, compress=True)
    except Exception as e:
        logger.error("takedown_pdf_failed", scan_id=scan_id, error=str(e))
        return jsonify({
            "status": "error",
            "message": "Could not generate the PDF.",
            "code": 500
        }), 500

    short_id = scan_id[:8]
    filename = f"astra-takedown-{short_id}.pdf"
    logger.info("takedown_pdf_generated", scan_id=scan_id, byte_size=len(pdf_bytes))

    response = Response(pdf_bytes, mimetype="application/pdf")
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Cache-Control"] = "no-store"
    return response


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
    low_risk_count = db.session.execute(select(func.count()).select_from(ScanRecord).where(ScanRecord.verdict == "LOW RISK")).scalar() or 0
    cert_count = db.session.execute(select(func.count()).select_from(CertificateRecord)).scalar() or 0

    recent_stmt = select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(10)
    recent = db.session.execute(recent_stmt).scalars().all()

    detection_rate = round((malicious_count + suspicious_count) / total_scans * 100, 1) if total_scans > 0 else 0.0

    now_utc = datetime.now(timezone.utc)
    recent_scans = []
    for r in recent:
        status = r.status
        if status in ["pending", "processing"]:
            ts = r.updated_at or r.created_at
            if ts:
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if (now_utc - ts).total_seconds() > STALE_SCAN_SECONDS:
                    status = "failed"
        imp = r.impersonation or {}
        imp_verdict = imp.get("verdict")
        imp_corr = set((imp.get("evidence") or {}).get("corroboration") or [])
        imp_strong = (
            imp_verdict == "IMPERSONATION"
            and bool("exfil" in imp_corr or "other_brand_cert" in imp_corr)
        )
        recent_scans.append({
            "scan_id": str(r.id),
            "file_name": r.file_name,
            "package_name": r.package_name,
            "verdict": r.verdict,
            "risk_score": r.risk_score,
            "status": status,
            "scanned_at": r.created_at.isoformat(),
            "impersonation_verdict": imp_verdict,
            "impersonation_brand": imp.get("brand_name"),
            "impersonation_strong": imp_strong,
        })

    return jsonify({
        "status": "success",
        "data": {
            "total_scans": total_scans,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "clean_count": clean_count,
            "low_risk_count": low_risk_count,
            "detection_rate_percent": detection_rate,
            "certificates_tracked": cert_count,
            "trusted_certs_in_db": len(TRUSTED_HASHES),
            "recent_scans": recent_scans
        }
    })


@api_bp.route("/auth/generate", methods=["POST"])
@limiter.limit("5 per hour")
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
