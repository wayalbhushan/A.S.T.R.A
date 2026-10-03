"""
ASTRA Demo Reset Script
Clears scan records, certificate records, Redis cache keys, and uploaded APK files.
"""

import argparse
import os
from pathlib import Path
import sys

# Ensure parent directory of scripts is in sys.path so "app" imports
SCRIPTS_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPTS_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def main():
    print("Back up first: docker compose exec db pg_dump -U postgres astra > astra_backup.sql (run on the host)")

    flask_env = os.environ.get("FLASK_ENV", "").lower()
    app_env = os.environ.get("APP_ENV", "").lower()
    if flask_env == "production" or app_env == "production":
        print("ERROR: demo_reset cannot run in production environment.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Reset demo database records, Redis scan cache, and uploads.")
    parser.add_argument("--yes", action="store_true", help="Execute deletion without confirmation prompt")
    parser.add_argument("--clear-vt", action="store_true", help="Delete cached VirusTotal keys (vt:*)")
    args = parser.parse_args()

    from app import create_app
    from app.extensions import db, redis_client
    from app.models.scan import ScanRecord, CertificateRecord
    from sqlalchemy import select, func, delete

    app = create_app()

    with app.app_context():
        scan_count = db.session.execute(select(func.count()).select_from(ScanRecord)).scalar() or 0
        cert_count = db.session.execute(select(func.count()).select_from(CertificateRecord)).scalar() or 0

        scan_keys = redis_client.keys("scan:*")
        vt_keys = redis_client.keys("vt:*")

        upload_folder = Path(app.config.get("UPLOAD_FOLDER", "/app/uploads"))
        if not upload_folder.exists() and Path("/app/uploads").exists():
            upload_folder = Path("/app/uploads")

        apk_files = list(upload_folder.glob("*.apk")) if upload_folder.exists() else []
        apk_count = len(apk_files)

        if not args.yes:
            print("What would be deleted:")
            print(f"  scan_records: {scan_count}")
            print(f"  certificate_records: {cert_count}")
            print(f"  Redis keys matching scan:*: {len(scan_keys)}")
            if args.clear_vt:
                print(f"  Redis keys matching vt:*: {len(vt_keys)} (deleted with --clear-vt)")
            else:
                print(f"  Redis keys matching vt:*: {len(vt_keys)} (kept unless --clear-vt)")
            print(f"  .apk files in {upload_folder}: {apk_count}")
            sys.exit(2)

        print("Counts before reset:")
        print(f"  scan_records: {scan_count}")
        print(f"  certificate_records: {cert_count}")
        print(f"  Redis keys (scan:*): {len(scan_keys)}")
        print(f"  Redis keys (vt:*): {len(vt_keys)} ({'to delete' if args.clear_vt else 'kept'})")
        print(f"  .apk files in {upload_folder}: {apk_count}")

        # Delete in foreign key order: scan_records first, then certificate_records
        db.session.execute(delete(ScanRecord))
        db.session.execute(delete(CertificateRecord))
        db.session.commit()

        # Delete scan:* keys, and vt:* keys only if --clear-vt was passed
        keys_to_delete = list(scan_keys)
        if args.clear_vt:
            keys_to_delete.extend(vt_keys)

        if keys_to_delete:
            redis_client.delete(*keys_to_delete)

        deleted_apks = 0
        for apk in apk_files:
            try:
                apk.unlink(missing_ok=True)
                deleted_apks += 1
            except Exception as e:
                print(f"Warning: could not delete {apk}: {e}")

        # Counts after reset
        scan_count_after = db.session.execute(select(func.count()).select_from(ScanRecord)).scalar() or 0
        cert_count_after = db.session.execute(select(func.count()).select_from(CertificateRecord)).scalar() or 0
        scan_keys_after = redis_client.keys("scan:*")
        vt_keys_after = redis_client.keys("vt:*")
        apk_files_after = list(upload_folder.glob("*.apk")) if upload_folder.exists() else []

        print("Counts after reset:")
        print(f"  scan_records: {scan_count_after}")
        print(f"  certificate_records: {cert_count_after}")
        print(f"  Redis keys (scan:*): {len(scan_keys_after)}")
        print(f"  Redis keys (vt:*): {len(vt_keys_after)}")
        print(f"  .apk files in {upload_folder}: {len(apk_files_after)}")


if __name__ == "__main__":
    main()
