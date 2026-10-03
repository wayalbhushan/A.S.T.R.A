"""
Add or Remove Trusted Certificate Script
Manages verified Android banking app certificate SHA-256 signatures in trusted_certs.json
and records all mutations in trusted_certs_changelog.jsonl.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

# Ensure backend root is in sys.path
SCRIPTS_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPTS_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def validate_hash(h: str) -> str:
    cleaned = h.strip().lower()
    if len(cleaned) != 64 or not all(c in "0123456789abcdef" for c in cleaned):
        print(
            f"Error: hash must be exactly 64 hexadecimal characters, got {len(cleaned)} characters: {h!r}",
            file=sys.stderr,
        )
        sys.exit(1)
    return cleaned


def extract_apk_signer_hashes(apk_path: str) -> tuple[list[str], str]:
    from androguard.core.bytecodes.apk import APK

    p = Path(apk_path)
    if not p.is_file():
        print(f"Error: APK file not found at {apk_path}", file=sys.stderr)
        sys.exit(1)

    a = APK(str(p))
    pkg = a.get_package()

    certs_der = []
    if hasattr(a, "get_certificates_der_v2"):
        certs_der = a.get_certificates_der_v2()

    if not certs_der and hasattr(a, "get_certificates"):
        certs = a.get_certificates()
        for c in certs:
            if isinstance(c, bytes):
                certs_der.append(c)
            elif hasattr(c, "public_bytes"):
                from cryptography.hazmat.primitives import serialization
                certs_der.append(c.public_bytes(serialization.Encoding.DER))
            elif hasattr(c, "get_der"):
                certs_der.append(c.get_der())

    hashes = [hashlib.sha256(der).hexdigest().lower() for der in certs_der]
    return hashes, pkg


def append_changelog(action: str, cert_hash: str, app_name: str, package_name: str, source_or_reason: str):
    changelog_path = BACKEND_DIR / "ml" / "trusted_certs_changelog.jsonl"
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "cert_hash": cert_hash,
        "app_name": app_name or "",
        "package_name": package_name or "",
        "source_or_reason": source_or_reason or "",
    }
    if action == "add":
        entry["source"] = source_or_reason or ""
    else:
        entry["reason"] = source_or_reason or ""

    with open(changelog_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Add or remove trusted banking certificates in trusted_certs.json")
    parser.add_argument("--apk", help="Path to APK file to compute signing certificate from")
    parser.add_argument("--hash", help="Certificate SHA-256 hash (64 hex characters)")
    parser.add_argument("--app-name", help="Human-readable banking app name (required for add)")
    parser.add_argument("--package", help="Official Android package name (required for add)")
    parser.add_argument("--source", help="Provenance note for certificate addition")
    parser.add_argument("--unverified", action="store_true", help="Allow adding hash without an APK file")
    parser.add_argument("--remove-hash", help="Certificate SHA-256 hash to remove")
    parser.add_argument("--reason", help="Reason for certificate removal")
    parser.add_argument("--dry-run", action="store_true", help="Simulate mutation without writing to disk")
    args = parser.parse_args()

    trusted_certs_path = BACKEND_DIR / "ml" / "trusted_certs.json"
    if not trusted_certs_path.is_file():
        print(f"Error: trusted_certs.json not found at {trusted_certs_path}", file=sys.stderr)
        sys.exit(1)

    with open(trusted_certs_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    trusted_list = data.get("trusted_certificates", [])
    old_count = len(trusted_list)

    # REMOVE MODE
    if args.remove_hash:
        target_hash = validate_hash(args.remove_hash)
        if not args.reason or not args.reason.strip():
            print("Error: --reason is required when removing a certificate.", file=sys.stderr)
            sys.exit(1)

        match_idx = None
        removed_entry = None
        for idx, item in enumerate(trusted_list):
            if item.get("cert_hash", "").lower() == target_hash:
                match_idx = idx
                removed_entry = item
                break

        if match_idx is None:
            print(f"Error: Certificate hash {target_hash} not found in trusted_certs.json", file=sys.stderr)
            sys.exit(3)

        if args.dry_run:
            print(f"Dry run: would remove entry for {removed_entry.get('app_name')} ({target_hash}):")
            print(json.dumps(removed_entry, indent=2, ensure_ascii=False))
            print(f"Old entry count: {old_count}")
            print(f"New entry count would be: {old_count - 1}")
            sys.exit(0)

        del trusted_list[match_idx]
        data["trusted_certificates"] = trusted_list

        temp_file = trusted_certs_path.with_suffix(".tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(temp_file, trusted_certs_path)

        append_changelog(
            action="remove",
            cert_hash=target_hash,
            app_name=removed_entry.get("app_name", ""),
            package_name=removed_entry.get("package_name", ""),
            source_or_reason=args.reason.strip(),
        )

        print(f"Old entry count: {old_count}")
        print(f"New entry count: {len(trusted_list)}")
        print(f"Successfully removed certificate {target_hash} ({removed_entry.get('app_name')})")
        sys.exit(0)

    # ADD MODE
    # Check for bare --hash without --apk
    if not args.apk and args.hash:
        if not args.unverified:
            print("Error: A bare --hash with no --apk is refused. Use --unverified to override.", file=sys.stderr)
            sys.exit(2)
        computed_hash = validate_hash(args.hash)
        source_note = args.source.strip() if args.source else "UNVERIFIED hash, not computed from a file"
    elif args.apk:
        signer_hashes, apk_pkg = extract_apk_signer_hashes(args.apk)
        if not signer_hashes:
            print("Error: No signer certificates found in APK.", file=sys.stderr)
            sys.exit(1)

        print(f"Signer certificate hashes found in APK ({len(signer_hashes)}):")
        for i, h in enumerate(signer_hashes, 1):
            print(f"  [{i}] {h}")

        computed_hash = signer_hashes[0]

        if not args.package:
            print("Error: --package is required for adding a certificate from APK.", file=sys.stderr)
            sys.exit(1)

        expected_pkg = args.package.strip()
        if apk_pkg != expected_pkg:
            print(
                f"Error: APK package name '{apk_pkg}' does not match expected package '{expected_pkg}'.",
                file=sys.stderr,
            )
            sys.exit(5)

        if args.hash:
            provided_hash = validate_hash(args.hash)
            if provided_hash != computed_hash:
                print(
                    "Provided hash does not match the APK's signing certificate. A file hash is not a certificate hash.",
                    file=sys.stderr,
                )
                sys.exit(4)

        source_note = args.source.strip() if args.source else "computed from APK pulled from a Play-installed device"
    else:
        print("Error: Either --apk or --remove-hash must be specified.", file=sys.stderr)
        sys.exit(2)

    if not args.app_name or not args.package:
        print("Error: Both --app-name and --package are required for adding a certificate.", file=sys.stderr)
        sys.exit(1)

    app_name = args.app_name.strip()
    package_name = args.package.strip()

    # Check for duplicate entry
    for entry in trusted_list:
        if entry.get("cert_hash", "").lower() == computed_hash:
            print(
                f"Error: Certificate hash {computed_hash} already exists in entry: {json.dumps(entry, ensure_ascii=False)}",
                file=sys.stderr,
            )
            sys.exit(3)

    new_entry = {
        "cert_hash": computed_hash,
        "app_name": app_name,
        "package_name": package_name,
        "issuer": "Verified Indian Banking App",
        "added_at": datetime.now(timezone.utc).isoformat(),
        "source_note": source_note,
    }

    new_count = old_count + 1

    if args.dry_run:
        print("Dry run: entry that would be added:")
        print(json.dumps(new_entry, indent=2, ensure_ascii=False))
        print(f"Old entry count: {old_count}")
        print(f"New entry count would be: {new_count}")
        sys.exit(0)

    trusted_list.append(new_entry)
    data["trusted_certificates"] = trusted_list

    temp_file = trusted_certs_path.with_suffix(".tmp")
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(temp_file, trusted_certs_path)

    append_changelog(
        action="add",
        cert_hash=computed_hash,
        app_name=app_name,
        package_name=package_name,
        source_or_reason=source_note,
    )

    print(f"Old entry count: {old_count}")
    print(f"New entry count: {new_count}")
    print(f"Successfully added certificate {computed_hash} for {app_name}")


if __name__ == "__main__":
    main()
