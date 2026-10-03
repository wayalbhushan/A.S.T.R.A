"""ASTRA Engine Version definition.

Computes engine version based on ENGINE_BASE and a hash fingerprint of
trusted_certs.json and brand_registry.json.
"""

import hashlib
from pathlib import Path

ENGINE_BASE = "15"


def _compute_registry_fingerprint() -> str:
    ml_dir = Path(__file__).resolve().parent.parent / "ml"
    certs_path = ml_dir / "trusted_certs.json"
    brand_path = ml_dir / "brand_registry.json"

    h = hashlib.sha256()
    for p in (certs_path, brand_path):
        try:
            with open(p, "rb") as f:
                h.update(f.read())
        except (OSError, IOError):
            h.update(b"missing")

    return h.hexdigest()[:6]


# Computed once at import, so a registry change gives a new version
# after a restart and old cached verdicts are not reused; keep the total
# length at 10 characters or less (database column is String(10)).
ENGINE_VERSION = f"{ENGINE_BASE}-{_compute_registry_fingerprint()}"
