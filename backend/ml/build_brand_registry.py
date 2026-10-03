"""Build Brand Registry.

Reads backend/ml/trusted_certs.json and produces backend/ml/brand_registry.json
containing brand definitions, keywords, weak keywords, official packages,
and trusted certificate hashes for Indian banking applications.
"""

from __future__ import annotations

import json
from pathlib import Path

CONTEXT_WORDS = [
    "bank", "banking", "mobile", "pay", "kyc", "netbanking",
    "upi", "card", "credit", "account", "wallet"
]

LURE_WORDS = [
    "kyc", "update", "reward", "rewards", "redeem", "verify",
    "verification", "block", "blocked", "suspend", "suspended", "claim",
    "gift", "challan", "offer", "cashback", "points", "expire", "expired",
    "urgent", "pan", "aadhaar"
]

BRANDS = [
    {
        "id": "sbi",
        "name": "State Bank of India",
        "keywords": ["sbi", "yono", "state bank of india"],
        "weak_keywords": [],
        "source_apps": ["YONO SBI"],
    },
    {
        "id": "rbi",
        "name": "Reserve Bank of India",
        "keywords": ["reserve bank of india", "rbi"],
        "weak_keywords": [],
        "source_apps": [],
    },
    {
        "id": "hdfc",
        "name": "HDFC Bank",
        "keywords": ["hdfc"],
        "weak_keywords": [],
        "source_apps": ["HDFC Bank"],
    },
    {
        "id": "icici",
        "name": "ICICI Bank",
        "keywords": ["icici"],
        "weak_keywords": ["imobile"],
        "source_apps": ["iMobile"],
    },
    {
        "id": "axis",
        "name": "Axis Bank",
        "keywords": ["axis bank", "axisbank"],
        "weak_keywords": ["axis"],
        "source_apps": ["Axis Mobile"],
    },
    {
        "id": "kotak",
        "name": "Kotak Mahindra Bank",
        "keywords": ["kotak"],
        "weak_keywords": [],
        "source_apps": ["Kotak811", "Kotak Bank"],
    },
    {
        "id": "pnb",
        "name": "Punjab National Bank",
        "keywords": ["punjab national", "pnb"],
        "weak_keywords": [],
        "source_apps": ["PNB ONE"],
    },
    {
        "id": "bob",
        "name": "Bank of Baroda",
        "keywords": ["bank of baroda", "bankofbaroda", "baroda"],
        "weak_keywords": ["bob"],
        "source_apps": ["bob World"],
    },
    {
        "id": "boi",
        "name": "Bank of India",
        "keywords": ["bank of india", "bankofindia"],
        "weak_keywords": ["boi"],
        "source_apps": ["BOI Mobile"],
    },
    {
        "id": "canara",
        "name": "Canara Bank",
        "keywords": ["canara"],
        "weak_keywords": [],
        "source_apps": ["Canara ai1"],
    },
    {
        "id": "cbi",
        "name": "Central Bank of India",
        "keywords": ["central bank of india", "centralbank", "cent mobile", "centpay"],
        "weak_keywords": ["cent", "cbi"],
        "source_apps": ["Cent Mobile", "CentPay"],
    },
    {
        "id": "ubi",
        "name": "Union Bank of India",
        "keywords": ["union bank of india", "unionbank"],
        "weak_keywords": ["union", "vyom"],
        "source_apps": ["Vyom"],
    },
    {
        "id": "idbi",
        "name": "IDBI Bank",
        "keywords": ["idbi"],
        "weak_keywords": [],
        "source_apps": ["IDBI Bank"],
    },
    {
        "id": "yes",
        "name": "YES Bank",
        "keywords": ["yes bank", "yesbank"],
        "weak_keywords": [],
        "source_apps": ["IRIS by YES BANK"],
    },
    {
        "id": "indusind",
        "name": "IndusInd Bank",
        "keywords": ["indusind"],
        "weak_keywords": ["indie"],
        "source_apps": ["INDIE"],
    },
    {
        "id": "rbl",
        "name": "RBL Bank",
        "keywords": ["rbl"],
        "weak_keywords": [],
        "source_apps": ["RBL BizBank", "RBL MyBank"],
    },
    {
        "id": "bandhan",
        "name": "Bandhan Bank",
        "keywords": ["bandhan", "mbandhan"],
        "weak_keywords": [],
        "source_apps": ["mBandhan"],
    },
    {
        "id": "federal",
        "name": "Federal Bank",
        "keywords": ["federal bank", "fedmobile", "fedbank"],
        "weak_keywords": ["federal"],
        "source_apps": ["FedMobile"],
    },
    {
        "id": "indian",
        "name": "Indian Bank",
        "keywords": ["indian bank", "indsmart"],
        "weak_keywords": ["indian"],
        "source_apps": ["IndSMART"],
    },
    {
        "id": "iob",
        "name": "Indian Overseas Bank",
        "keywords": ["indian overseas", "iob mobile"],
        "weak_keywords": ["iob"],
        "source_apps": ["IOB Mobile"],
    },
    {
        "id": "uco",
        "name": "UCO Bank",
        "keywords": ["uco bank", "uco mbanking"],
        "weak_keywords": ["uco"],
        "source_apps": ["UCO mBanking Plus"],
    },
    {
        "id": "psb",
        "name": "Punjab & Sind Bank",
        "keywords": ["punjab and sind", "punjab & sind", "psb unic"],
        "weak_keywords": ["psb"],
        "source_apps": ["PSB UnIC"],
    },
    {
        "id": "bom",
        "name": "Bank of Maharashtra",
        "keywords": ["bank of maharashtra", "mahamobile", "mahabank"],
        "weak_keywords": [],
        "source_apps": ["Mahamobile Plus"],
    },
    {
        "id": "csb",
        "name": "CSB Bank",
        "keywords": ["csb bank", "csbmobile"],
        "weak_keywords": ["csb"],
        "source_apps": ["CSBMobile+: Smart Banking"],
    },
    {
        "id": "cub",
        "name": "City Union Bank",
        "keywords": ["city union bank", "cub mbank"],
        "weak_keywords": ["cub"],
        "source_apps": ["CUB mBank Plus"],
    },
    {
        "id": "dcb",
        "name": "DCB Bank",
        "keywords": ["dcb bank"],
        "weak_keywords": ["dcb"],
        "source_apps": ["DCB Bank"],
    },
    {
        "id": "dhanlaxmi",
        "name": "Dhanlaxmi Bank",
        "keywords": ["dhanlaxmi", "dhansmart"],
        "weak_keywords": [],
        "source_apps": ["DhanSmart-5x"],
    },
    {
        "id": "jkb",
        "name": "Jammu and Kashmir Bank",
        "keywords": ["jammu and kashmir bank", "j&k bank", "jkb"],
        "weak_keywords": [],
        "source_apps": ["JKB mPay Delight+"],
    },
    {
        "id": "kbl",
        "name": "Karnataka Bank",
        "keywords": ["karnataka bank", "kbl mobile"],
        "weak_keywords": ["kbl"],
        "source_apps": ["KBL Mobile Plus"],
    },
    {
        "id": "kvb",
        "name": "Karur Vysya Bank",
        "keywords": ["karur vysya", "kvb"],
        "weak_keywords": [],
        "source_apps": ["KVB - DLite"],
    },
    {
        "id": "nainital",
        "name": "Nainital Bank",
        "keywords": ["nainital", "naini neo"],
        "weak_keywords": [],
        "source_apps": ["NAINI NEO"],
    },
    {
        "id": "sib",
        "name": "South Indian Bank",
        "keywords": ["south indian bank", "sib mirror"],
        "weak_keywords": ["sib"],
        "source_apps": ["SIB Mirror+"],
    },
]


def build_registry() -> dict:
    """Reads trusted_certs.json and produces brand_registry.json."""
    ml_dir = Path(__file__).resolve().parent
    trusted_certs_path = ml_dir / "trusted_certs.json"
    output_path = ml_dir / "brand_registry.json"

    with open(trusted_certs_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    trusted_entries = data.get("trusted_certificates", [])
    mapped_indices = set()

    brands_output = []
    total_mapped_cert_count = 0

    for brand in BRANDS:
        matched_packages: set[str] = set()
        matched_hashes: set[str] = set()

        for idx, entry in enumerate(trusted_entries):
            app_name = entry.get("app_name", "").strip()
            if app_name in brand["source_apps"]:
                mapped_indices.add(idx)
                pkg = entry.get("package_name", "").strip()
                chash = entry.get("cert_hash", "").strip()
                if pkg:
                    matched_packages.add(pkg)
                if chash:
                    matched_hashes.add(chash)

        total_mapped_cert_count += len(matched_hashes)
        brands_output.append({
            "id": brand["id"],
            "name": brand["name"],
            "keywords": brand["keywords"],
            "weak_keywords": brand["weak_keywords"],
            "official_packages": sorted(list(matched_packages)),
            "cert_hashes": sorted(list(matched_hashes)),
        })

    registry = {
        "context_words": CONTEXT_WORDS,
        "lure_words": LURE_WORDS,
        "brands": brands_output,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)

    unmapped_count = len(trusted_entries) - len(mapped_indices)
    zero_cert_brands = [b["id"] for b in brands_output if len(b["cert_hashes"]) == 0]

    print(f"Unmapped trusted cert entries: {unmapped_count}")
    print(f"Brands with zero cert_hashes: {zero_cert_brands}")
    print(f"Total mapped cert hashes: {total_mapped_cert_count}")

    return registry


if __name__ == "__main__":
    build_registry()
