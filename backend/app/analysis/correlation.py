"""
ASTRA Signal Correlation Engine
Aggregates risk metrics from static analysis and ML models.
"""
import structlog

logger = structlog.get_logger()

ML_WEIGHT = 0.35
VT_WEIGHT = 0.30
SANDBOX_WEIGHT = 0.20
SIGNATURE_WEIGHT = 0.15

def correlate(androguard_data: dict, ml_result: dict, vt_report: dict, sandbox_report: dict, signature_verdict: str) -> dict:
    """Calculates basic weighted risk score."""
    ml_score = ml_result.get("confidence", 0.0) * 100.0
    vt_score = 50.0
    sandbox_score = min(sandbox_report.get("severity_score", 0) * 10.0, 100.0)
    signature_score = 40.0
    
    risk_score = (
        ml_score * ML_WEIGHT +
        vt_score * VT_WEIGHT +
        sandbox_score * SANDBOX_WEIGHT +
        signature_score * SIGNATURE_WEIGHT
    )
    return {
        "risk_score": round(risk_score, 1),
        "verdict": "CLEAN" if risk_score < 40 else "SUSPICIOUS"
    }
