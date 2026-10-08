from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel, HttpUrl

from app.database import get_db
from app.models import UrlScan
from app.phishing_detector import analyze_url


router = APIRouter()


# ==========================================
# Request Model
# ==========================================

class ScanRequest(BaseModel):
    url: HttpUrl


# ==========================================
# Normalize ML Result
# ==========================================

def normalize_result(url: str, raw_result: dict):

    verdict = (
        raw_result.get("verdict")
        or raw_result.get("result")
        or "Unknown"
    )

    risk_score = (
        raw_result.get("risk_score")
        or raw_result.get("score")
        or 0
    )

    risk_level = (
        raw_result.get("risk_level")
        or "Unknown"
    )

    reasons = (
        raw_result.get("reasons")
        or raw_result.get("reason")
        or []
    )

    if isinstance(reasons, str):
        reasons = [reasons]

    advice = (
        raw_result.get("advice")
        or "Be careful before opening this link."
    )

    return {
        "url": raw_result.get("url") or url,
        "verdict": verdict,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "advice": advice
    }



# ==========================================
# Save Scan
# ==========================================

def save_scan(db: Session, result: dict):

    verdict = result.get("verdict") or "Unknown"
    risk_score = result.get("risk_score") or 0
    reasons = result.get("reasons") or []

    if isinstance(reasons, str):
        reasons = [reasons]

    reason_text = ", ".join(reasons)

    scan = UrlScan(
        url=result["url"],

        # Old / database fields
        result=verdict,
        score=risk_score,
        reasons=reason_text,

        # Current fields
        verdict=verdict,
        risk_score=risk_score,
        risk_level=result.get("risk_level") or "Unknown",
        reason=reason_text,
        advice=result.get("advice") or "Be careful before opening this link.",
        source="web"
    )

    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    except Exception as e:
        db.rollback()
        print("Database error:", e)
        raise



# ==========================================
# Scan URL Endpoint
# ==========================================

@router.post("/scan-url")
def scan_url(
    request: ScanRequest,
    rescan: bool = Query(False),
    db: Session = Depends(get_db)
):

    url = str(request.url)

    print("=" * 50)
    print("Scanning URL:", url)
    print("=" * 50)


    # Check existing scan
    existing = (
        db.query(UrlScan)
        .filter(UrlScan.url == url)
        .order_by(
            UrlScan.created_at.desc()
        )
        .first()
    )


    if existing and not rescan:

        print("Returning cached result")

        return {
            "success": True,
            "cached": True,
            "data": {
                "scan_id": existing.id,
                "url": existing.url,
                "verdict": existing.verdict,
                "risk_score": existing.risk_score,
                "risk_level": getattr(
                    existing,
                    "risk_level",
                    "Unknown"
                ),
                "reasons": (
                    existing.reason.split(", ")
                    if existing.reason
                    else []
                ),
                "advice":
                    existing.advice
                    or
                    "Be careful before opening this link.",
                "last_scanned_at":
                    existing.created_at.isoformat()
            }
        }



    # Run AI detection
    try:

        raw_result = analyze_url(url)

        print("AI RESULT:")
        print(raw_result)

        result = normalize_result(
            url,
            raw_result
        )

    except Exception as e:

        print("Analysis error:", e)

        raise HTTPException(
            status_code=500,
            detail=f"Phishing analysis failed: {str(e)}"
        )


    # Save result
    scan = save_scan(
        db,
        result
    )


    return {

        "success": True,

        "cached": False,

        "data": {

            "scan_id": scan.id,

            "url": scan.url,

            "verdict": scan.verdict,

            "risk_score": scan.risk_score,

            "risk_level":
                scan.risk_level,

            "reasons":
                result["reasons"],

            "advice":
                result["advice"],

            "last_scanned_at":
                scan.created_at.isoformat()
        }
    }



# ==========================================
# Dashboard Summary
# ==========================================

@router.get("/dashboard/summary")
def dashboard_summary(
    db: Session = Depends(get_db)
):

    total = (
        db.query(UrlScan)
        .count()
    )


    safe = (
        db.query(UrlScan)
        .filter(
            UrlScan.verdict == "Safe"
        )
        .count()
    )


    suspicious = (
        db.query(UrlScan)
        .filter(
            UrlScan.verdict == "Suspicious"
        )
        .count()
    )


    high_risk = (
        db.query(UrlScan)
        .filter(
            UrlScan.verdict == "High Risk"
        )
        .count()
    )


    unique_urls = (
        db.query(
            func.count(
                func.distinct(
                    UrlScan.url
                )
            )
        )
        .scalar()
    )


    repeated_links = (
        total - unique_urls
    )


    return {

        "success": True,

        "summary": {

            "total_scans":
                total,

            "safe":
                safe,

            "suspicious":
                suspicious,

            "high_risk":
                high_risk,

            "repeated_links":
                repeated_links
        }
    }