from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import UrlScan
from app.phishing_detector import analyze_url
from app.whatsapp_service import send_whatsapp_message


@celery_app.task(name="scan_url_task")
def scan_url_task(url: str, source: str = "background"):
    db = SessionLocal()

    try:
        result = analyze_url(url)

        scan = UrlScan(
            url=result["url"],
            result=result["result"],
            verdict=result["verdict"],
            risk_level=result["risk_level"],
            score=result["score"],
            risk_score=result["risk_score"],
            reasons=", ".join(result.get("reasons", [])),
            reason=", ".join(result.get("reasons", [])),
            advice=result.get("advice", ""),
            source=source,
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        return {
            "status": "completed",
            "scan_id": scan.id,
            "url": scan.url,
            "verdict": scan.verdict,
        }

    except Exception as e:
        db.rollback()
        return {
            "status": "failed",
            "error": str(e),
        }

    finally:
        db.close()


@celery_app.task(name="whatsapp_scan_reply_task")
def whatsapp_scan_reply_task(url: str, phone_number: str):
    result = scan_url_task(url, source="whatsapp_background")

    if result.get("status") != "completed":
        send_whatsapp_message(
            phone_number,
            "Sorry, the link could not be scanned at the moment. Please try again later.",
        )
        return result

    db = SessionLocal()

    try:
        scan = db.query(UrlScan).filter(UrlScan.id == result["scan_id"]).first()

        if not scan:
            return {"status": "failed", "error": "Saved scan not found"}

        message = (
            "🔍 Phishing Scan Result\n\n"
            f"URL: {scan.url}\n"
            f"Verdict: {scan.verdict or scan.result}\n"
            f"Risk Level: {scan.risk_level}\n"
            f"Risk Score: {scan.risk_score or scan.score}\n\n"
            f"Advice: {scan.advice}"
        )

        send_whatsapp_message(phone_number, message)

        return {
            "status": "reply_sent",
            "scan_id": scan.id,
            "phone_number": phone_number,
        }

    finally:
        db.close()