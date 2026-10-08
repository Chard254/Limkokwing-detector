import re

from typing import Optional

from sqlalchemy.orm import Session

from app.models import UrlScan



URL_PATTERN = re.compile(
    r'(https?://[^\s<>"]+|www\.[^\s<>"]+)',
    re.IGNORECASE,
)



# ==========================================================
# URL Extraction
# ==========================================================


def extract_url(text: str) -> Optional[str]:

    if not text:
        return None


    match = URL_PATTERN.search(text)


    if not match:
        return None


    url = match.group(0).strip()


    url = url.rstrip(
        ".,;:!?)]}"
    )


    if url.startswith("www."):

        url = "https://" + url


    return url



# ==========================================================
# Normalize Detector Result
# ==========================================================


def normalize_scan_result(
    url: str,
    raw_result: dict
):


    verdict = (

        raw_result.get("verdict")

        or raw_result.get("result")

        or "Unknown"

    )



    risk_score = (

        raw_result.get("risk_score")

        if raw_result.get("risk_score") is not None

        else raw_result.get("score",0)

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


        "url":
            raw_result.get("url")
            or url,


        "verdict":
            verdict,


        "risk_score":
            risk_score,


        "risk_level":
            risk_level,


        "reasons":
            reasons,


        "advice":
            advice

    }



# ==========================================================
# Save Scan
# ==========================================================


def save_scan_to_database(
    db: Session,
    result: dict
):


    reasons = result.get(
        "reasons",
        []
    )


    if isinstance(
        reasons,
        list
    ):

        reasons_text = ", ".join(
            reasons
        )

    else:

        reasons_text = str(
            reasons
        )



    data = {


        "url":
        result["url"],


        "verdict":
        result["verdict"],


        "risk_score":
        result["risk_score"],


        "risk_level":
        result["risk_level"],


        "reason":
        reasons_text,


        "reasons":
        reasons_text,


        "score":
        result["risk_score"],


        "result":
        result["verdict"],


        "advice":
        result["advice"],


        "source":
        "whatsapp"

    }



    columns = set(
        UrlScan.__table__.columns.keys()
    )


    filtered = {

        key:value

        for key,value in data.items()

        if key in columns

    }



    scan = UrlScan(
        **filtered
    )


    try:

        db.add(scan)

        db.commit()

        db.refresh(scan)


    except Exception:


        db.rollback()

        raise



    return scan



# ==========================================================
# WhatsApp Reply Builder
# ==========================================================


def build_reply(
    result: dict
):


    reasons = result.get(
        "reasons",
        []
    )


    reasons_text = "\n".join(

        [
            f"• {reason}"

            for reason in reasons[:5]
        ]

    )


    if not reasons_text:

        reasons_text = (
            "• No major suspicious signs found"
        )



    return f"""
🔍 Phishing Scan Result


URL:
{result['url']}


Verdict:
{result['verdict']}


Risk Level:
{result['risk_level']}


Risk Score:
{result['risk_score']}


Reasons:

{reasons_text}


Advice:

{result['advice']}
"""