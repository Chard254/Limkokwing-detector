import os
import time
import base64
import json
import urllib.parse
import urllib.request
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def encode_url_for_virustotal(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return encoded


def check_virustotal(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {
            "available": False,
            "source": "VirusTotal",
            "error": "VirusTotal API key missing",
        }

    url_id = encode_url_for_virustotal(url)

    request_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    request = urllib.request.Request(
        request_url,
        method="GET",
        headers={
            "x-apikey": VIRUSTOTAL_API_KEY,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))

        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            verdict = "Phishing"
        elif suspicious > 0:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        return {
            "available": True,
            "source": "VirusTotal",
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "stats": stats,
        }

    except Exception as e:
        return {
            "available": False,
            "source": "VirusTotal",
            "error": str(e),
        }


def submit_url_to_virustotal(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {
            "available": False,
            "source": "VirusTotal",
            "error": "VirusTotal API key missing",
        }

    request_url = "https://www.virustotal.com/api/v3/urls"

    payload = urllib.parse.urlencode({"url": url}).encode("utf-8")

    request = urllib.request.Request(
        request_url,
        data=payload,
        method="POST",
        headers={
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))

        return {
            "available": True,
            "source": "VirusTotal",
            "analysis_id": data.get("data", {}).get("id"),
            "raw": data,
        }

    except Exception as e:
        return {
            "available": False,
            "source": "VirusTotal",
            "error": str(e),
        }


def check_url_threat_intelligence(url: str) -> dict:
    vt_result = check_virustotal(url)

    if vt_result.get("available"):
        return vt_result

    submit_result = submit_url_to_virustotal(url)

    return {
        "available": False,
        "source": "VirusTotal",
        "message": "URL was not found in VirusTotal or lookup failed. Submission attempted.",
        "lookup_error": vt_result.get("error"),
        "submission": submit_result,
    }