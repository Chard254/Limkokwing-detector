import os
import logging
from typing import List, Dict

from dotenv import load_dotenv
from groq import Groq


load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Load API Key
# ---------------------------------------------------------------------

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise RuntimeError(
        "GROQ_API_KEY not found in .env file."
    )

client = Groq(api_key=GROQ_API_KEY)

# ---------------------------------------------------------------------
# AI Configuration
# ---------------------------------------------------------------------

MODEL_NAME = "openai/gpt-oss-120b"

SYSTEM_PROMPT = """
You are PhishGuard AI.

Your purpose is to educate users about cybersecurity.

You specialize in:

- Phishing
- Email scams
- SMS scams (Smishing)
- WhatsApp scams
- Fake websites
- Fake banking pages
- QR code scams
- Password security
- Social engineering
- Malware
- Online fraud
- Safe browsing

Rules:

1. Keep answers clear and simple.
2. Explain technical words.
3. Never invent facts.
4. If unsure, say you are unsure.
5. Encourage safe cybersecurity practices.
6. If a user sends a suspicious URL, advise them to scan it using PhishGuard.
7. Stay focused on cybersecurity. Politely decline unrelated topics.
8. Use short paragraphs.
9. Use bullet points where helpful.
10. Always be friendly and professional.
"""

# ---------------------------------------------------------------------
# AI Service
# ---------------------------------------------------------------------


class AIService:
    """
    Handles communication with Groq.
    """

    @staticmethod
    def ask(messages: List[Dict]) -> str:
        """
        Sends conversation history to Groq and returns the assistant reply.

        messages example:

        [
            {"role":"system","content":"..."},
            {"role":"user","content":"Hello"},
            {"role":"assistant","content":"Hi"},
            {"role":"user","content":"What is phishing?"}
        ]
        """

        try:

            conversation = [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                }
            ]

            # Avoid duplicate system prompts
            for message in messages:
                if message["role"] != "system":
                    conversation.append(message)

            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=conversation,
                temperature=0.3,
                max_completion_tokens=700,
                top_p=1,
                stream=False,
            )

            return response.choices[0].message.content.strip()

        except Exception as e:

            logger.exception("Groq API Error")

            return (
                "Sorry, I couldn't process your request at the moment. "
                "Please try again in a few moments."
            )