import logging

from sqlalchemy.orm import Session

from app.ai_service import AIService
from app.models import Conversation, ConversationState

from app.phishing_service import (
    extract_url,
    normalize_scan_result,
    save_scan_to_database,
    build_reply,
)

from app.phishing_detector import analyze_url


logger = logging.getLogger(__name__)


class ConversationService:
    """
    Main application service.

    Handles:
    - Conversation history
    - AI context
    - URL detection
    - Phishing scanning
    - Conversation states
    - Learning menu
    """

    # ============================================================
    # Conversation Storage
    # ============================================================

    @staticmethod
    def save_message(
        db: Session,
        phone_number: str,
        role: str,
        message: str,
    ):
        chat = Conversation(
            phone_number=phone_number,
            role=role,
            message=message,
        )

        db.add(chat)
        db.commit()
        db.refresh(chat)

        return chat

    @staticmethod
    def get_history(
        db: Session,
        phone_number: str,
        limit: int = 20,
    ):
        return (
            db.query(Conversation)
            .filter(
                Conversation.phone_number == phone_number
            )
            .order_by(
                Conversation.created_at.asc()
            )
            .limit(limit)
            .all()
        )

    # ============================================================
    # Conversation State Management
    # ============================================================

    @staticmethod
    def get_state(
        db: Session,
        phone_number: str,
    ):
        state = (
            db.query(ConversationState)
            .filter(
                ConversationState.phone_number == phone_number
            )
            .first()
        )

        if not state:
            state = ConversationState(
                phone_number=phone_number,
                state="IDLE",
            )

            db.add(state)
            db.commit()
            db.refresh(state)

        return state

    @staticmethod
    def update_state(
        db: Session,
        phone_number: str,
        new_state: str,
    ):
        state = ConversationService.get_state(
            db,
            phone_number,
        )

        state.state = new_state

        db.commit()

        return state

    # ============================================================
    # Last URL
    # ============================================================

    @staticmethod
    def get_last_url(
        db: Session,
        phone_number: str,
    ):
        """
        Find the most recent URL previously sent
        by this WhatsApp user.
        """

        messages = (
            db.query(Conversation)
            .filter(
                Conversation.phone_number == phone_number,
                Conversation.role == "user",
            )
            .order_by(
                Conversation.created_at.desc()
            )
            .limit(50)
            .all()
        )

        for item in messages:
            url = extract_url(item.message)

            if url:
                return url

        return None

    # ============================================================
    # Learning Menu
    # ============================================================

    @staticmethod
    def handle_learning_menu(
        db: Session,
        phone_number: str,
        option: str,
    ):
        """
        Handle options from the WhatsApp learning menu.

        Option 1:
            Re-scan the user's most recently submitted URL.

        Options 2-5:
            Keep their existing educational responses.
        """

        # --------------------------------------------------------
        # Option 1 - Re-scan last URL
        # --------------------------------------------------------

        if option == "1":
            last_url = ConversationService.get_last_url(
                db,
                phone_number,
            )

            if not last_url:
                return """
⚠️ I could not find a previous URL to scan.

Please send a URL first.

Example:
https://example.com
""".strip()

            logger.info(
                "Option 1 selected. Re-scanning last URL "
                "for %s: %s",
                phone_number,
                last_url,
            )

            return ConversationService.process_url(
                db,
                phone_number,
                last_url,
            )

        # --------------------------------------------------------
        # Options 2-5
        # --------------------------------------------------------

        menus = {
            "2": """
📚 What is phishing?

Phishing is a cyber attack where criminals pretend to be
trusted companies or people.

They try to steal:

• Passwords
• Bank details
• OTP codes
• Personal information

Examples:

• Fake banking websites
• Fake login pages
• Fake prizes
""",

            "3": """
🛡 How to protect yourself online:

✅ Check links before clicking
✅ Never share OTP codes
✅ Use two-factor authentication
✅ Avoid unknown attachments
✅ Verify suspicious messages
""",

            "4": """
📱 Common WhatsApp scams:

• Fake job offers
• Fake lottery winnings
• Verification code scams
• Fake customer support
• Family emergency scams

Never share your WhatsApp verification code.
""",

            "5": """
🔍 Send me another URL and I will scan it for you.
""",
        }

        return menus.get(
            option,
            """
Please select an option:

1️⃣ Explain this result
2️⃣ What is phishing?
3️⃣ How do I protect myself?
4️⃣ WhatsApp scams
5️⃣ Scan another URL
""",
        ).strip()

    # ============================================================
    # AI Context
    # ============================================================

    @staticmethod
    def build_ai_messages(
        db: Session,
        phone_number: str,
        latest_message: str,
    ):
        history = ConversationService.get_history(
            db,
            phone_number,
        )

        messages = [
            {
                "role": "system",
                "content": """
You are PhishGuard AI.

You help users understand:

- phishing
- scams
- suspicious websites
- cybersecurity

Keep answers simple and educational.
""".strip(),
            }
        ]

        for item in history:
            messages.append(
                {
                    "role": item.role,
                    "content": item.message,
                }
            )

        messages.append(
            {
                "role": "user",
                "content": latest_message,
            }
        )

        return messages

    # ============================================================
    # URL Processing
    # ============================================================

    @staticmethod
    def process_url(
        db: Session,
        phone_number: str,
        url: str,
    ):
        logger.info(
            "Scanning URL %s",
            url,
        )

        # Run phishing detector
        raw_result = analyze_url(url)

        # Normalize result
        result = normalize_scan_result(
            url,
            raw_result,
        )

        # Save scan result
        save_scan_to_database(
            db,
            result,
        )

        # Build normal scan reply
        scan_reply = build_reply(
            result
        )

        # Get an educational AI explanation
        ai_reply = AIService.ask(
            [
                {
                    "role": "system",
                    "content": """
Explain phishing scan results.

Do not change the ML verdict.

Educate the user.
""".strip(),
                },
                {
                    "role": "user",
                    "content": f"""
URL:
{result['url']}

Verdict:
{result['verdict']}

Risk:
{result['risk_level']}

Reasons:
{', '.join(result['reasons'])}

Advice:
{result['advice']}
""".strip(),
                },
            ]
        )

        # Activate learning menu
        ConversationService.update_state(
            db,
            phone_number,
            "LEARNING_MENU",
        )

        return f"""
{scan_reply}

━━━━━━━━━━━━━━━━━━

🤖 AI Explanation

{ai_reply}

━━━━━━━━━━━━━━━━━━

📚 Learn More

Reply:

1️⃣ Explain this result
2️⃣ What is phishing?
3️⃣ How do I protect myself?
4️⃣ WhatsApp scams
5️⃣ Scan another URL
""".strip()

    # ============================================================
    # AI Normal Chat
    # ============================================================

    @staticmethod
    def process_ai(
        db: Session,
        phone_number: str,
        text: str,
    ):
        messages = ConversationService.build_ai_messages(
            db,
            phone_number,
            text,
        )

        return AIService.ask(messages)

    # ============================================================
    # Main Message Handler
    # ============================================================

    @staticmethod
    def process_message(
        db: Session,
        phone_number: str,
        text: str,
    ):
        text = (text or "").strip()

        if not text:
            return "Please send a message."

        # Save incoming user message
        ConversationService.save_message(
            db,
            phone_number,
            "user",
            text,
        )

        state = ConversationService.get_state(
            db,
            phone_number,
        )

        try:

            # ====================================================
            # Learning Menu
            # ====================================================

            if state.state == "LEARNING_MENU":
                reply = ConversationService.handle_learning_menu(
                    db,
                    phone_number,
                    text,
                )

            # ====================================================
            # Normal Conversation
            # ====================================================

            else:
                url = extract_url(text)

                if url:
                    reply = ConversationService.process_url(
                        db,
                        phone_number,
                        url,
                    )

                else:
                    reply = ConversationService.process_ai(
                        db,
                        phone_number,
                        text,
                    )

        except Exception:
            logger.exception(
                "Conversation error"
            )

            reply = (
                "Sorry, I encountered an error."
            )

        # Save outgoing assistant message
        ConversationService.save_message(
            db,
            phone_number,
            "assistant",
            reply,
        )

        return reply