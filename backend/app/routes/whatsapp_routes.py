import logging
import os

from typing import Optional

from dotenv import load_dotenv

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
)

from sqlalchemy.orm import Session

from app.database import get_db

from app.conversation_service import ConversationService

from app.whatsapp_service import (
    mark_whatsapp_message_as_read,
    send_whatsapp_message,
)


load_dotenv()


logger = logging.getLogger(__name__)


router = APIRouter()


VERIFY_TOKEN = os.getenv(
    "WHATSAPP_VERIFY_TOKEN",
    "phishguard123",
)



# ==========================================================
# WhatsApp Webhook Verification
# ==========================================================


@router.get("/webhook/whatsapp")
def verify_webhook(

    hub_mode: Optional[str] = Query(
        None,
        alias="hub.mode",
    ),

    hub_verify_token: Optional[str] = Query(
        None,
        alias="hub.verify_token",
    ),

    hub_challenge: Optional[str] = Query(
        None,
        alias="hub.challenge",
    ),

):

    logger.info(
        "WhatsApp verification request"
    )


    if (
        hub_mode == "subscribe"
        and hub_verify_token == VERIFY_TOKEN
    ):

        logger.info(
            "WhatsApp webhook verified"
        )


        return Response(
            content=hub_challenge,
            media_type="text/plain",
        )


    raise HTTPException(
        status_code=403,
        detail="Verification failed",
    )



# ==========================================================
# Incoming WhatsApp Messages
# ==========================================================


@router.post("/webhook/whatsapp")
async def receive_whatsapp_message(

    request: Request,

    db: Session = Depends(get_db),

):


    processed_messages = []


    try:


        body = await request.json()


        logger.info(
            "Incoming WhatsApp event"
        )



        entries = body.get(
            "entry",
            []
        )



        for entry in entries:


            changes = entry.get(
                "changes",
                []
            )


            for change in changes:


                value = change.get(
                    "value",
                    {}
                )


                # Ignore delivery/read events

                messages = value.get(
                    "messages",
                    []
                )


                if not messages:

                    continue



                for message in messages:


                    sender_phone = message.get(
                        "from"
                    )


                    message_id = message.get(
                        "id"
                    )


                    message_type = message.get(
                        "type"
                    )



                    if not sender_phone:

                        continue



                    logger.info(
                        "Message from %s",
                        sender_phone
                    )



                    # ----------------------------------
                    # Mark WhatsApp message read
                    # ----------------------------------

                    if message_id:

                        try:

                            mark_whatsapp_message_as_read(
                                message_id
                            )


                        except Exception:

                            logger.exception(
                                "Failed marking message read"
                            )



                    # ----------------------------------
                    # Only process text messages
                    # ----------------------------------


                    if message_type != "text":


                        send_whatsapp_message(

                            sender_phone,

                            """
Please send a text message.

You can:

🔍 Send a URL to scan

📚 Learn about phishing

🤖 Ask cybersecurity questions
"""
                        )


                        processed_messages.append(

                            {
                                "phone": sender_phone,
                                "status": "ignored",
                                "reason": "not_text"
                            }

                        )


                        continue




                    # ----------------------------------
                    # Extract text
                    # ----------------------------------


                    text = (

                        message
                        .get(
                            "text",
                            {}
                        )
                        .get(
                            "body",
                            ""
                        )
                        .strip()

                    )



                    if not text:

                        continue



                    logger.info(

                        "User message: %s",

                        text

                    )



                    # ----------------------------------
                    # Conversation Engine
                    # ----------------------------------


                    try:


                        reply = ConversationService.process_message(

                            db,

                            sender_phone,

                            text

                        )


                    except Exception:


                        db.rollback()


                        logger.exception(

                            "Conversation service failed"

                        )


                        reply = (

                            "Sorry, I could not process your message."

                        )



                    # ----------------------------------
                    # Send WhatsApp Reply
                    # ----------------------------------


                    send_whatsapp_message(

                        sender_phone,

                        reply

                    )



                    processed_messages.append(

                        {
                            "phone": sender_phone,
                            "status": "processed"
                        }

                    )




        return {

            "status": "success",

            "processed": processed_messages

        }



    except Exception as e:


        logger.exception(

            "WhatsApp webhook error"

        )


        return {

            "status": "error",

            "detail": str(e)

        }