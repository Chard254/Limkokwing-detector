import os
import json
import logging
import urllib.request
import urllib.error

from dotenv import load_dotenv


load_dotenv()


logger = logging.getLogger(__name__)



# =====================================================
# WhatsApp Configuration
# =====================================================


WHATSAPP_TOKEN = (

    os.getenv("WHATSAPP_ACCESS_TOKEN")

    or os.getenv("WHATSAPP_TOKEN")

)



PHONE_NUMBER_ID = os.getenv(
    "WHATSAPP_PHONE_NUMBER_ID"
)



GRAPH_API_VERSION = (

    os.getenv("GRAPH_API_VERSION")

    or os.getenv("WHATSAPP_API_VERSION")

    or "v25.0"

).strip("/")




# =====================================================
# WhatsApp URL
# =====================================================


def _whatsapp_messages_url():

    return (

        f"https://graph.facebook.com/"

        f"{GRAPH_API_VERSION}/"

        f"{PHONE_NUMBER_ID}/messages"

    )




# =====================================================
# Send WhatsApp Message
# =====================================================


def send_whatsapp_message(

    to: str,

    message: str,

    preview_url: bool = False

):


    if not WHATSAPP_TOKEN:

        logger.error(
            "Missing WhatsApp token"
        )

        return {
            "error":
            "Missing WhatsApp token"
        }



    if not PHONE_NUMBER_ID:

        logger.error(
            "Missing phone number ID"
        )

        return {
            "error":
            "Missing phone number ID"
        }



    # Prevent huge messages

    if len(message) > 4000:

        message = (
            message[:3900]
            +
            "\n\n..."
        )



    payload = {

        "messaging_product":
            "whatsapp",


        "to":
            to,


        "type":
            "text",


        "text":
        {

            "preview_url":
                preview_url,


            "body":
                message

        }

    }



    data = json.dumps(
        payload
    ).encode(
        "utf-8"
    )



    request = urllib.request.Request(

        _whatsapp_messages_url(),

        data=data,

        method="POST",

        headers={

            "Authorization":
            f"Bearer {WHATSAPP_TOKEN}",


            "Content-Type":
            "application/json"

        }

    )



    try:


        with urllib.request.urlopen(
            request,
            timeout=20
        ) as response:


            body = response.read().decode(
                "utf-8"
            )


            logger.info(
                "WhatsApp sent successfully"
            )


            return json.loads(
                body
            )



    except urllib.error.HTTPError as e:


        error = e.read().decode(
            "utf-8"
        )


        logger.error(
            "WhatsApp API error %s: %s",
            e.code,
            error
        )


        return {

            "status":
            e.code,


            "error":
            error

        }



    except Exception as e:


        logger.exception(
            "WhatsApp sending failed"
        )


        return {

            "error":
            str(e)

        }




# =====================================================
# Mark Message Read
# =====================================================


def mark_whatsapp_message_as_read(

    message_id: str

):


    if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:

        return {

            "error":
            "Missing WhatsApp credentials"

        }



    payload = {

        "messaging_product":
        "whatsapp",


        "status":
        "read",


        "message_id":
        message_id

    }



    data = json.dumps(
        payload
    ).encode(
        "utf-8"
    )



    request = urllib.request.Request(

        _whatsapp_messages_url(),

        data=data,

        method="POST",

        headers={

            "Authorization":
            f"Bearer {WHATSAPP_TOKEN}",


            "Content-Type":
            "application/json"

        }

    )



    try:


        with urllib.request.urlopen(
            request,
            timeout=20
        ) as response:


            body = response.read().decode(
                "utf-8"
            )


            return json.loads(
                body
            )



    except urllib.error.HTTPError as e:


        error = e.read().decode(
            "utf-8"
        )


        logger.error(
            "Read receipt failed: %s",
            error
        )


        return {

            "error":
            error

        }


    except Exception as e:


        return {

            "error":
            str(e)

        }