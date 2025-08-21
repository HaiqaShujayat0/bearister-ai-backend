# utils.py
import requests
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from jose import jwt
from postmarker.core import PostmarkClient


load_dotenv()



# Load env variables
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")


def create_verification_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_verification_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def send_verification_email(to_email: str, token: str):
    verify_link = f"{FRONTEND_URL}/auth/verify-email?token={token}"

    client = PostmarkClient(POSTMARK_API_TOKEN)

    client.emails.send(
        From="support@bearister.ai",   # make sure this is your verified sender signature
        To=to_email,
        Subject="Verify your account",
        TextBody=f"Please verify your email by clicking the link below:\n\n{verify_link}\n\nThis link will expire in 30 minutes.",
        Tag="email-verification"
    )
