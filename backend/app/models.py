from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
)

from sqlalchemy.sql import func

from datetime import datetime

from app.database import Base



# ==========================================================
# WhatsApp Conversation State
# ==========================================================


class ConversationState(Base):

    __tablename__ = "conversation_states"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )


    phone_number = Column(
        String(30),
        unique=True,
        index=True,
        nullable=False
    )


    state = Column(
        String(50),
        default="IDLE",
        nullable=False
    )


    # Stores last scan information/context

    context = Column(
        Text,
        nullable=True
    )


    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )



# ==========================================================
# Users
# ==========================================================


class User(Base):

    __tablename__ = "users"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )


    full_name = Column(
        String(120),
        nullable=False
    )


    email = Column(
        String(120),
        unique=True,
        index=True,
        nullable=False
    )


    password_hash = Column(
        String(255),
        nullable=False
    )


    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )



# ==========================================================
# URL Scan History
# ==========================================================


class UrlScan(Base):

    __tablename__ = "url_scans"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )


    url = Column(
        Text,
        nullable=False
    )


    result = Column(
        String(50),
        nullable=True
    )


    verdict = Column(
        String(50),
        nullable=True
    )


    risk_level = Column(
        String(50),
        nullable=True
    )


    score = Column(
        Integer,
        nullable=True
    )


    risk_score = Column(
        Integer,
        nullable=True
    )


    reasons = Column(
        Text,
        nullable=True
    )


    reason = Column(
        Text,
        nullable=True
    )


    advice = Column(
        Text,
        nullable=True
    )


    source = Column(
        String(50),
        default="web"
    )


    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )



# ==========================================================
# Conversation History
# ==========================================================


class Conversation(Base):

    __tablename__ = "conversations"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )


    phone_number = Column(
        String(30),
        index=True,
        nullable=False
    )


    # user | assistant | system

    role = Column(
        String(20),
        nullable=False
    )


    message = Column(
        Text,
        nullable=False
    )


    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )