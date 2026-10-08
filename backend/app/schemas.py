from datetime import datetime
from typing import List
from pydantic import BaseModel


class ConversationCreate(BaseModel):
    phone_number: str
    role: str
    message: str


class ConversationResponse(BaseModel):
    id: int
    phone_number: str
    role: str
    message: str
    created_at: datetime

    class Config:
        from_attributes = True      # Use orm_mode=True if Pydantic v1


class ConversationHistory(BaseModel):
    phone_number: str
    messages: List[ConversationResponse]