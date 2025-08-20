from sqlalchemy import Column, Integer, String,Boolean
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    phone = Column(String(20), unique=True, index=True)
    is_superadmin = Column(Boolean, default=False)
    agree_terms = Column(Boolean, nullable=False)
    verification_token = Column(String, nullable=True)
    is_verified = Column(Boolean, default=False)
