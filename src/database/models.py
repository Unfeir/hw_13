from datetime import date, datetime

from sqlalchemy import Column, Integer, String, Date, DateTime, func, ForeignKey, Boolean
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50))
    email = Column(String(150), nullable=False, unique=True)
    email_confirm = Column(Boolean, default=False)
    password = Column(String(255), nullable=False)
    avatar = Column(String(255), nullable=True)
    refresh_token = Column(String(255), nullable=True)
    password_reset_token = Column(String(255), nullable=True)

class Contact(Base):
    __tablename__ = 'contacts'
    id = Column(Integer, primary_key=True)
    first_name = Column(String(50), nullable=False, index=True)
    last_name = Column(String(50), nullable=False, index=True)
    email = Column(String(50), nullable=False, index=True)
    phone_number = Column(String(20), nullable=False)
    birthday = Column(Date, nullable=True, default=date(year=1900, month=1, day=1))
    address = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship('User', backref='contacts')
