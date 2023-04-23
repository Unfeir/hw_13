from libgravatar import Gravatar
from sqlalchemy.orm import Session

from src.database.models import User
from src.schemas import UserModel


async def get_user_by_email(email, db):
    user = db.query(User).filter(User.email == email).first()
    return user


async def get_user_by_id(userid, db):
    user = db.query(User).filter(User.id == userid).first()
    return user


async def add_user(body: UserModel, db):
    user = User(
        username=body.username,
        email=body.email,
        password=body.password,
        avatar=Gravatar(body.email).get_image()
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


async def update_token(user: User, refresh_token, db: Session):
    user.refresh_token = refresh_token
    db.commit()


async def update_reset_token(user: User, reset_token: str, db: Session):
    user.password_reset_token = reset_token
    db.commit()

async def update_password(user: User, new_password: str, db: Session):
    user.password = new_password
    db.commit()


async def verify_email(user: User, db: Session):
    user.email_confirm = True
    db.commit()


async def update_avatar(user: User, url: str, db: Session) -> User:
    user.avatar = url
    db.commit()
    return user
