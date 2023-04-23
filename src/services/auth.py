from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, Depends, status
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import redis

from src.conf.config import settings
from src.database.db import get_db
from src.repository import user as repository_user


class AuthPassword:
    pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

    def get_hash_password(self, password: str):
        return self.pwd_context.hash(password)

    def verify_password(self, password: str, hashed_password: str):
        return self.pwd_context.verify(password, hashed_password)


class AuthToken:
    SECRET_KEY = settings.secret_key
    ALGORITHM = settings.algorithm
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/auth/login')
    r = redis.Redis(host=settings.redis_host, port=settings.redis_port, db=0)

    async def create_access_token(self, data: dict, expires_delta: Optional[float] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(minutes=30)

        to_encode.update({'iat': datetime.utcnow(), 'exp': expire, 'scope': 'access_token'})
        access_token = jwt.encode(to_encode, self.SECRET_KEY, self.ALGORITHM)
        return access_token

    async def create_refresh_token(self, data: dict, expires_delta: Optional[float] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(minutes=30)

        to_encode.update({'iat': datetime.utcnow(), 'exp': expire, 'scope': 'refresh_token'})
        refresh_token = jwt.encode(to_encode, self.SECRET_KEY, self.ALGORITHM)
        return refresh_token

    async def create_reset_password_token(self, data: dict, expires_delta: Optional[float] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(minutes=5)

        to_encode.update({'iat': datetime.utcnow(), 'exp': expire, 'scope': 'reset_password_token'})
        reset_password_token = jwt.encode(to_encode, self.SECRET_KEY, self.ALGORITHM)
        return reset_password_token

    async def get_current_user(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )

        try:
            payload = jwt.decode(token, self.SECRET_KEY, self.ALGORITHM)
            if payload['scope'] == 'access_token':
                email = payload['sub']
                if email is None:
                    raise credentials_exception
            else:
                raise credentials_exception
        except:
            raise credentials_exception
# TODO
        user = self.r.get(email)
        if user is None:
            user = await repository_user.get_user_by_email(email, db)
            user = user.id
            if user is None:
                raise credentials_exception
            self.r.set(email, user)
            self.r.expire(email, 60)
        else:
            user = user.decode()
        return user

    async def refresh_token_email(self, refresh_token: str = Depends(oauth2_scheme)):
        try:
            payload = jwt.decode(refresh_token, self.SECRET_KEY, self.ALGORITHM)
            if payload['scope'] == 'refresh_token':
                email = payload['sub']
                if email is None:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid Email')
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid scope for token')
        except:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate credentials')

        return email

    async def reset_token_email(self, reset_token: str = Depends(oauth2_scheme)):
        try:
            payload = jwt.decode(reset_token, self.SECRET_KEY, self.ALGORITHM)
            if payload['scope'] == 'reset_password_token':
                email = payload['sub']
                if email is None:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid Email')
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid scope for token')
        except:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate credentials')

        return email

    async def create_email_token(self, data: dict):
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(hours=1)
        to_encode.update({"iat": datetime.utcnow(), "exp": expire})
        token = jwt.encode(to_encode, self.SECRET_KEY, self.ALGORITHM)
        return token

    async def get_email_from_token(self, token: str):
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            email = payload["sub"]
            return email
        except JWTError as e:
            print(e)
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="Invalid token for email verification")
