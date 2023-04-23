from datetime import date
from pydantic import BaseModel, Field, EmailStr


class UserModel(BaseModel):
    username: str
    email: EmailStr
    password: str = Field(min_length=5)


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    avatar: str

    class Config:
        orm_mode = True



class ContactModel(BaseModel):
    first_name: str = Field(max_length=50)
    last_name: str = Field(max_length=50)
    email: EmailStr
    phone_number: str = Field(max_length=20)
    birthday: date = Field(default=date(year=1900, month=1, day=1))
    address: str = Field(max_length=200)
    user_id: int


class ContactsResponse(ContactModel):
    user = UserResponse

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserInDB(UserModel):
    hashed_password: str


class RequestEmail(BaseModel):
    email: EmailStr


class ResetPassword(BaseModel):
    reset_password_token: str
    new_password: str
    confirm_password: str
