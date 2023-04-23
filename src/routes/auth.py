from fastapi import Depends, HTTPException, status, APIRouter, Security, BackgroundTasks, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from src.database.db import get_db
from src.schemas import UserModel, UserResponse, Token, RequestEmail, ResetPassword
from src.repository import user as repository_user
from src.services.auth import AuthPassword, AuthToken
from src.services.email import send_email, pass_reset_email

router = APIRouter(prefix="/auth", tags=['auth'])
security = HTTPBearer()
authpassword = AuthPassword()
authtoken = AuthToken()


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED,
             description='Create new user')
async def sign_up(body: UserModel, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db)):
    check_user = await repository_user.get_user_by_email(body.email, db)
    if check_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='This email is already in use')

    body.password = authpassword.get_hash_password(body.password)
    new_user = await repository_user.add_user(body, db)
    background_tasks.add_task(send_email, new_user.email, new_user.username, str(request.base_url))
    return new_user


@router.post("/login", response_model=Token)
async def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = await repository_user.get_user_by_email(body.username, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email")
    if not authpassword.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    if not user.email_confirm:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"check {user.email} to Confirm account")

    access_token = await authtoken.create_access_token(data={"sub": user.email})
    refresh_token = await authtoken.create_refresh_token(data={"sub": user.email})
    await repository_user.update_token(user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh_token", response_model=Token)
async def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    email = await authtoken.refresh_token_email(token)
    user = await repository_user.get_user_by_email(email, db)
    if user.refresh_token != token:
        await repository_user.update_token(user, None, db)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = await authtoken.create_access_token(data={"sub": email})
    refresh_token = await authtoken.create_refresh_token(data={"sub": email})
    await repository_user.update_token(user, refresh_token, db)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.get('/confirmed_email/{token}')
async def confirmed_email(token: str, db: Session = Depends(get_db)):
    email = await authtoken.get_email_from_token(token)
    user = await repository_user.get_user_by_email(email, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification error")
    if user.email_confirm:
        return {"message": "Your email is already confirmed"}
    await repository_user.verify_email(user, db)
    return {"message": "Email confirmed"}


@router.post('/request_email')
async def request_email(body: RequestEmail, background_tasks: BackgroundTasks, request: Request,
                        db: Session = Depends(get_db)):
    user = await repository_user.get_user_by_email(body.email, db)

    if user.confirmed:
        return {"message": "Your email is already confirmed"}
    if user:
        background_tasks.add_task(send_email, user.email, user.username, request.base_url)
    return {"message": "Check your email for confirmation."}


@router.post('/password_reset')
async def password_reset(email: str, background_tasks: BackgroundTasks, request: Request,
                         db: Session = Depends(get_db)):
    user = await repository_user.get_user_by_email(email, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='no user with such email')

    background_tasks.add_task(pass_reset_email, user.email, user.username, request.base_url)
    return f'Reset instruction was sending to {email}'


@router.get('/password_reset_confirm/{token}')
async def password_reset_email(token: str, db: Session = Depends(get_db)):
    print(token)
    email = await authtoken.get_email_from_token(token)
    print(email)
    user = await repository_user.get_user_by_email(email, db)
    print(user)
    reset_password_token = await authtoken.create_reset_password_token(data={"sub": user.email})
    await repository_user.update_reset_token(user, reset_password_token, db)
    return {'reset_token': reset_password_token}


@router.post('/set_new_password')
async def password_reset(request: ResetPassword, db: Session=Depends(get_db)):
    token = request.reset_password_token
    print(token)
    email = await authtoken.reset_token_email(token)
    user = await repository_user.get_user_by_email(email, db)
    check_token = user.password_reset_token
    print(check_token)
    if check_token != token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid reset token")
    if request.new_password != request.confirm_password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="passwords do not match")

    new_password = authpassword.get_hash_password(request.new_password)
    await repository_user.update_password(user, new_password, db)
    await repository_user.update_reset_token(user, None, db)
    return 'password update successfully'