from fastapi import APIRouter, Depends, status, UploadFile, File
from sqlalchemy.orm import Session


from src.database.db import get_db
from src.repository import user as repository_users
from src.services.auth import AuthToken
from src.schemas import UserResponse
from src.services.cloudinary import CloudImage

cloud_image = CloudImage()

authtoken = AuthToken()
router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me/", response_model=UserResponse)
async def read_users_me(current_user: int = Depends(authtoken.get_current_user), db: Session = Depends(get_db) ):
    return await repository_users.get_user_by_id(current_user, db)


@router.patch('/avatar', response_model=UserResponse)
async def update_avatar_user(file: UploadFile = File(), current_user: int = Depends(authtoken.get_current_user),
                             db: Session = Depends(get_db)):
    user = await repository_users.get_user_by_id(current_user, db)
    route = cloud_image.get_name(user.email)
    r = cloud_image.upload(file.file, route)
    src_url = cloud_image.get_url_for_avatar(route, r)
    user = await repository_users.update_avatar(user, src_url, db)
    return user
