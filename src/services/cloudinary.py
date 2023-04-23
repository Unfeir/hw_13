import hashlib

import cloudinary
import cloudinary.uploader

from src.conf.config import settings


class CloudImage:
    cloudinary.config(
        cloud_name=settings.cloudinary_name,
        api_key=settings.cloudinary_api_key,
        api_secret=settings.cloudinary_api_secret,
        secure=True
    )

    def get_name(self, email):
        return hashlib.sha256(email.encode()).hexdigest()[:8]


    def upload(self, file, route):
        r = cloudinary.uploader.upload(file, folder='NoteBook', public_id=route, overwrite=True)
        return r

    def get_url_for_avatar(self, route, r):
        src_url = cloudinary.CloudinaryImage(f'NoteBook/{route}') \
            .build_url(width=250, height=250, crop='fill', version=r.get('version'))
        return src_url
