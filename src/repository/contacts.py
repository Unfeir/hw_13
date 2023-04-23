from datetime import date, timedelta

from sqlalchemy.orm import Session

from src.database.models import Contact
from src.schemas import ContactModel


async def get_contacts(skip, limit, user: int, db: Session):
    contacts = db.query(Contact).filter_by(user_id=user).offset(skip).limit(limit).all()
    return contacts


async def get_contact(contact_id, user: int, db: Session):
    contact = db.query(Contact).filter_by(id=contact_id, user_id=user).first()
    return contact


async def search_contact(db: Session, user: int, first_name=None, last_name=None, email=None):
    contacts = None
    if first_name and last_name:
        contacts = db.query(Contact).filter_by(first_name=first_name.capitalize(), last_name=last_name.capitalize(),
                                               user_id=user).all()
    if first_name:
        contacts = db.query(Contact).filter_by(first_name=first_name.capitalize(), user_id=user).all()
    if email:
        contacts = db.query(Contact).filter_by(email=email.lower(), user_id=user).all()

    return contacts


async def add_contact(body: ContactModel, user: int, db: Session):
    contact = Contact(first_name=body.first_name.capitalize(),
                      last_name=body.last_name.capitalize(),
                      email=body.email,
                      phone_number=body.phone_number,
                      birthday=body.birthday,
                      address=body.address,
                      user_id=user)

    db.add(contact)
    db.commit()
    db.refresh(contact)
    return contact


async def change_contact(contact_id, body, user: int, db: Session):
    contact = await get_contact(contact_id, user, db)
    if contact:
        contact.first_name = body.first_name
        contact.last_name = body.last_name
        contact.birthday = body.birthday
        contact.email = body.email
        contact.address = body.address
        db.commit()
    return contact


async def remove_contact(contact_id, user: int, db: Session):
    contact = await get_contact(contact_id, user, db)
    if contact:
        db.delete(contact)
        db.commit()
    return contact


async def get_birthdays(user: int, db: Session):
    today = date.today()
    delta = timedelta(days=7)
    all_contacts = db.query(Contact).filter_by(user_id=user).all()
    contacts = []
    for contact in all_contacts:
        if contact.birthday.replace(year=today.year) >= today and contact.birthday.replace(
                year=today.year) <= today + delta:
            contacts.append(contact)
    return contacts
