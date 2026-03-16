import os

from sqlmodel import Session, select

from backend.classes.database import engine
from backend.classes.auth import hash_password
from backend.models.user import User


def seed_admin():
    """Create default admin user if it doesn't exist."""
    username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    password = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin")

    with Session(engine) as session:
        existing = session.exec(select(User).where(User.username == username)).first()
        if not existing:
            admin = User(
                username=username,
                password_hash=hash_password(password),
                role="admin",
            )
            session.add(admin)
            session.commit()
            print(f"Seeded default admin user ({username})")
