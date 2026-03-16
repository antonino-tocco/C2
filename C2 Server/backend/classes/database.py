import os
from sqlmodel import SQLModel, Session, create_engine

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://c2admin:c2password@localhost:5432/c2db")

engine = create_engine(DATABASE_URL, echo=False)


def init_db():
    import backend.models  # noqa: F401 — ensure all models are registered
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
