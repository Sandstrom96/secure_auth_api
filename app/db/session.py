from sqlmodel import create_engine, Session
from typing import Generator
from app.core.config import settings

# Create the database engine using the URL from our settings.
# pool_pre_ping=True: Checks the connection before using it.
# This fixes "server closed connection" errors if the DB has been idle.
engine = create_engine(url=settings.DATABASE_URL, pool_pre_ping=True)


def get_session() -> Generator[Session, None, None]:
    """
    Dependency function that provides a database session to a route.
    Using 'yield' allows FastAPI to close the session automatically
    after the request is finished (even if an error occurs).
    """
    with Session(engine) as session:
        yield session
