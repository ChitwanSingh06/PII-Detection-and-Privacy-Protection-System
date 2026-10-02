from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine


class SqliteModel:
    engine = None

    @classmethod
    def create_engine(cls, sqlite_path: str):
        if cls.engine is None:
            Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            database_url = f"sqlite+aiosqlite:///{sqlite_path}"
            cls.engine = create_async_engine(
                database_url,
                connect_args={"check_same_thread": False},
            )
        return cls.engine
