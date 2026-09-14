from sqlalchemy.ext.asyncio import create_async_engine

class PostgresModel:
    engine = None
    @classmethod
    def create_engine(cls, user, password, host, db):
        if cls.engine is None:
            DATABASE_URL = f"postgresql+asyncpg://{user}:{password}@{host}/{db}"
            cls.engine = create_async_engine(DATABASE_URL)
        return cls.engine