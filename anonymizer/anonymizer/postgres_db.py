import logging
import os

from sqlalchemy import create_engine, text

POSTGRESDB_ENDPOINT = os.environ.get("POSTGRESDB_ENDPOINT", None)

log = logging.getLogger(__name__)


class PostgresDB:

    engine = None
    DATABASE_URL = f"postgresql+psycopg2://admin:admin@{POSTGRESDB_ENDPOINT}/pii"

    @classmethod
    def get_db_engine(cls):
        # singleton so that we dont start the engine everytime
        log.info("Starting the PostgresDB Engine...")
        if cls.engine is None:
            cls.engine = create_engine(cls.DATABASE_URL, echo=True)
        return cls.engine

    def __init__(self):
        self._engine = self.get_db_engine()
