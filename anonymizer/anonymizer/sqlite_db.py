import logging
import sys
from pathlib import Path

from sqlalchemy import create_engine

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import SQLITE_PATH  # noqa: E402

log = logging.getLogger(__name__)


class SqliteDB:
    engine = None
    DATABASE_URL = f"sqlite:///{SQLITE_PATH}"

    @classmethod
    def get_db_engine(cls):
        log.info("Starting the SQLite engine...")
        if cls.engine is None:
            Path(SQLITE_PATH).parent.mkdir(parents=True, exist_ok=True)
            cls.engine = create_engine(
                cls.DATABASE_URL,
                echo=False,
                connect_args={"check_same_thread": False},
            )
        return cls.engine

    def __init__(self):
        self._engine = self.get_db_engine()
