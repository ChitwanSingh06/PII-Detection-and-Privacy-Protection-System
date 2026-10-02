import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PII_ANALYSER_DIR = ROOT / "consumer_analyzer" / "pii_analyser"
for path in (str(ROOT), str(PII_ANALYSER_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from pii_analyser import PIIProcessor  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


class LocalUploadTrigger:
    """Replace S3 PUT / Kafka events with an in-process analysis trigger."""

    def __init__(self):
        self.processor = PIIProcessor()

    def on_put(self, bucket_name: str, object_key: str) -> None:
        logging.info(f"Local PUT trigger: analyzing {bucket_name}/{object_key}")
        self.processor.process(bucket_name, object_key)


if __name__ == "__main__":
    print("This trigger is used by the proxy after local uploads. No Kafka consumer is required.")
