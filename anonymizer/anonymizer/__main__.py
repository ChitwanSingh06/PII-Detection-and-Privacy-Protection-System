import logging

from anonymizer.server.server import GrpcServer
from anonymizer.pii_anonymizer import PIIAnonymizer
from anonymizer.sqlite_db import SqliteDB

logging.basicConfig(
    level=logging.DEBUG,  # Show all logs DEBUG and above
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger(__name__)


if __name__ == "__main__":
    # initialize the anonymizer engine
    PIIAnonymizer.get_anonymizer_engine()

    SqliteDB.get_db_engine()

    # start the grpc server
    server = GrpcServer().start_server()
    try:
        server.wait_for_termination()  # Block the thread to keep the server running
    except Exception as e:
        log.info(f"Failed to start grpc server: {e}")
    except KeyboardInterrupt:
        log.info("gRPC server stopping...")
        server.stop(0)  # Gracefully stop the server
