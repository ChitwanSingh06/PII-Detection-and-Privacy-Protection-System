import grpc
import logging
from concurrent import futures
from grpc_reflection.v1alpha import reflection

from pb.anonymizer import anonymizer_pb2_grpc
from pb.anonymizer import anonymizer_pb2

from anonymizer.server.handler import PIIAnonymizerServiceServicer

GRPC_PORT = 10666
log = logging.getLogger(__name__)


class GrpcServer:

    def __init__(self):
        self._port = GRPC_PORT

    def start_server(self):
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
        anonymizer_pb2_grpc.add_PIIAnonymizerServiceServicer_to_server(PIIAnonymizerServiceServicer(), server)

        SERVICE_NAMES = (
            anonymizer_pb2.DESCRIPTOR.services_by_name['PIIAnonymizerService'].full_name,
            reflection.SERVICE_NAME,
        )
        reflection.enable_server_reflection(SERVICE_NAMES, server)

        server.add_insecure_port(f"[::]:{self._port}")
        log.info(f"gRPC server started on port {self._port}")
        server.start()

        return server
