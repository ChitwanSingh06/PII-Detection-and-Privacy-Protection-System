<<<<<<< HEAD
=======
import json
>>>>>>> d7328bf (changed proj)
import logging

from pb.anonymizer import anonymizer_pb2_grpc
from pb.anonymizer import anonymizer_pb2

from anonymizer.pii_anonymizer import PIIAnonymizer
<<<<<<< HEAD
from anonymizer.postgres_db import PostgresDB
=======
from anonymizer.sqlite_db import SqliteDB
>>>>>>> d7328bf (changed proj)

from sqlalchemy import text

log = logging.getLogger(__name__)


class PIIAnonymizerServiceServicer(anonymizer_pb2_grpc.PIIAnonymizerServiceServicer):
    """
    handler code for pii anonymizer gRPC server
    """

    def AnonymizeObject(self, request, context):

        log.info(f"Received Anonymization request for {request.bucketName}/{request.objectKey}")

        bucket_name = request.bucketName
        object_key = request.objectKey
        policy_map = request.policy_map

<<<<<<< HEAD
        # decode the objectBytes to text
        object_data = request.objectData.decode("utf-8")

        # get the sql engine to talk to PostgreSQL DB
        sql_engine = PostgresDB.get_db_engine()
        # connect to PostgreSQL DB to extract the Analyzer results
=======
        object_data = request.objectData.decode("utf-8")

        sql_engine = SqliteDB.get_db_engine()
>>>>>>> d7328bf (changed proj)
        with sql_engine.connect() as conn:
            result = conn.execute(
                text("SELECT pii_entities FROM pii_objects WHERE bucket_name=:bucket AND object_key=:key"),
                {"bucket": bucket_name, "key": object_key}
            ).fetchone()
<<<<<<< HEAD
        pii_metadata = result[0]
        # Anonymize the object data
        anonymizer = PIIAnonymizer()
        updated_object_data = anonymizer.anonymize_data(object_data=object_data, policy_map=policy_map, pii_metadata=pii_metadata)
=======

        if result is None or result[0] is None:
            log.info("No PII metadata found; returning original object")
            return anonymizer_pb2.AnonymizeObjectResponse(
                updatedObjectData=request.objectData,
                objectLength=len(object_data),
            )

        pii_metadata = result[0]
        if isinstance(pii_metadata, str):
            pii_metadata = json.loads(pii_metadata)

        anonymizer = PIIAnonymizer()
        updated_object_data = anonymizer.anonymize_data(
            object_data=object_data, policy_map=policy_map, pii_metadata=pii_metadata
        )
>>>>>>> d7328bf (changed proj)

        return anonymizer_pb2.AnonymizeObjectResponse(
            updatedObjectData=updated_object_data.encode("utf-8"),
            objectLength=len(updated_object_data),
        )
