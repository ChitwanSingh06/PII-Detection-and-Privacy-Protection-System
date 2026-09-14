import logging

from presidio_analyzer import RecognizerResult
from presidio_anonymizer.entities import OperatorConfig
from presidio_anonymizer import AnonymizerEngine

from google.protobuf.json_format import MessageToDict

log = logging.getLogger(__name__)


class PIIAnonymizer:

    anonymizer_engine = None

    @classmethod
    def get_anonymizer_engine(cls):
        # singleton so that we dont start the engine everytime
        if cls.anonymizer_engine is None:
            log.info("Starting the Anonymizer Engine...")
            cls.anonymizer_engine = AnonymizerEngine()
            log.info("Anonymizer Engine is running...")
        return cls.anonymizer_engine

    def __init__(self):
        self._anonymizer = self.get_anonymizer_engine()

    def anonymize_data(
        self, *, object_data: str, policy_map: dict, pii_metadata: list
    ) -> str:
        """Anonymize data as per policy map"""

        anonymized_result = self._anonymizer.anonymize(
            text=object_data,
            analyzer_results=self._get_analyzer_data(pii_metadata=pii_metadata),
            operators=self._create_operator_config(policy_map=policy_map),
        )
        return anonymized_result.text

    def _get_analyzer_data(self, *, pii_metadata):
        return [
            RecognizerResult(
                entity_type=entry["type"],
                start=entry["start"],
                end=entry["end"],
                score=entry["score"],
            )
            for entry in pii_metadata
        ]

    def _create_operator_config(self, *, policy_map: dict):
        """
        Sample Input:
        [
            {
                entity_type: PERSON,
                operator_name: replace,
                operator_params: {"new_value": "REPLACED_NAME"}
            },
            {
                entity_type: EMAIL_ADDRESS,
                operator_name: mask,
                operator_params: {"masking_char": "*", "chars_to_mask": 5, "from_end": True}
            },
            ....
        ]

        Sample Output:
        {
            "PERSON": OperatorConfig(
                operator_name="replace",
                params={"new_value": "REPLACED_NAME"}
            ),
            "EMAIL_ADDRESS": OperatorConfig(
                operator_name="mask",
                params={"masking_char": "*", "chars_to_mask": 5, "from_end": True}
            ),
            ...
        }
        """
        operator_config_map = {}
        for policy in policy_map:
            entity_type = policy.entityType
            operator_name = policy.operatorName
            operator_params = MessageToDict(policy.operatorParams)

            if operator_name == "mask":
                operator_params["chars_to_mask"] = int(operator_params["chars_to_mask"])

            if entity_type and operator_name:
                if entity_type in operator_config_map:
                    log.error(f"Multiple policies found for entity type {entity_type}!")
                    continue
                operator_config_map[entity_type] = OperatorConfig(
                    operator_name=operator_name, params=operator_params
                )
        # default operator is noop
        operator_config_map["DEFAULT"] = OperatorConfig(operator_name="keep")

        return operator_config_map
