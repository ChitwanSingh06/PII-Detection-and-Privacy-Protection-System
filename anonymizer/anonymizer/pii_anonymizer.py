import logging

from presidio_analyzer import RecognizerResult
from presidio_anonymizer.entities import OperatorConfig
from presidio_anonymizer import AnonymizerEngine

from google.protobuf.json_format import MessageToDict

log = logging.getLogger(__name__)


def _card_masker(params: dict):
    """Mask a card number by DIGITS (separators are kept and never counted), always hiding all but the last 4.

    Presidio's stock mask counts characters, so on '4111 1111 1111 1111' a policy of 10 chars hid only 8 digits and
    left 8 visible. The policy's chars_to_mask / from_end / masking_char are still honoured; the last 4 digits are
    the most that can ever stay visible.
    """
    ch = str(params.get("masking_char") or "*")[:1] or "*"
    n = int(params.get("chars_to_mask") or 0)
    from_end = bool(params.get("from_end", False))

    def mask(text: str) -> str:
        idx = [i for i, c in enumerate(text) if c.isdigit()]
        total = len(idx)
        hide = set(idx[:max(total - 4, 0)])  # the floor: everything except the last 4 digits
        n_eff = min(max(n, 0), total)
        hide |= set(idx[total - n_eff:] if from_end else idx[:n_eff])
        return "".join(ch if i in hide else c for i, c in enumerate(text))

    return mask


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

        operators = self._create_operator_config(policy_map=policy_map)
        cc = operators.get("CREDIT_CARD")
        if cc is not None and cc.operator_name == "mask":
            operators["CREDIT_CARD"] = OperatorConfig("custom", {"lambda": _card_masker(cc.params)})
        # Policy-aware conflict resolution: Presidio drops any span that lies INSIDE another span, whatever
        # the policy says. Without this filter an address span (or a spaCy ORGANIZATION) that has no rule
        # could swallow a PIN code / e-mail / phone that DOES have a rule, and it would be returned unmasked.
        # Spans of types without a rule only ever "keep" the text, so removing them changes nothing else.
        analyzer_results = [
            r for r in self._get_analyzer_data(pii_metadata=pii_metadata)
            if r.entity_type in operators and r.entity_type != "DEFAULT"
        ]
        anonymized_result = self._anonymizer.anonymize(
            text=object_data,
            analyzer_results=analyzer_results,
            operators=operators,
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
                operator_params["chars_to_mask"] = int(operator_params.get("chars_to_mask", 0))
                if "from_end" in operator_params:
                    operator_params["from_end"] = bool(operator_params["from_end"])

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
