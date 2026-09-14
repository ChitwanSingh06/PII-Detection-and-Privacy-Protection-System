# Dynamic Policy-Driven Data Privacy Framework for Alletra MP X10000 and AI Workloads
A proof-of-concept (PoC) implementation of a native, inline sensitive data protection framework for HPE Alletra MP X10000.
This solution integrates sensitive data detection and policy enforcement directly into storage operations such as PUT and GET, enabling secure and intelligent management of unstructured data.

## Features
- **Inline Analysis** – Automatically scans for sensitive information and enriches metadata during object `PUT` operations.  
- **Real-time Policy Enforcement** – Applies masking, redaction, or other anonymization actions dynamically during object `GET` based on user policies.  
- **Event-Driven Architecture** – Analysis pipeline gets automatically triggered on S3 `PUT` object event.  
- **Pluggable Detection Framework** – Supports custom analyzers and policies for diverse data types and governance requirements.
- **Seamless S3 API Compatibility** - The framework works transparently with standard S3 APIs, requiring no changes to existing applications and minimizing integration or operational overhead

## Architecture 

![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/80950/0223949c-842f-49c5-83b7-31d51b2ed3a1)

## Results 
The POC was evaluated using Kaggle's PII Data detection competition dataset with -

- **Scale**: 1000 object retrievals (~2450 words, ~45 PII entities each) 
- **CPU**: 40 cores, Memory: 256GiB 

A negligible retrieval latency of ~25ms was observed. Using default Presidio recognisers, it achieved recall rates of **95.8%** for person names and **94%** for emails. Anonymization strategies were correctly applied based on user-specific policies during GET object requests.


![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/68480/6b1b126c-d2c6-4c57-acdf-bb27686915a6)

## Example Usage

### Admin User
![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/68480/7f020bff-c358-43ce-b828-6338719c0cbe)

### User-1 
Policy associated with User-1
```json
[
    {
        "entity_type": "PERSON",
        "operator_name": "replace",
        "operator_params": {"new_value": "PERSON"}
    },
    {
        "entity_type": "CREDIT_CARD",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 10}
    },
    {
        "entity_type": "EMAIL_ADDRESS",
        "operator_name": "replace",
        "operator_params": {"new_value": "<EMAIL>"}
    },
    {
        "entity_type": "PHONE_NUMBER",
        "operator_name": "replace",
        "operator_params": {"new_value": "PHONE_NUMBER"}
    },
    {
        "entity_type": "US_SSN",
        "operator_name": "redact"
    },
    {
        "entity_type": "US_BANK_NUMBER",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 10}
    }
]
```
![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/68480/ff7e63b8-eb15-4be8-92ff-96644e840e07)

### User-2

Policy associated with User-2
```json
[
    {
        "entity_type": "CREDIT_CARD",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 10}
    },
    {
        "entity_type": "EMAIL_ADDRESS",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 100}
    },
    {
        "entity_type": "PHONE_NUMBER",
        "operator_name": "replace",
        "operator_params": {"new_value": "<PHONE>"}
    },
    {
        "entity_type": "US_SSN",
        "operator_name": "redact"
    },
    {
        "entity_type": "US_BANK_NUMBER",
        "operator_name": "mask",
        "operator_params": {"from_end": false, "masking_char": "*", "chars_to_mask": 10}
    }
]
```
![image](https://github.hpe.com/deepika-indran/PII-for-Object-Storage/assets/68480/39d8f51f-4aba-4588-987f-156a3a754e74)


