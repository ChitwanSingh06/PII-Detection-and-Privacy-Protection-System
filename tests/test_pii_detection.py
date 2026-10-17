"""PII detection accuracy for the Indian + US categories, using the REAL analyzer (spaCy + custom recognizers).

Covers: formatting variants, checksum validation (Verhoeff for Aadhaar, Luhn for cards), structural SSN rules,
context requirements for ambiguous digit runs, and a set of look-alike strings that must NOT be detected.
"""
import pytest

from pii_recognizers import luhn_valid, verhoeff_check_digit, verhoeff_valid


@pytest.fixture(scope="module")
def analyzer():
    from pii_analyser import PIIAnalyzer
    return PIIAnalyzer()


def found(analyzer, text):
    # the threshold is the project's configured PII_SCORE_THRESHOLD (default 0.6)
    return [(r["type"], text[r["start"]:r["end"]]) for r in analyzer.analyze(text)]


def types(analyzer, text):
    return {t for t, _ in found(analyzer, text)}


def has(analyzer, text, etype, value=None):
    return any(t == etype and (value is None or v == value) for t, v in found(analyzer, text))


# ---- checksum helpers ---------------------------------------------------------------------------------
def test_verhoeff_reference_vector():
    assert verhoeff_check_digit("236") == "3" and verhoeff_valid("2363") and not verhoeff_valid("2364")


def test_luhn_reference():
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")


VALID_AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")  # 234567890124


# ---- Aadhaar ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("fmt", [
    "{a} {b} {c}", "{a}-{b}-{c}", "{a}.{b}.{c}",
])
def test_aadhaar_grouped_variants(analyzer, fmt):
    a, b, c = VALID_AADHAAR[:4], VALID_AADHAAR[4:8], VALID_AADHAAR[8:]
    v = fmt.format(a=a, b=b, c=c)
    assert has(analyzer, f"KYC document number {v} received", "IN_AADHAAR", v)


def test_aadhaar_contiguous_needs_context(analyzer):
    assert has(analyzer, f"Aadhaar: {VALID_AADHAAR}", "IN_AADHAAR", VALID_AADHAAR)
    assert not has(analyzer, f"Order number {VALID_AADHAAR} shipped", "IN_AADHAAR")


def test_aadhaar_bad_checksum_rejected(analyzer):
    bad = VALID_AADHAAR[:-1] + str((int(VALID_AADHAAR[-1]) + 1) % 10)
    assert not has(analyzer, f"Aadhaar {bad[:4]} {bad[4:8]} {bad[8:]}", "IN_AADHAAR")


def test_aadhaar_cannot_start_with_0_or_1(analyzer):
    p = "1" + VALID_AADHAAR[1:11]
    n = p + verhoeff_check_digit(p)
    assert not has(analyzer, f"Aadhaar {n}", "IN_AADHAAR")


def test_aadhaar_not_carved_out_of_a_card_number(analyzer):
    assert "IN_AADHAAR" not in types(analyzer, "Card 4111 1111 1111 1111 on file")


# ---- Indian phone numbers -----------------------------------------------------------------------------
@pytest.mark.parametrize("num", [
    "+91 98765 43210", "+91-9876543210", "+919876543210", "0091 9876543210", "(+91) 98765-43210",
    "09876543210", "98765 43210", "98765-43210", "91 9876543210",
    "022-2345 6789", "+91 11 23456789", "011-23456789", "080 4123 4567",
])
def test_indian_phone_variants(analyzer, num):
    assert has(analyzer, f"You can reach me on {num} anytime", "PHONE_NUMBER", num), found(analyzer, num)


def test_bare_ten_digits_need_phone_context(analyzer):
    assert has(analyzer, "Mobile: 9876543210", "PHONE_NUMBER", "9876543210")
    assert not has(analyzer, "Invoice 9876543210 was paid", "PHONE_NUMBER")


@pytest.mark.parametrize("text", [
    "Call 5876543210 now",          # does not start with 6-9
    "Call 9999999999 now",          # repeated digits
    "Tracking id 1234567890123",    # too long
    "Timestamp 1700000000 UTC",
])
def test_phone_false_positives(analyzer, text):
    assert "PHONE_NUMBER" not in types(analyzer, text)


# ---- PIN codes ----------------------------------------------------------------------------------------
@pytest.mark.parametrize("text,val", [
    ("PIN code 560001", "560001"), ("Pincode: 400 001", "400 001"), ("Chennai - 600001", "600001"),
    ("Karnataka 560034", "560034"), ("PIN: 110001", "110001"),
])
def test_pin_with_context(analyzer, text, val):
    assert has(analyzer, text, "IN_PIN_CODE", val), found(analyzer, text)


@pytest.mark.parametrize("text", [
    "Reference 560001 closed", "Invoice 123456", "Total 100001 units", "PIN 000001", "pincode 890123",
])
def test_pin_without_context_or_invalid_circle_rejected(analyzer, text):
    assert "IN_PIN_CODE" not in types(analyzer, text)


# ---- Indian addresses ---------------------------------------------------------------------------------
def test_indian_full_address(analyzer):
    t = "Please ship to Flat 402, Sunrise Apartments, MG Road, Bengaluru 560001. Thanks"
    f = found(analyzer, t)
    assert ("IN_ADDRESS", "Flat 402, Sunrise Apartments, MG Road, Bengaluru 560001") in f
    assert ("IN_PIN_CODE", "560001") in f


def test_indian_address_with_label_and_state(analyzer):
    t = "Address: 12/3, 4th Cross, Koramangala, Bengaluru - 560034, Karnataka"
    assert any(ty == "IN_ADDRESS" and v.startswith("12/3") and "560034" in v for ty, v in found(analyzer, t))


def test_indian_street_only(analyzer):
    assert has(analyzer, "Customer Daniel Costa at 42 Residency Road reported a login", "IN_ADDRESS", "42 Residency Road")


@pytest.mark.parametrize("text", [
    "Order 5601234567 ref 123456 amount 1,234,567.89 on 2024-01-15 build 20240115 version 3.11.2",
    "cards 5500 0000 0000 0004, 3782 822463 10005, 6011 1111 1111 1117",
    "Hi John, please call me back when you can, thanks",
    "We opened 3 new offices, 2 in Chennai, 1 in Pune",
])
def test_address_false_positives(analyzer, text):
    assert not types(analyzer, text) & {"IN_ADDRESS", "US_ADDRESS"}


# ---- US SSN -------------------------------------------------------------------------------------------
@pytest.mark.parametrize("v", ["123-45-6789", "123 45 6789", "123.45.6789"])
def test_ssn_with_context(analyzer, v):
    assert has(analyzer, f"Employee SSN {v} on file", "US_SSN", v)


def test_ssn_hyphenated_without_context_and_bare_digits(analyzer):
    assert has(analyzer, "Record 123-45-6789 updated", "US_SSN", "123-45-6789")
    assert has(analyzer, "social security number 123456789", "US_SSN", "123456789")
    assert not has(analyzer, "Reference 123456789 closed", "US_SSN")
    assert not has(analyzer, "Record 123 45 6789 updated", "US_SSN")   # space-separated needs context


@pytest.mark.parametrize("v", ["000-12-3456", "666-12-3456", "987-65-4321", "123-00-4567", "123-45-0000", "078-05-1120"])
def test_ssn_invalid_structure_rejected(analyzer, v):
    assert not has(analyzer, f"SSN {v}", "US_SSN")


# ---- credit / debit cards -----------------------------------------------------------------------------
@pytest.mark.parametrize("v", [
    "4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111111",       # Visa
    "5500 0000 0000 0004", "2221 0000 0000 0009",                           # Mastercard
    "3782 822463 10005", "3714-496353-98431",                               # Amex 4-6-5
    "6011 1111 1111 1117", "3530 1113 3330 0000", "6011 0009 9013 9424",
])
def test_card_variants(analyzer, v):
    assert has(analyzer, f"Charge card {v} today", "CREDIT_CARD", v), found(analyzer, v)


@pytest.mark.parametrize("v", ["4111 1111 1111 1112", "1234 5678 9012 3456", "0000 0000 0000 0000", "4111 1111 1111"])
def test_card_invalid_rejected(analyzer, v):
    assert not has(analyzer, f"Charge card {v} today", "CREDIT_CARD")


# ---- US addresses + ZIP -------------------------------------------------------------------------------
def test_us_addresses(analyzer):
    f = found(analyzer, "Send to 1600 Pennsylvania Ave NW, Washington, DC 20500 please")
    assert ("US_ADDRESS", "1600 Pennsylvania Ave NW, Washington, DC 20500") in f
    assert ("US_ZIP_CODE", "20500") in f
    assert has(analyzer, "Office: 350 Fifth Avenue, Suite 4100, New York, NY 10118.", "US_ADDRESS")
    assert has(analyzer, "742 Evergreen Terrace, Springfield, IL 62704", "US_ADDRESS")


def test_us_street_without_city(analyzer):
    assert has(analyzer, "He lives at 221 Baker Street", "US_ADDRESS", "221 Baker Street")


@pytest.mark.parametrize("text,val", [("zip code 94105", "94105"), ("San Francisco, CA 94105", "94105"), ("ZIP: 10001-1234", "10001-1234")])
def test_zip_with_context(analyzer, text, val):
    assert has(analyzer, text, "US_ZIP_CODE", val), found(analyzer, text)


@pytest.mark.parametrize("text", ["Order number 12345", "Room 90210 reserved", "zip code 00000", "Qty 10001-1234"])
def test_zip_false_positives(analyzer, text):
    assert "US_ZIP_CODE" not in types(analyzer, text)


# ---- existing categories keep working + noise suppression ---------------------------------------------
def test_existing_categories_still_detected(analyzer):
    t = "Contact Anita Rao at anita.rao@example.com from 10.24.8.17"
    assert {"PERSON", "EMAIL_ADDRESS", "IP_ADDRESS"} <= types(analyzer, t)


def test_bare_numbers_are_not_dates_or_nhs(analyzer):
    t = "Ref 560025 and 123456 and 9876543210 and 5601234567"
    assert not types(analyzer, t) & {"DATE_TIME", "UK_NHS", "PHONE_NUMBER", "IN_PIN_CODE"}


def test_results_never_contain_values(analyzer):
    r = analyzer.analyze("SSN 123-45-6789")
    assert r and all(set(x) == {"type", "start", "end", "score"} for x in r)


def test_mixed_document_all_categories(analyzer):
    t = (f"Verify KYC: Anita Rao, Aadhaar {VALID_AADHAAR[:4]} {VALID_AADHAAR[4:8]} {VALID_AADHAAR[8:]}, "
         "mobile +91 98765 43210, Flat 402, Sunrise Apartments, MG Road, Bengaluru 560001. "
         "US: SSN 123-45-6789, card 4111 1111 1111 1111, 350 Fifth Avenue, New York, NY 10118.")
    assert {"IN_AADHAAR", "PHONE_NUMBER", "IN_ADDRESS", "IN_PIN_CODE", "US_SSN", "CREDIT_CARD", "US_ADDRESS",
            "US_ZIP_CODE", "PERSON"} <= types(analyzer, t)


def test_address_stops_at_sentence_end_and_never_swallows_other_ids(analyzer):
    t = ("KYC: Flat 402, Sunrise Apartments, MG Road, Bengaluru 560001. US: SSN 123-45-6789, "
         "card 4111 1111 1111 1111, mobile +91 98765 43210, a@b.com")
    f = found(analyzer, t)
    assert ("IN_ADDRESS", "Flat 402, Sunrise Apartments, MG Road, Bengaluru 560001") in f
    assert ("US_SSN", "123-45-6789") in f and ("CREDIT_CARD", "4111 1111 1111 1111") in f
    for ty, v in f:
        if ty in ("IN_ADDRESS", "US_ADDRESS"):
            assert "123-45-6789" not in v and "4111" not in v and "98765" not in v


def test_ssn_like_text_is_not_a_house_number(analyzer):
    assert not types(analyzer, "Employee SSN 123-45-6789, Bengaluru") & {"IN_ADDRESS"}
