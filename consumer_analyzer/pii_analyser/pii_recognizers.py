"""Indian + US PII recognizers for Presidio, plus the post-processing that keeps false positives low.

Entity types produced (these are the names used in policies, the dashboard and the anonymizer):

  PHONE_NUMBER   Indian mobile / landline numbers (existing type, so existing phone rules apply)
  IN_AADHAAR     12-digit Aadhaar, Verhoeff checksum validated
  IN_PIN_CODE    6-digit Indian PIN code, only with PIN/city/state context and a valid postal circle
  IN_ADDRESS     Indian postal address (house + street/locality + city/state/PIN)
  US_SSN         US Social Security Number (existing type), structural rules, context for bare digits
  CREDIT_CARD    credit/debit cards (existing type): brand prefix + length + Luhn
  US_ZIP_CODE    5 / 9 digit ZIP, only with state or ZIP context
  US_ADDRESS     US street address, optionally with unit, city, state and ZIP

Design rules for precision:
  * A checksum failure is never reported (Aadhaar, cards).
  * Bare digit runs (no separators) are only reported with a nearby context word.
  * Bare 5/6 digit numbers are never postal codes without PIN/ZIP/state/city context.
  * The recognizers only look at text; nothing here logs or stores matched values.
"""
import re
from typing import Iterable, Optional

from presidio_analyzer import EntityRecognizer, RecognizerResult

# =====================================================================================================
# Checksums
# =====================================================================================================
_VD = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VP = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VINV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    """True when the digit string (check digit included) passes the Verhoeff checksum."""
    if not number.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VD[c][_VP[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(payload: str) -> str:
    """Check digit to append to `payload` (used by tests to build valid Aadhaar numbers)."""
    c = 0
    for i, ch in enumerate(reversed(payload)):
        c = _VD[c][_VP[(i + 1) % 8][int(ch)]]
    return str(_VINV[c])


def luhn_valid(number: str) -> bool:
    if not number.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# =====================================================================================================
# Shared helpers
# =====================================================================================================
def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _before(text: str, start: int, n: int = 40) -> str:
    return text[max(0, start - n):start].lower()


def _after(text: str, end: int, n: int = 20) -> str:
    return text[end:end + n].lower()


def _same_digit_run(d: str) -> bool:
    return len(set(d)) <= 2 and len(d) >= 8  # 9999999999, 0000000000, 1212121212 ...


class _Recognizer(EntityRecognizer):
    """Minimal EntityRecognizer: subclasses implement `_find(text)` -> (entity, start, end, score)."""

    ENTITIES: tuple = ()

    def __init__(self, name: str):
        super().__init__(supported_entities=list(self.ENTITIES), name=name, supported_language="en")

    def load(self) -> None:  # nothing to load
        pass

    def analyze(self, text, entities, nlp_artifacts=None):
        wanted = set(entities or self.ENTITIES)
        out = []
        for entity, start, end, score in self._find(text):
            if entity in wanted and score > 0:
                out.append(RecognizerResult(
                    entity_type=entity, start=start, end=end, score=round(float(score), 2),
                    recognition_metadata={
                        RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                    },
                ))
        return out

    def _find(self, text: str) -> Iterable[tuple]:
        raise NotImplementedError


# =====================================================================================================
# Indian phone numbers
# =====================================================================================================
_PHONE_CTX = re.compile(
    r"\b(?:phone|mobile|mob|cell|call|contact|whatsapp|tel|telephone|ph|dial|reach|sms|helpline)\b")
_SEP = r"[ .\-]?"
_MOBILE_BODY = (
    rf"(?:[6-9]\d{{4}}{_SEP}\d{{5}}|[6-9]\d{{2}}{_SEP}\d{{3}}{_SEP}\d{{4}}|[6-9]\d{_SEP}\d{{4}}{_SEP}\d{{4}})"
)
_CC = r"(?:(?:\+|00)[ ]?91[ .\-]?\(?0?\)?[ .\-]?|\(\+?91\)[ .\-]?|91[ \-])"  # country-code prefixes
_NOT_DIGIT_BEFORE = r"(?<![\w+])(?<!\d[ .\-])"
_NOT_DIGIT_AFTER = r"(?![ .\-]?\d)"

_IN_MOBILE_CC = re.compile(rf"{_NOT_DIGIT_BEFORE}(?:{_CC}){_MOBILE_BODY}{_NOT_DIGIT_AFTER}")
_IN_MOBILE_TRUNK = re.compile(rf"{_NOT_DIGIT_BEFORE}0[ \-]?{_MOBILE_BODY}{_NOT_DIGIT_AFTER}")
_IN_MOBILE_BARE = re.compile(rf"{_NOT_DIGIT_BEFORE}{_MOBILE_BODY}{_NOT_DIGIT_AFTER}")
_IN_MOBILE_91_PLAIN = re.compile(rf"{_NOT_DIGIT_BEFORE}91[6-9]\d{{9}}{_NOT_DIGIT_AFTER}")  # 919876543210
_IN_LANDLINE = re.compile(
    rf"{_NOT_DIGIT_BEFORE}(?P<pre>(?:(?:\+|00)[ ]?91[ .\-]?\(?0?\)?[ .\-]?)|0)\(?(?P<std>[1-9]\d{{1,3}})\)?"
    rf"(?P<sep>[ .\-]?)(?P<sub>\d{{6,8}}|\d{{3,4}}[ .\-]\d{{3,4}}){_NOT_DIGIT_AFTER}"
)


class IndianPhoneRecognizer(_Recognizer):
    ENTITIES = ("PHONE_NUMBER",)

    def __init__(self):
        super().__init__("IndianPhoneRecognizer")

    def _find(self, text):
        seen = {}

        def add(m, score):
            s, e = m.span()
            if score > seen.get((s, e), 0):
                seen[(s, e)] = score

        for m in _IN_MOBILE_CC.finditer(text):
            d = _digits(m.group())
            if not _same_digit_run(d[-10:]):
                add(m, 0.9)
        for m in _IN_MOBILE_91_PLAIN.finditer(text):
            ctx = _PHONE_CTX.search(_before(text, m.start(), 30))
            add(m, 0.85 if ctx else 0.0)
        for m in _IN_MOBILE_TRUNK.finditer(text):
            d = _digits(m.group())
            if not _same_digit_run(d[1:]):
                add(m, 0.8)
        for m in _IN_MOBILE_BARE.finditer(text):
            d = _digits(m.group())
            if _same_digit_run(d):
                continue
            ctx = _PHONE_CTX.search(_before(text, m.start(), 30))
            grouped = bool(re.search(r"[ .\-]", m.group()))
            add(m, 0.85 if ctx else (0.65 if grouped else 0.4))
        for m in _IN_LANDLINE.finditer(text):
            std, sub = m.group("std"), _digits(m.group("sub"))
            if len(std) + len(sub) != 10:
                continue
            has_cc = m.group("pre") != "0"
            has_sep = bool(re.search(r"[ .\-()]", m.group()[len(m.group("pre")):]))
            ctx = _PHONE_CTX.search(_before(text, m.start(), 30))
            add(m, 0.88 if has_cc else (0.78 if has_sep else (0.85 if ctx else 0.45)))
        for (s, e), score in seen.items():
            yield "PHONE_NUMBER", s, e, score


# =====================================================================================================
# Aadhaar
# =====================================================================================================
_AADHAAR_CTX = re.compile(r"\b(?:aadhaar|aadhar|adhaar|uidai|uid|aadhaar\s+(?:card|number|no))\b")
_AADHAAR = re.compile(
    r"(?<!\d)(?<!\d[ .\-])(?P<a>[2-9]\d{3})(?P<s>[ .\-]?)(?P<b>\d{4})(?P=s)(?P<c>\d{4})(?![ .\-]?\d)"
)


class AadhaarRecognizer(_Recognizer):
    ENTITIES = ("IN_AADHAAR",)

    def __init__(self):
        super().__init__("AadhaarRecognizer")

    def _find(self, text):
        for m in _AADHAAR.finditer(text):
            d = _digits(m.group())
            if len(set(d)) == 1 or not verhoeff_valid(d):  # checksum failure => not an Aadhaar number
                continue
            ctx = _AADHAAR_CTX.search(_before(text, m.start(), 40)) or _AADHAAR_CTX.search(_after(text, m.end(), 15))
            grouped = bool(m.group("s"))
            if ctx:
                score = 0.95
            else:
                score = 0.85 if grouped else 0.4  # bare 12 digits need a context word
            yield "IN_AADHAAR", m.start(), m.end(), score


# =====================================================================================================
# Indian geography (used by PIN code + address recognizers)
# =====================================================================================================
_IN_STATES = [
    "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh", "Goa", "Gujarat", "Haryana",
    "Himachal Pradesh", "Jharkhand", "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur",
    "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Orissa", "Punjab", "Rajasthan", "Sikkim", "Tamil Nadu",
    "Tamilnadu", "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand", "West Bengal", "Delhi", "New Delhi",
    "Jammu and Kashmir", "Jammu & Kashmir", "Ladakh", "Chandigarh", "Puducherry", "Pondicherry",
    "Andaman and Nicobar", "Lakshadweep", "Dadra and Nagar Haveli", "Daman and Diu",
]
_IN_CITIES = [
    "Mumbai", "Bombay", "Navi Mumbai", "Thane", "Pune", "Nagpur", "Nashik", "Aurangabad", "Solapur", "Kolhapur",
    "Bengaluru", "Bangalore", "Mysuru", "Mysore", "Hubli", "Mangaluru", "Mangalore", "Belagavi", "Belgaum",
    "Kalaburagi", "Gulbarga", "Chennai", "Madras", "Coimbatore", "Madurai", "Tiruchirappalli", "Trichy",
    "Salem", "Tirunelveli", "Erode", "Vellore", "Hyderabad", "Secunderabad", "Warangal", "Visakhapatnam",
    "Vizag", "Vijayawada", "Guntur", "Nellore", "Tirupati", "Kochi", "Cochin", "Thiruvananthapuram",
    "Trivandrum", "Kozhikode", "Calicut", "Thrissur", "Kolkata", "Calcutta", "Howrah", "Siliguri", "Durgapur",
    "Gurugram", "Gurgaon", "Noida", "Ghaziabad", "Faridabad", "Lucknow", "Kanpur", "Varanasi", "Agra",
    "Meerut", "Prayagraj", "Allahabad", "Bareilly", "Moradabad", "Jaipur", "Jodhpur", "Udaipur", "Kota",
    "Ajmer", "Bikaner", "Ahmedabad", "Surat", "Vadodara", "Baroda", "Rajkot", "Gandhinagar", "Bhopal",
    "Indore", "Gwalior", "Jabalpur", "Raipur", "Bhilai", "Patna", "Ranchi", "Jamshedpur", "Dhanbad",
    "Bhubaneswar", "Cuttack", "Guwahati", "Dehradun", "Amritsar", "Ludhiana", "Jalandhar", "Srinagar",
    "Jammu", "Shimla", "Panaji", "Imphal", "Shillong", "Gangtok", "Agartala", "Aizawl",
]
_GEO = sorted(set(_IN_STATES + _IN_CITIES), key=len, reverse=True)
_GEO_RE = re.compile(r"\b(?:" + "|".join(re.escape(g) for g in _GEO) + r")\b", re.I)
_PIN_LEAD_RE = re.compile(r"(?:\b(?:" + "|".join(re.escape(g) for g in _GEO) + r")|\bindia)[\s,.\-:]*(?:pin(?:\s?code)?[\s:.\-]*)?$", re.I)
_PIN_KEY_RE = re.compile(r"\b(?:pin(?:\s?code)?|postal\s?code|post\s?code|pincode)\b[\s:.#\-]*$", re.I)
# first two digits of valid Indian postal circles (11-85 plus 90-99 for army post offices)
_PIN_PREFIX_OK = {int(p) for p in (
    list(range(11, 29)) + list(range(30, 35)) + list(range(36, 50)) + list(range(50, 54)) + list(range(56, 65)) +
    list(range(67, 86)) + list(range(90, 100)))}
_PIN = re.compile(r"(?<!\d)(?<!\d[ \-.])(?P<pin>[1-9]\d{2}[ ]?\d{3})(?![ \-.]?\d)")


def _pin_context_score(text: str, start: int, end: int) -> float:
    d = _digits(text[start:end])
    if len(d) != 6 or int(d[:2]) not in _PIN_PREFIX_OK or len(set(d)) == 1:
        return 0.0
    before = text[max(0, start - 60):start]
    if _PIN_KEY_RE.search(before):
        return 0.92
    if _PIN_LEAD_RE.search(before):
        return 0.88
    if re.match(r"\s*,?\s*india\b", text[end:end + 12], re.I):
        return 0.8
    return 0.0


class IndianPinCodeRecognizer(_Recognizer):
    ENTITIES = ("IN_PIN_CODE",)

    def __init__(self):
        super().__init__("IndianPinCodeRecognizer")

    def _find(self, text):
        for m in _PIN.finditer(text):
            s = _pin_context_score(text, m.start("pin"), m.end("pin"))
            if s:
                yield "IN_PIN_CODE", m.start("pin"), m.end("pin"), s


# =====================================================================================================
# Addresses
# =====================================================================================================
_IN_STREET_WORDS = (
    r"road|rd|street|st|lane|ln|marg|nagar|layout|colony|cross|main|sector|phase|society|apartments?|enclave|"
    r"chowk|bazaar|bazar|puram|vihar|extension|stage|block|gali|path|salai|park|tower|towers|complex|residency|"
    r"heights|garden|gardens|mahal|chawl|wadi|bagh|ganj|mohalla|village|taluk|tehsil|district|dist|"
    r"near|opp|opposite|behind|landmark|floor|wing|plaza|market|circle|junction|highway|bypass"
)
_IN_LOCAL_WORDS = r"nagar|layout|colony|marg|sector|phase|enclave|chowk|puram|vihar|extension|stage|gali|salai|mohalla|wadi|bagh|ganj"
_IN_STREET_RE = re.compile(rf"\b(?:{_IN_STREET_WORDS})\b\.?", re.I)
_IN_HOUSE_RE = re.compile(
    r"(?:\b(?:flat|plot|house|h\.?\s?no|door|d\.?\s?no|apt|apartment|villa|shop|room|unit|no)\b\.?[\s:#\-]*[\w/\-]+|#\s?\d[\w/\-]*|"
    r"(?<![\w/\-])\d{1,5}[A-Za-z]?(?:[/\-]\d{1,4}[A-Za-z]?)*(?![\w/\-]))", re.I)
_CAP_WORD = re.compile(r"^[A-Z][\w.'&()\-]*$")
_PLAUSIBLE_NAMEWORD = re.compile(r"^[A-Z][\w.'&()\-]*$|^(?i:of|the|and|&|cross|main|[0-9]+(?:st|nd|rd|th))$")
_GENERIC_CITY_STOP = {"Please", "Thanks", "Regards", "Hello", "Dear", "Hi", "Thank", "Ship", "Deliver"}


def _segments(text: str):
    """Comma / newline / semicolon separated segments as (start, end) pairs (whitespace trimmed)."""
    pos = 0
    # a full stop that ends a sentence also ends a segment ("... Bengaluru 560001. US: SSN ...")
    for part in re.split(r"([,\n;]|(?<=\d)\.(?=\s)|(?<=[A-Za-z]{3})\.(?=\s+[A-Z]))", text):
        if part in {",", "\n", ";", "."}:
            pos += 1
            continue
        s = pos + (len(part) - len(part.lstrip()))
        e = pos + len(part.rstrip())
        if e > s:
            yield s, e
        pos += len(part)


_PURE_HOUSE = re.compile(r"^(?:(?:flat|plot|house|h\.?\s?no|door|d\.?\s?no|apt|apartment|villa|shop|room|unit|no)\b\.?[\s:#\-]*)?"
                         r"#?\d{1,5}[A-Za-z]?(?:[/\-]\d{1,4}[A-Za-z]?)?$", re.I)
_LEAD_NUM_HOUSE = re.compile(r"^#?\d{1,5}[A-Za-z]?(?:[/\-]\d{1,4}[A-Za-z]?)?\s+[A-Za-z]")
_TRAIL_NUM_HOUSE = re.compile(r"(?:^|\s)#?\d{1,5}[A-Za-z]?(?:[/\-]\d{1,4}[A-Za-z]?)?$")
_HOUSE_WORD = re.compile(r"\b(?:flat|plot|house|h\.?\s?no|door|d\.?\s?no|apt|apartment|villa|shop|room|unit)\b\.?[\s:#\-]*[\w/\-]*\d", re.I)


def _seg_flags(text: str, s: int, e: int) -> dict:
    seg = text[s:e]
    words = seg.split()
    noisy = len(re.findall(r"\d{4,}", seg)) >= 2 or bool(re.search(r"\d{7,}", seg)) or len(words) > 9
    if noisy or not words:  # card lists, ids, long prose
        return {"house": False, "street": False, "geo": False, "pin": False, "name": False}
    house = bool(_PURE_HOUSE.match(seg.strip()) or _LEAD_NUM_HOUSE.match(seg.strip()) or _HOUSE_WORD.search(seg)
                 or (len(words) <= 3 and _TRAIL_NUM_HOUSE.search(seg.strip())))
    pin = False
    for m in re.finditer(r"(?<!\d)[1-9]\d{2}\s?\d{3}(?!\d)", seg):
        if _pin_context_score(text, s + m.start(), s + m.end()):
            pin = True
    return {
        "house": house,
        "street": bool(_IN_STREET_RE.search(seg)),
        "geo": bool(_GEO_RE.search(seg)) or bool(re.search(r"\bindia\b", seg, re.I)),
        "pin": pin,
        "name": len(words) <= 5 and all(_PLAUSIBLE_NAMEWORD.match(w) for w in words)
                and not any(w in _GENERIC_CITY_STOP for w in words),
    }


def _trim_start(seg: str, flags: dict, first: bool) -> int:
    """Offset inside the first segment where the address starts (drops leading prose such as 'please ship to')."""
    if not first:
        return 0
    m = _IN_HOUSE_RE.search(seg)
    if m and flags["house"]:
        # earliest house marker that is not a bare number inside prose
        return m.start()
    words = list(re.finditer(r"\S+", seg))
    i = len(words)
    while i > 0 and _PLAUSIBLE_NAMEWORD.match(words[i - 1].group()) and words[i - 1].group() not in _GENERIC_CITY_STOP:
        i -= 1
    return words[i].start() if i < len(words) else 0


def find_indian_addresses(text: str):
    """Yield (start, end, score) for Indian postal addresses."""
    segs = list(_segments(text))
    flags = [_seg_flags(text, s, e) for s, e in segs]
    i = 0
    while i < len(segs):
        f = flags[i]
        addresslike = f["house"] or f["street"] or f["geo"] or f["pin"] or f["name"]
        if not addresslike:
            i += 1
            continue
        j = i
        while j + 1 < len(segs) and (j - i) < 7:
            nf = flags[j + 1]
            if nf["house"] or nf["street"] or nf["geo"] or nf["pin"] or nf["name"]:
                j += 1
            else:
                break
        while j > i and not any(flags[j][k] for k in ("house", "street", "geo", "pin")):
            j -= 1  # a trailing segment with no address evidence (e.g. a following sentence) is not part of it
        window = flags[i:j + 1]
        has = {k: any(w[k] for w in window) for k in ("house", "street", "geo", "pin")}
        evidence = sum(has.values())
        names = sum(1 for w in window if w["name"] and not (w["geo"] or w["pin"] or w["house"] or w["street"]))
        ok = len(window) >= 2 and (
            (has["pin"] and (has["house"] or has["street"])) or
            (has["house"] and has["street"] and has["geo"]) or
            (has["pin"] and has["geo"] and names >= 1)
        )
        if ok:
            first_s, first_e = segs[i]
            start = first_s + _trim_start(text[first_s:first_e], flags[i], True)
            last_s, last_e = segs[j]
            end = last_e
            if has["pin"]:
                pm = None
                for pm in re.finditer(r"(?<!\d)[1-9]\d{2}\s?\d{3}(?!\d)", text[last_s:last_e]):
                    pass
                if pm is not None:
                    end = last_s + pm.end()
            else:  # cut trailing prose after the last geo/street word
                tail = text[last_s:last_e]
                keep = 0
                for m in list(_GEO_RE.finditer(tail)) + list(_IN_STREET_RE.finditer(tail)):
                    keep = max(keep, m.end())
                end = last_s + keep if keep else last_e
            if end - start >= 8:
                yield start, end, (0.9 if has["pin"] else 0.78)
        i = j + 1


# --- single-line street addresses ("42 Residency Road", "1600 Pennsylvania Ave NW") --------------------
_US_ONLY_SUFFIX = r"Avenue|Ave|Boulevard|Blvd|Drive|Dr|Court|Ct|Way|Place|Pl|Circle|Cir|Terrace|Ter|Highway|Hwy|Parkway|Pkwy|Trail|Square|Sq|Plaza"
_AMBIG_SUFFIX = r"Street|St|Road|Rd|Lane|Ln"
_IN_ONLY_SUFFIX = r"Marg|Nagar|Layout|Colony|Cross|Salai|Path|Gali|Chowk|Vihar|Enclave|Puram"
_STREET_RE = re.compile(
    rf"(?<![\w/\-])(?P<num>\d{{1,6}}[A-Za-z]?(?:[/\-]\d{{1,4}})?)\s+(?P<dir>(?:[NSEW]|North|South|East|West)\.?\s+)?"
    rf"(?P<name>(?:[A-Z0-9][\w.'\-]*\s+){{0,4}}?[A-Z0-9][\w.'\-]*)\s+"
    rf"(?P<suffix>(?:{_US_ONLY_SUFFIX}|{_AMBIG_SUFFIX}|{_IN_ONLY_SUFFIX})\b\.?)"
    rf"(?:\s+(?P<post>NW|NE|SW|SE|N|S|E|W)\b\.?)?"
)
_US_STATES = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California", "CO": "Colorado",
    "CT": "Connecticut", "DE": "Delaware", "DC": "District of Columbia", "FL": "Florida", "GA": "Georgia",
    "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa", "KS": "Kansas",
    "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland", "MA": "Massachusetts",
    "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri", "MT": "Montana",
    "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico",
    "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma",
    "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina", "SD": "South Dakota",
    "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont", "VA": "Virginia", "WA": "Washington",
    "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming", "PR": "Puerto Rico",
}
_STATE_ALT = "|".join(sorted(list(_US_STATES) + list(_US_STATES.values()), key=len, reverse=True))
_US_TAIL = re.compile(
    rf"^(?:\s*,?\s*(?:Apt|Apartment|Suite|Ste|Unit|Floor|Fl|Bldg|Building|#)\.?\s*[\w\-]+)?"
    rf"(?:\s*,\s*|\s+)(?:(?P<city>[A-Z][A-Za-z.'\-]+(?:\s[A-Z][A-Za-z.'\-]+){{0,3}})\s*,?\s+)?"
    rf"(?P<state>{_STATE_ALT})\.?,?\s+(?P<zip>\d{{5}}(?:-\d{{4}})?)(?!\d)"
)
_US_UNIT = re.compile(r"^\s*,?\s*(?:Apt|Apartment|Suite|Ste|Unit|Floor|Fl|Bldg|Building|#)\.?\s*[\w\-]+")


def find_street_addresses(text: str):
    """Yield (entity, start, end, score) for single-line street addresses (US_ADDRESS / IN_ADDRESS)."""
    for m in _STREET_RE.finditer(text):
        suffix = m.group("suffix").rstrip(".")
        start, end = m.start(), m.end()
        tail_text = text[end:end + 90]
        us = _US_TAIL.match(tail_text)
        if us:
            yield "US_ADDRESS", start, end + us.end(), 0.92
            continue
        # Indian tail: ", Locality, City 560001" / ", City" -> let the multi-segment finder own it (it extends)
        in_tail = re.match(r"^\s*,\s*[A-Za-z0-9 .'&\-]{2,40}(?:,\s*[A-Za-z0-9 .'&\-]{2,40}){0,3}", tail_text)
        geo_after = bool(in_tail and _GEO_RE.search(in_tail.group()))
        in_marker = suffix in _IN_ONLY_SUFFIX.split("|") or geo_after
        unit = _US_UNIT.match(tail_text)
        if unit:
            end += unit.end()
        if in_marker:
            yield "IN_ADDRESS", start, end, 0.8
        elif suffix in _US_ONLY_SUFFIX.split("|") or suffix in ("Street", "St"):
            yield "US_ADDRESS", start, end, 0.68
        else:  # Road / Rd / Lane / Ln with no regional marker
            yield "IN_ADDRESS", start, end, 0.65


class AddressRecognizer(_Recognizer):
    ENTITIES = ("IN_ADDRESS", "US_ADDRESS")

    def __init__(self):
        super().__init__("IndiaUsAddressRecognizer")

    def _find(self, text):
        found = []
        for s, e, score in find_indian_addresses(text):
            found.append(["IN_ADDRESS", s, e, score])
        for entity, s, e, score in find_street_addresses(text):
            overlapped = [f for f in found if f[0] == "IN_ADDRESS" and not (e <= f[1] or s >= f[2])]
            if entity == "IN_ADDRESS" and overlapped:
                for f in overlapped:  # the multi-segment span already covers it; widen if needed
                    f[1], f[2] = min(f[1], s), max(f[2], e)
                    f[3] = max(f[3], score)
                continue
            found.append([entity, s, e, score])
        for entity, s, e, score in found:
            yield entity, s, e, score


# =====================================================================================================
# US SSN
# =====================================================================================================
_SSN_CTX = re.compile(r"(?:\bssn\b|\bss\s?#|\bss\s?no\b|social\s+sec(?:urity)?(?:\s+(?:number|no\.?|#))?)")
_SSN_FORMATTED = re.compile(r"(?<![\d\-])(?P<a>\d{3})(?P<s>[\- .])(?P<g>\d{2})(?P=s)(?P<n>\d{4})(?![\d\-])(?!\.\d)")
_SSN_BARE = re.compile(r"(?<![\d\-.])(?P<a>\d{3})(?P<g>\d{2})(?P<n>\d{4})(?![\d\-])(?!\.\d)")
_SSN_NEVER_ISSUED = {"078051120", "219099999", "457555462"}


def _ssn_structure_ok(a: str, g: str, n: str) -> bool:
    return a not in ("000", "666") and not a.startswith("9") and g != "00" and n != "0000" and (a + g + n) not in _SSN_NEVER_ISSUED


class StrictUsSsnRecognizer(_Recognizer):
    ENTITIES = ("US_SSN",)

    def __init__(self):
        super().__init__("StrictUsSsnRecognizer")

    def _find(self, text):
        for m in _SSN_FORMATTED.finditer(text):
            if not _ssn_structure_ok(m.group("a"), m.group("g"), m.group("n")):
                continue
            ctx = _SSN_CTX.search(_before(text, m.start(), 30))
            if ctx:
                score = 0.95
            elif m.group("s") == "-":
                score = 0.8
            else:
                score = 0.4  # space / dot separated without context is too ambiguous
            yield "US_SSN", m.start(), m.end(), score
        for m in _SSN_BARE.finditer(text):
            if not _ssn_structure_ok(m.group("a"), m.group("g"), m.group("n")):
                continue
            if _SSN_CTX.search(_before(text, m.start(), 30)):
                yield "US_SSN", m.start(), m.end(), 0.85


# =====================================================================================================
# Credit / debit cards
# =====================================================================================================
def _card_brand_ok(d: str) -> bool:
    n = len(d)
    p2, p3, p4, p6 = int(d[:2]), int(d[:3]), int(d[:4]), int(d[:6])
    if d[0] == "4":  # Visa
        return n in (13, 16, 19)
    if 51 <= p2 <= 55 or 2221 <= p4 <= 2720:  # Mastercard
        return n == 16
    if p2 in (34, 37):  # American Express
        return n == 15
    if d.startswith("6011") or p2 == 65 or 644 <= p3 <= 649 or 622126 <= p6 <= 622925:  # Discover
        return n in (16, 17, 18, 19)
    if 300 <= p3 <= 305 or p2 in (36, 38, 39):  # Diners Club
        return n in (14, 15, 16, 17, 18, 19)
    if 3528 <= p4 <= 3589:  # JCB
        return n in (16, 17, 18, 19)
    if p2 == 62:  # UnionPay
        return n in (16, 17, 18, 19)
    if p2 in (60, 81, 82) or p3 == 508:  # RuPay (Indian debit/credit)
        return n == 16
    if p2 in (50, 56, 57, 58, 63, 67):  # Maestro
        return 12 <= n <= 19 and n >= 13
    return False


_CARD_CTX = re.compile(r"\b(?:card|visa|mastercard|amex|debit|credit|cc|pan|cvv|payment|ending)\b")
_CARD = re.compile(
    r"(?<![\d\-])(?<!\d[ .])(?:"
    r"(?P<amex>3[47]\d{2}(?P<a>[ .\-]?)\d{6}(?P=a)\d{5})|"
    r"(?P<diners>3[0689]\d{2}(?P<d>[ .\-]?)\d{6}(?P=d)\d{4})|"
    r"(?P<std>\d{4}(?P<s>[ .\-]?)\d{4}(?P=s)\d{4}(?P=s)\d{4}(?:(?P=s)?\d{1,3})?)|"
    r"(?P<v13>4\d{3}(?P<t>[ .\-]?)\d{3}(?P=t)\d{3}(?P=t)\d{3})"
    r")(?![\d\-])(?![ .]\d)"
)


class StrictCardRecognizer(_Recognizer):
    ENTITIES = ("CREDIT_CARD",)

    def __init__(self):
        super().__init__("StrictCardRecognizer")

    def _find(self, text):
        for m in _CARD.finditer(text):
            d = _digits(m.group())
            if len(set(d)) == 1 or not _card_brand_ok(d) or not luhn_valid(d):
                continue
            grouped = bool(re.search(r"[ .\-]", m.group()))
            ctx = _CARD_CTX.search(_before(text, m.start(), 30))
            score = 0.95 if ctx else (0.9 if grouped else 0.85)
            yield "CREDIT_CARD", m.start(), m.end(), score


# =====================================================================================================
# US ZIP
# =====================================================================================================
_ZIP_KEY_RE = re.compile(r"\b(?:zip(?:\s?code)?|postal\s?code|post\s?code|zipcode)\b[\s:.#\-]*$", re.I)
_ZIP_STATE_RE = re.compile(rf"(?:\b(?:{_STATE_ALT})\.?,?[ ])$")
_ZIP = re.compile(r"(?<![\d\-.])(?P<z>\d{5})(?P<p>-\d{4})?(?![\d\-])(?!\.\d)")


class UsZipRecognizer(_Recognizer):
    ENTITIES = ("US_ZIP_CODE",)

    def __init__(self):
        super().__init__("UsZipRecognizer")

    def _find(self, text):
        for m in _ZIP.finditer(text):
            z = m.group("z")
            if z == "00000" or z.startswith("000"):
                continue
            before = text[max(0, m.start() - 40):m.start()]
            if _ZIP_KEY_RE.search(before):
                score = 0.92
            elif _ZIP_STATE_RE.search(before):
                score = 0.9
            elif m.group("p"):
                score = 0.4  # ZIP+4 alone is distinctive but still ambiguous
            else:
                continue
            yield "US_ZIP_CODE", m.start(), m.end(), score


# =====================================================================================================
# Registry wiring + post-processing
# =====================================================================================================
CUSTOM_RECOGNIZER_CLASSES = (
    IndianPhoneRecognizer, AadhaarRecognizer, IndianPinCodeRecognizer, AddressRecognizer,
    StrictUsSsnRecognizer, StrictCardRecognizer, UsZipRecognizer,
)
REPLACED_PRESIDIO_RECOGNIZERS = ("CreditCardRecognizer", "UsSsnRecognizer")  # stricter versions above replace these

#: Every category the system advertises (used by the PII Detection page and the Policy Engine suggestions).
SUPPORTED_CATEGORIES = [
    {"entity_type": "PERSON", "label": "Person name", "region": "Global", "detector": "NER model (spaCy)"},
    {"entity_type": "EMAIL_ADDRESS", "label": "Email address", "region": "Global", "detector": "Pattern"},
    {"entity_type": "PHONE_NUMBER", "label": "Phone number (India + international)", "region": "IN / Global", "detector": "Pattern + phone-number library"},
    {"entity_type": "IN_AADHAAR", "label": "Aadhaar number", "region": "India", "detector": "Pattern + Verhoeff checksum"},
    {"entity_type": "IN_PIN_CODE", "label": "PIN code", "region": "India", "detector": "Pattern + postal-circle check + context"},
    {"entity_type": "IN_ADDRESS", "label": "Indian address", "region": "India", "detector": "Rules (house, street, city/state, PIN)"},
    {"entity_type": "US_SSN", "label": "Social Security Number", "region": "US", "detector": "Pattern + SSA rules + context"},
    {"entity_type": "CREDIT_CARD", "label": "Credit / debit card", "region": "US / Global", "detector": "Pattern + brand + Luhn checksum"},
    {"entity_type": "US_ZIP_CODE", "label": "ZIP code", "region": "US", "detector": "Pattern + state/ZIP context"},
    {"entity_type": "US_ADDRESS", "label": "US address", "region": "US", "detector": "Rules (street, unit, city, state, ZIP)"},
    {"entity_type": "LOCATION", "label": "Location", "region": "Global", "detector": "NER model (spaCy)"},
    {"entity_type": "IP_ADDRESS", "label": "IP address", "region": "Global", "detector": "Pattern"},
]


def register_custom_recognizers(registry) -> None:
    for name in REPLACED_PRESIDIO_RECOGNIZERS:
        try:
            registry.remove_recognizer(name)
        except Exception:  # noqa: BLE001 - older/newer Presidio without that recognizer
            pass
    for cls in CUSTOM_RECOGNIZER_CLASSES:
        registry.add_recognizer(cls())


# --- post-processing -----------------------------------------------------------------------------
_PRIORITY = {
    "CREDIT_CARD": 100, "IN_AADHAAR": 95, "US_SSN": 90, "EMAIL_ADDRESS": 85, "IP_ADDRESS": 80,
    "PHONE_NUMBER": 70, "IN_PIN_CODE": 60, "US_ZIP_CODE": 60,
}
_CONTAINER_TYPES = {"IN_ADDRESS", "US_ADDRESS"}  # never dropped by, and never drop, other spans (the anonymizer is policy-aware)
_STRONG_MIN = 60
_NOISE_WORDS = {"ssn", "pin", "pan", "otp", "cvv", "aadhaar", "aadhar", "uid", "zip", "dob", "id", "sms", "upi", "ifsc"}
_NHS_CTX = re.compile(r"\b(?:nhs|national health)\b")


def _overlap(a, b) -> bool:
    return a.start < b.end and b.start < a.end


def postprocess(text: str, results: list) -> list:
    """Remove known false positives, resolve overlaps between different types, merge same-type overlaps."""
    kept = []
    for r in results:
        span = text[r.start:r.end]
        low = span.strip().lower()
        if r.entity_type in ("PERSON", "ORGANIZATION", "LOCATION", "NRP") and (low in _NOISE_WORDS or len(low) < 2):
            continue
        if r.entity_type in ("ORGANIZATION", "LOCATION", "NRP") and span.islower() and " " not in span.strip():
            continue  # a single lower-case word ("ref", "plain") is not an organisation or place
        if r.entity_type == "DATE_TIME" and re.fullmatch(r"[\d\s.\-]+", span) and len(_digits(span)) >= 5 \
                and not re.search(r"\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}", span):
            continue  # a bare run of digits is an identifier, not a date
        if r.entity_type == "UK_NHS" and not _NHS_CTX.search(_before(text, r.start, 40)):
            continue  # NHS numbers share a checksum any 10-digit number can pass by chance
        kept.append(r)

    def prio(r) -> int:
        return _PRIORITY.get(r.entity_type, 10)

    dropped = set()
    for i, a in enumerate(kept):
        if a.entity_type in _CONTAINER_TYPES:
            continue
        for j, b in enumerate(kept):
            if i == j or b.entity_type in _CONTAINER_TYPES or a.entity_type == b.entity_type or not _overlap(a, b):
                continue
            if prio(b) >= _STRONG_MIN and (prio(b), b.score) > (prio(a), a.score):
                dropped.add(i)
                break
    kept = [r for i, r in enumerate(kept) if i not in dropped]

    # An address must never swallow another identifier: the anonymizer drops spans CONTAINED in another span,
    # so the contained Aadhaar / SSN / card / e-mail / phone would lose its own rule. Cut the address before it.
    ids = [r for r in kept if r.entity_type in ("CREDIT_CARD", "IN_AADHAAR", "US_SSN", "EMAIL_ADDRESS", "PHONE_NUMBER")]
    for a in [r for r in kept if r.entity_type in _CONTAINER_TYPES]:
        for x in sorted(ids, key=lambda r: r.start):
            if a.start <= x.start and x.end <= a.end:
                a.end = len(text[:x.start].rstrip(" ,.;:-"))
        if a.end - a.start < 8:
            kept.remove(a)

    # NER noise inside a recognised address ("Sunrise Apartments" as ORGANIZATION, "4th Cross" as DATE_TIME ...)
    addresses = [r for r in kept if r.entity_type in _CONTAINER_TYPES]
    kept = [
        r for r in kept
        if not (r.entity_type in ("ORGANIZATION", "DATE_TIME", "NRP", "AGE", "ID")
                and any(a.start <= r.start and r.end <= a.end for a in addresses))
    ]

    # merge overlapping spans of the same type (union, highest score)
    merged = []
    for r in sorted(kept, key=lambda x: (x.entity_type, x.start, -x.end)):
        last = merged[-1] if merged else None
        if last is not None and last.entity_type == r.entity_type and r.start < last.end:
            last.end = max(last.end, r.end)
            last.score = max(last.score, r.score)
        else:
            merged.append(r)
    return sorted(merged, key=lambda x: (x.start, x.end))
