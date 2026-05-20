from redactyl.detectors.api_key import ApiKeyDetector
from redactyl.detectors.aws import AWSDetector
from redactyl.detectors.bearer import BearerTokenDetector
from redactyl.detectors.custom_keyword import CustomKeywordDetector
from redactyl.detectors.business_unit import BusinessUnitDetector
from redactyl.detectors.company_email import CompanyEmailDetector
from redactyl.detectors.credit_card import CreditCardDetector
from redactyl.detectors.db_conn import DBConnectionStringDetector
from redactyl.detectors.domain import DomainDetector
from redactyl.detectors.email import EmailDetector
from redactyl.detectors.ip import IPDetector
from redactyl.detectors.jwt import JWTDetector
from redactyl.detectors.password import PasswordDetector
from redactyl.detectors.phone import PhoneDetector
from redactyl.detectors.private_key import PrivateKeyDetector
from redactyl.detectors.request_id import RequestIDDetector
from redactyl.detectors.session_cookie import SessionCookieDetector
from redactyl.detectors.ssn import SSNDetector
from redactyl.detectors.url import URLDetector


def build_detectors(config):
    detectors = [
        EmailDetector(),
        CompanyEmailDetector(config.get("internal_domains", [])),
        PhoneDetector(),
        CreditCardDetector(),
        SSNDetector(),
        JWTDetector(),
        BearerTokenDetector(),
        ApiKeyDetector(),
        AWSDetector(),
        PrivateKeyDetector(),
        SessionCookieDetector(),
        PasswordDetector(),
        DomainDetector(config.get("internal_domains", [])),
        IPDetector(),
        URLDetector(),
        DBConnectionStringDetector(),
        RequestIDDetector(),
        BusinessUnitDetector(config.get("business_units", [])),
        CustomKeywordDetector(config.get("custom_keywords", [])),
    ]

    enabled = set(config.get("enabled_detectors", []) or [])
    disabled = set(config.get("disabled_detectors", []) or [])

    if enabled:
        detectors = [d for d in detectors if d.name in enabled]

    if disabled:
        detectors = [d for d in detectors if d.name not in disabled]

    return detectors