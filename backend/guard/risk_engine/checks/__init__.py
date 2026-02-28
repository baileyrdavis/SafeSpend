from guard.risk_engine.checks.archive_stability import ArchiveStabilityCheck
from guard.risk_engine.checks.checkout_redirect import CheckoutRedirectCheck
from guard.risk_engine.checks.contact_info import ContactInformationCheck
from guard.risk_engine.checks.dns_change import DnsChangeCheck
from guard.risk_engine.checks.domain_age import DomainAgeCheck
from guard.risk_engine.checks.html_change_hash import HtmlChangeHashCheck
from guard.risk_engine.checks.https_check import HttpsCheck
from guard.risk_engine.checks.missing_policies import MissingPoliciesCheck
from guard.risk_engine.checks.platform_fingerprint import EcommercePlatformFingerprintCheck
from guard.risk_engine.checks.registrar_change import RegistrarChangeCheck

DEFAULT_CHECKS = [
    DomainAgeCheck,
    RegistrarChangeCheck,
    DnsChangeCheck,
    HttpsCheck,
    EcommercePlatformFingerprintCheck,
    MissingPoliciesCheck,
    ContactInformationCheck,
    ArchiveStabilityCheck,
    CheckoutRedirectCheck,
    HtmlChangeHashCheck,
]