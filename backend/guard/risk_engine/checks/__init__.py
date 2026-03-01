from guard.risk_engine.checks.archive_stability import ArchiveStabilityCheck
from guard.risk_engine.checks.abn_validation import AbnValidationCheck
from guard.risk_engine.checks.brand_impersonation import BrandImpersonationCheck
from guard.risk_engine.checks.checkout_redirect import CheckoutRedirectCheck
from guard.risk_engine.checks.contact_details_change import ContactDetailsChangeCheck
from guard.risk_engine.checks.contact_info import ContactInformationCheck
from guard.risk_engine.checks.dns_change import DnsChangeCheck
from guard.risk_engine.checks.domain_age import DomainAgeCheck
from guard.risk_engine.checks.evidence_coverage_guardrail import EvidenceCoverageGuardrailCheck
from guard.risk_engine.checks.html_change_hash import HtmlChangeHashCheck
from guard.risk_engine.checks.https_check import HttpsCheck
from guard.risk_engine.checks.missing_policies import MissingPoliciesCheck
from guard.risk_engine.checks.payment_method_risk import PaymentMethodRiskCheck
from guard.risk_engine.checks.payment_form_security import PaymentFormSecurityCheck
from guard.risk_engine.checks.payment_processor_reputation import PaymentProcessorReputationCheck
from guard.risk_engine.checks.platform_fingerprint import EcommercePlatformFingerprintCheck
from guard.risk_engine.checks.registrar_change import RegistrarChangeCheck
from guard.risk_engine.checks.threat_feed_reputation import ThreatFeedReputationCheck

DEFAULT_CHECKS = [
    BrandImpersonationCheck,
    ThreatFeedReputationCheck,
    DomainAgeCheck,
    RegistrarChangeCheck,
    DnsChangeCheck,
    HttpsCheck,
    EvidenceCoverageGuardrailCheck,
    EcommercePlatformFingerprintCheck,
    PaymentFormSecurityCheck,
    PaymentProcessorReputationCheck,
    PaymentMethodRiskCheck,
    MissingPoliciesCheck,
    ContactInformationCheck,
    ContactDetailsChangeCheck,
    AbnValidationCheck,
    ArchiveStabilityCheck,
    CheckoutRedirectCheck,
    HtmlChangeHashCheck,
]
