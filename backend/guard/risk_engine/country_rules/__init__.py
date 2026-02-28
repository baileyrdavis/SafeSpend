from guard.risk_engine.country_rules.au import AustraliaCountryRule
from guard.risk_engine.country_rules.uk import UnitedKingdomCountryRule
from guard.risk_engine.country_rules.us import UnitedStatesCountryRule

COUNTRY_RULES = {
    'AU': AustraliaCountryRule(),
    'US': UnitedStatesCountryRule(),
    'UK': UnitedKingdomCountryRule(),
}


def get_country_rule(country_code: str):
    return COUNTRY_RULES.get(country_code)