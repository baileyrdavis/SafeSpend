from __future__ import annotations

import re
from typing import Any

from tldextract import extract

COUNTRY_ALIASES = {
    'AUSTRALIA': 'AU',
    'AU': 'AU',
    'UNITED STATES': 'US',
    'USA': 'US',
    'US': 'US',
    'UNITED KINGDOM': 'UK',
    'UK': 'UK',
    'GREAT BRITAIN': 'UK',
    'GB': 'UK',
}

CURRENCY_TO_COUNTRY = {
    'AUD': 'AU',
    'USD': 'US',
    'GBP': 'UK',
}

AU_ADDRESS_PATTERN = re.compile(r'\b(NSW|VIC|QLD|WA|SA|TAS|ACT|NT)\b\s*\d{4}\b', re.IGNORECASE)
US_ADDRESS_PATTERN = re.compile(r'\b(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV|DC)\b\s*\d{5}(?:-\d{4})?\b', re.IGNORECASE)
UK_ADDRESS_PATTERN = re.compile(r'\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b', re.IGNORECASE)


def normalize_country(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().upper()
    return COUNTRY_ALIASES.get(cleaned)


def infer_country(domain: str, signals: dict[str, Any]) -> tuple[str | None, float, dict[str, Any]]:
    votes: dict[str, int] = {'AU': 0, 'US': 0, 'UK': 0}
    evidence: dict[str, Any] = {}

    parsed = extract(domain)
    suffix = (parsed.suffix or '').lower()
    if suffix in {'au', 'com.au', 'net.au', 'org.au'}:
        votes['AU'] += 2
        evidence['tld'] = 'AU'
    elif suffix in {'us'}:
        votes['US'] += 2
        evidence['tld'] = 'US'
    elif suffix in {'uk', 'co.uk', 'org.uk'}:
        votes['UK'] += 2
        evidence['tld'] = 'UK'

    currency = (signals.get('currency') or '').upper()
    country_for_currency = CURRENCY_TO_COUNTRY.get(currency)
    if country_for_currency:
        votes[country_for_currency] += 2
        evidence['currency'] = currency

    destinations = signals.get('shipping_destinations') or []
    if isinstance(destinations, str):
        destinations = [destinations]

    normalized_destinations = [normalize_country(item) for item in destinations]
    for destination in normalized_destinations:
        if destination in votes:
            votes[destination] += 1

    if any(normalized_destinations):
        evidence['shipping_destinations'] = [item for item in normalized_destinations if item]

    address_text = signals.get('address_text') or ''
    if isinstance(address_text, str):
        if AU_ADDRESS_PATTERN.search(address_text):
            votes['AU'] += 1
            evidence['address_format'] = 'AU'
        elif US_ADDRESS_PATTERN.search(address_text):
            votes['US'] += 1
            evidence['address_format'] = 'US'
        elif UK_ADDRESS_PATTERN.search(address_text):
            votes['UK'] += 1
            evidence['address_format'] = 'UK'

    total_votes = sum(votes.values())
    if total_votes == 0:
        return None, 0.0, evidence

    winner = max(votes, key=votes.get)
    max_votes = votes[winner]

    sorted_votes = sorted(votes.values(), reverse=True)
    if len(sorted_votes) > 1 and sorted_votes[0] == sorted_votes[1]:
        return None, 0.3, {'votes': votes, **evidence}

    confidence = round(max_votes / total_votes, 2)
    return winner, confidence, {'votes': votes, **evidence}