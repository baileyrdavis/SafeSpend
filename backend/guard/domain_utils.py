from __future__ import annotations

import ipaddress
import re

from tldextract import extract

DOMAIN_PATTERN = re.compile(r'^[a-z0-9][a-z0-9.-]{0,253}[a-z0-9]$')
FORBIDDEN_HOSTNAMES = {'localhost', 'localhost.localdomain'}


def normalize_domain(raw_domain: str) -> str:
    domain = (raw_domain or '').strip().lower()
    if '://' in domain:
        domain = domain.split('://', 1)[1]
    domain = domain.split('/', 1)[0].split(':', 1)[0].strip('.')

    parsed = extract(domain)
    if parsed.top_domain_under_public_suffix:
        return parsed.top_domain_under_public_suffix

    return domain


def is_likely_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    if ' ' in domain or '_' in domain:
        return False
    if '..' in domain:
        return False
    if len(domain) > 255 or '.' not in domain:
        return False
    if domain in FORBIDDEN_HOSTNAMES:
        return False
    if not DOMAIN_PATTERN.match(domain):
        return False

    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    labels = domain.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False

    return True
