from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable

from django.db import OperationalError, ProgrammingError, transaction
import tldextract

from guard.models import Brand, BrandDomain, BrandDomainType


@dataclass(frozen=True)
class KnownBrandSeed:
    name: str
    domains: tuple[str, ...]


KNOWN_BRAND_SEEDS: tuple[KnownBrandSeed, ...] = (
    KnownBrandSeed('Amazon', ('amazon.com', 'amazon.com.au', 'amazon.co.uk')),
    KnownBrandSeed('Target', ('target.com', 'target.com.au')),
    KnownBrandSeed('Apple', ('apple.com', 'apple.com.au', 'apple.co.uk')),
    KnownBrandSeed('Google', ('google.com', 'google.com.au', 'google.co.uk')),
    KnownBrandSeed('Microsoft', ('microsoft.com', 'microsoft.com.au', 'microsoft.co.uk')),
    KnownBrandSeed('eBay', ('ebay.com', 'ebay.com.au', 'ebay.co.uk')),
    KnownBrandSeed('PayPal', ('paypal.com', 'paypal.com.au', 'paypal.co.uk')),
    KnownBrandSeed('Walmart', ('walmart.com',)),
    KnownBrandSeed('Nike', ('nike.com', 'nike.com.au', 'nike.co.uk')),
    KnownBrandSeed('Adidas', ('adidas.com', 'adidas.com.au', 'adidas.co.uk')),
)

_SEEDS_ENSURED = False

CHAR_SUBSTITUTIONS = str.maketrans({
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '7': 't',
    '8': 'b',
    '$': 's',
    '@': 'a',
})


def _registered_parts(domain: str) -> tuple[str, str]:
    parsed = tldextract.extract(domain)
    return (parsed.domain or '').lower(), (parsed.suffix or '').lower()


def _normalize_label(label: str) -> str:
    return (label or '').lower().translate(CHAR_SUBSTITUTIONS)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + cost,
            ))
        prev = curr
    return prev[-1]


def ensure_brand_seed_data() -> None:
    global _SEEDS_ENSURED
    if _SEEDS_ENSURED:
        return

    try:
        with transaction.atomic():
            for seed in KNOWN_BRAND_SEEDS:
                brand, _ = Brand.objects.get_or_create(name=seed.name, defaults={'is_active': True})
                for domain in seed.domains:
                    BrandDomain.objects.get_or_create(
                        domain=domain.lower(),
                        defaults={
                            'brand': brand,
                            'domain_type': BrandDomainType.REGIONAL,
                            'is_official': True,
                            'is_active': True,
                            'source': 'seed',
                        },
                    )
        _SEEDS_ENSURED = True
    except (OperationalError, ProgrammingError):
        # Migrations may not be applied yet.
        return


@lru_cache(maxsize=1)
def load_active_brand_domains() -> tuple[tuple[str, str], ...]:
    ensure_brand_seed_data()
    rows = (
        BrandDomain.objects.select_related('brand')
        .filter(is_active=True, is_official=True, brand__is_active=True)
        .values_list('domain', 'brand__name')
    )
    return tuple((domain.lower(), brand_name) for domain, brand_name in rows)


def reset_brand_domain_cache() -> None:
    load_active_brand_domains.cache_clear()


def find_brand_match(domain: str) -> tuple[str, str] | None:
    target = (domain or '').lower()
    for official_domain, brand_name in load_active_brand_domains():
        if target == official_domain:
            return official_domain, brand_name
    return None


def find_typosquat_match(domain: str) -> tuple[str, str] | None:
    target = (domain or '').lower()
    target_label, target_suffix = _registered_parts(target)
    if not target_label or not target_suffix:
        return None

    normalized_target = _normalize_label(target_label)
    for official_domain, brand_name in load_active_brand_domains():
        if target == official_domain:
            continue

        official_label, official_suffix = _registered_parts(official_domain)
        if not official_label or official_suffix != target_suffix:
            continue

        normalized_official = _normalize_label(official_label)
        distance = _levenshtein(normalized_target, normalized_official)
        if distance <= 1:
            return official_domain, brand_name
        if distance == 2 and min(len(normalized_target), len(normalized_official)) >= 6:
            return official_domain, brand_name

    return None

