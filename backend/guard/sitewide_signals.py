from __future__ import annotations

import re
import time
from dataclasses import dataclass
from html import unescape
from typing import Any
from urllib.parse import urljoin, urlparse

import requests


_CACHE_TTL_SECONDS = 10 * 60
_CACHE_MAX_SIZE = 256
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}

_TWO_PART_SUFFIXES = {'co.uk', 'org.uk', 'com.au', 'net.au', 'org.au'}
_LINK_PATTERN = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_SCRIPT_STYLE_PATTERN = re.compile(r'<(script|style)\b[^>]*>.*?</\1>', re.IGNORECASE | re.DOTALL)
_TAG_PATTERN = re.compile(r'<[^>]+>')
_WHITESPACE_PATTERN = re.compile(r'\s+')

_POLICY_KEYWORDS = {
    'refund': ('refund', 'returns', 'return policy', 'money back'),
    'privacy': ('privacy', 'privacy policy'),
    'terms': ('terms', 'conditions', 'terms of service', 'terms and conditions'),
}

_CONTACT_KEYWORDS = ('contact', 'support', 'help', 'about')
_PAYMENT_PROVIDER_TERMS = ('stripe', 'paypal', 'braintree', 'adyen', 'square', 'shopify', 'amazon pay', 'checkout.com')
_PAYMENT_TRUSTED_METHODS = ('paypal', 'apple pay', 'google pay', 'afterpay', 'klarna', 'stripe', 'shop pay')
_PAYMENT_RISKY_METHODS = ('gift card', 'wire transfer', 'western union', 'moneygram', 'payid', 'bitcoin', 'crypto', 'ethereum', 'usdt')
_CHECKOUT_HINTS = ('checkout', 'cart', 'basket', 'billing', 'payment', 'order')


@dataclass
class _PageSample:
    url: str
    html: str
    text: str


def _guess_registered_domain(hostname: str) -> str:
    host = str(hostname or '').lower().strip('.')
    parts = [item for item in host.split('.') if item]
    if len(parts) <= 2:
        return host

    tail = '.'.join(parts[-2:])
    tail3 = '.'.join(parts[-3:])
    if tail in _TWO_PART_SUFFIXES:
        return tail3
    return '.'.join(parts[-2:])


def _strip_html(html: str) -> str:
    cleaned = _SCRIPT_STYLE_PATTERN.sub(' ', html or '')
    cleaned = _TAG_PATTERN.sub(' ', cleaned)
    cleaned = unescape(cleaned)
    cleaned = _WHITESPACE_PATTERN.sub(' ', cleaned)
    return cleaned.strip()


def _fetch_html(url: str, timeout_seconds: int = 4) -> str:
    response = requests.get(
        url,
        timeout=timeout_seconds,
        headers={
            'User-Agent': 'SafeSpendScanner/1.0 (+https://safespend.local)',
            'Accept': 'text/html,application/xhtml+xml',
        },
    )
    if response.status_code >= 400:
        return ''
    content_type = str(response.headers.get('Content-Type') or '').lower()
    if 'html' not in content_type and 'text/' not in content_type:
        return ''
    return str(response.text or '')[:300_000]


def _extract_same_site_links(html: str, base_url: str, root_domain: str) -> list[str]:
    links: list[str] = []
    for match in _LINK_PATTERN.finditer(html or ''):
        href = str(match.group(1) or '').strip()
        if not href or href.startswith('#') or href.lower().startswith(('javascript:', 'mailto:', 'tel:')):
            continue
        try:
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
        except (TypeError, ValueError):
            continue
        if parsed.scheme not in {'http', 'https'}:
            continue
        if _guess_registered_domain(parsed.hostname or '') != root_domain:
            continue
        links.append(absolute)
    return links


def _collect_abn_candidates(text: str) -> tuple[list[str], list[str], list[str]]:
    labeled = set()
    unlabeled = set()

    label_first = re.compile(r'\b(?:ABN|Australian Business Number)\b[^\d]{0,24}(\d(?:[\s-]*\d){10,15})\b', re.IGNORECASE)
    number_first = re.compile(r'\b(\d(?:[\s-]*\d){10,15})\b[^\n\r]{0,32}\b(?:ABN|Australian Business Number)\b', re.IGNORECASE)
    context = re.compile(r'\b(?:company|business|pty ltd|australia|australian)\b[^\d]{0,32}(\d(?:[\s-]*\d){10,15})\b', re.IGNORECASE)

    for pattern, bucket in ((label_first, labeled), (number_first, labeled), (context, unlabeled)):
        for match in pattern.finditer(text):
            digits = re.sub(r'\D+', '', str(match.group(1) or ''))
            if len(digits) == 11:
                bucket.add(digits)
            if len(labeled) + len(unlabeled) >= 6:
                break

    merged = list(dict.fromkeys([*labeled, *unlabeled]))[:5]
    return merged, list(labeled)[:5], list(unlabeled)[:5]


def _empty_sitewide_payload() -> dict[str, Any]:
    return {
        'pages_scanned': [],
        'page_count': 0,
        'policies': {'refund': False, 'privacy': False, 'terms': False},
        'contact': {'email': False, 'phone': False, 'contact_page': False, 'address': False},
        'payment_methods': {
            'methods': [],
            'trusted_methods': [],
            'risky_methods': [],
            'risky_confidence': 0.0,
            'risky_evidence_count': 0,
            'risky_evidence': [],
        },
        'payment_form_security': {
            'has_raw_card_form_fields': False,
            'card_field_count': 0,
            'expiry_field_count': 0,
            'cvv_field_count': 0,
            'card_form_signal_count': 0,
            'secure_provider_detected': False,
            'secure_provider_iframe_count': 0,
            'secure_provider_script_count': 0,
            'secure_provider_action_count': 0,
            'trusted_providers': [],
            'raw_card_form_risk': False,
            'evidence': [],
        },
        'abn_signals': {
            'candidates': [],
            'labeled_candidates': [],
            'unlabeled_candidates': [],
            'candidate_count': 0,
            'labeled_candidate_count': 0,
        },
        'shipping_destinations': [],
        'currency': '',
        'dom_features': {
            'checkout_route': False,
            'cart_route': False,
            'checkout_ui_markers': False,
        },
    }


def collect_sitewide_signals(domain: str, max_pages: int = 5) -> dict[str, Any]:
    normalized_domain = str(domain or '').strip().lower()
    if not normalized_domain:
        return _empty_sitewide_payload()

    cached = _CACHE.get(normalized_domain)
    now = time.time()
    if cached and now - cached[0] <= _CACHE_TTL_SECONDS:
        return dict(cached[1])

    root_url = f'https://{normalized_domain}/'
    root_domain = _guess_registered_domain(normalized_domain)
    payload = _empty_sitewide_payload()

    try:
        root_html = _fetch_html(root_url)
    except Exception:
        root_html = ''
    if not root_html:
        try:
            root_html = _fetch_html(f'http://{normalized_domain}/')
            root_url = f'http://{normalized_domain}/'
        except Exception:
            root_html = ''

    if not root_html:
        _CACHE[normalized_domain] = (now, payload)
        return payload

    root_sample = _PageSample(url=root_url, html=root_html, text=_strip_html(root_html))
    pages: list[_PageSample] = [root_sample]

    links = _extract_same_site_links(root_html, root_url, root_domain)
    prioritized: list[str] = []
    for link in links:
        lower = link.lower()
        if any(keyword in lower for keyword in (*_CONTACT_KEYWORDS, *_CHECKOUT_HINTS, 'privacy', 'terms', 'refund', 'return', 'shipping')):
            prioritized.append(link)
    seen_links = {root_url}
    for link in prioritized:
        if len(pages) >= max(1, max_pages):
            break
        if link in seen_links:
            continue
        seen_links.add(link)
        try:
            html = _fetch_html(link)
        except Exception:
            html = ''
        if not html:
            continue
        pages.append(_PageSample(url=link, html=html, text=_strip_html(html)))

    policies = {'refund': False, 'privacy': False, 'terms': False}
    contact = {'email': False, 'phone': False, 'contact_page': False, 'address': False}
    methods = set()
    trusted_methods = set()
    risky_methods = set()
    risky_evidence = set()
    trusted_providers = set()
    abn_candidates = set()
    labeled_abns = set()
    unlabeled_abns = set()
    destinations = set()
    currency = ''

    payment_form = payload['payment_form_security']
    dom_features = payload['dom_features']

    for page in pages:
        html_lower = page.html.lower()
        text_lower = page.text.lower()
        url_lower = page.url.lower()

        payload['pages_scanned'].append(page.url)

        for policy_name, terms in _POLICY_KEYWORDS.items():
            if policies[policy_name]:
                continue
            if any(term in text_lower or term in html_lower for term in terms):
                policies[policy_name] = True

        if 'mailto:' in html_lower or re.search(r'\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b', text_lower):
            contact['email'] = True
        if 'tel:' in html_lower or re.search(r'\+?\d[\d\s().-]{6,}\d', page.text):
            contact['phone'] = True
        if any(keyword in url_lower or keyword in text_lower for keyword in _CONTACT_KEYWORDS):
            contact['contact_page'] = True
        if re.search(r'\b(?:street|st|road|rd|avenue|ave|drive|dr|vic|nsw|qld|wa|sa|tas|act)\b', text_lower):
            contact['address'] = True

        for provider in _PAYMENT_PROVIDER_TERMS:
            if provider in html_lower or provider in text_lower:
                trusted_providers.add(provider)

        for method in _PAYMENT_TRUSTED_METHODS:
            if method in text_lower:
                trusted_methods.add(method.replace(' ', '_'))
                methods.add(method.replace(' ', '_'))

        for method in _PAYMENT_RISKY_METHODS:
            if method in text_lower:
                key = method.replace(' ', '_')
                risky_methods.add(key)
                methods.add(key)
                risky_evidence.add(f'{key}_terms')

        card_field_count = len(re.findall(r'(name|id|placeholder|aria-label)\s*=\s*["\'][^"\']*(card number|credit card|cc-number|ccnum)[^"\']*["\']', page.html, re.IGNORECASE))
        expiry_field_count = len(re.findall(r'(name|id|placeholder|aria-label)\s*=\s*["\'][^"\']*(exp|expiry|expiration|month|year)[^"\']*["\']', page.html, re.IGNORECASE))
        cvv_field_count = len(re.findall(r'(name|id|placeholder|aria-label)\s*=\s*["\'][^"\']*(cvv|cvc|security code)[^"\']*["\']', page.html, re.IGNORECASE))

        payment_form['card_field_count'] += card_field_count
        payment_form['expiry_field_count'] += expiry_field_count
        payment_form['cvv_field_count'] += cvv_field_count
        payment_form['card_form_signal_count'] += card_field_count + expiry_field_count + cvv_field_count
        page_has_raw = card_field_count > 0 and (expiry_field_count > 0 or cvv_field_count > 0)
        payment_form['has_raw_card_form_fields'] = bool(payment_form['has_raw_card_form_fields'] or page_has_raw)

        provider_detected = bool(trusted_providers)
        payment_form['secure_provider_detected'] = bool(payment_form['secure_provider_detected'] or provider_detected)

        path = urlparse(page.url).path.lower()
        if any(f'/{hint}' in path for hint in ('checkout', 'payment', 'billing')):
            dom_features['checkout_route'] = True
        if any(f'/{hint}' in path for hint in ('cart', 'basket', 'order')):
            dom_features['cart_route'] = True
        if any(hint in text_lower for hint in ('checkout', 'place order', 'order summary', 'payment method')):
            dom_features['checkout_ui_markers'] = True

        if 'australia' in text_lower or 'ships to au' in text_lower or 'ship to au' in text_lower:
            destinations.add('AU')
        if 'united states' in text_lower or 'ships to us' in text_lower or 'ship to us' in text_lower or 'usa' in text_lower:
            destinations.add('US')
        if 'united kingdom' in text_lower or 'ships to uk' in text_lower or 'ship to uk' in text_lower:
            destinations.add('UK')

        if not currency:
            if re.search(r'\bAUD\b|AU\$|A\$', page.text, re.IGNORECASE):
                currency = 'AUD'
            elif re.search(r'\bUSD\b|US\$', page.text, re.IGNORECASE):
                currency = 'USD'
            elif re.search(r'\bGBP\b|£', page.text, re.IGNORECASE):
                currency = 'GBP'

        merged_abns, labeled, unlabeled = _collect_abn_candidates(page.text)
        abn_candidates.update(merged_abns)
        labeled_abns.update(labeled)
        unlabeled_abns.update(unlabeled)

    payment_form['trusted_providers'] = sorted(trusted_providers)[:8]
    payment_form['raw_card_form_risk'] = bool(
        payment_form['has_raw_card_form_fields'] and not payment_form['secure_provider_detected']
    )
    payment_form['evidence'] = sorted(risky_evidence)[:10]

    payload['page_count'] = len(payload['pages_scanned'])
    payload['policies'] = policies
    payload['contact'] = contact
    payload['payment_methods'] = {
        'methods': sorted(methods)[:12],
        'trusted_methods': sorted(trusted_methods)[:8],
        'risky_methods': sorted(risky_methods)[:8],
        'risky_confidence': 0.7 if risky_methods else 0.0,
        'risky_evidence_count': len(risky_evidence),
        'risky_evidence': sorted(risky_evidence)[:8],
    }
    payload['payment_form_security'] = payment_form
    payload['abn_signals'] = {
        'candidates': sorted(abn_candidates)[:5],
        'labeled_candidates': sorted(labeled_abns)[:5],
        'unlabeled_candidates': sorted(unlabeled_abns)[:5],
        'candidate_count': min(5, len(abn_candidates)),
        'labeled_candidate_count': min(5, len(labeled_abns)),
    }
    payload['shipping_destinations'] = sorted(destinations)
    payload['currency'] = currency
    payload['dom_features'] = dom_features

    if len(_CACHE) >= _CACHE_MAX_SIZE:
        oldest_key = min(_CACHE, key=lambda key: _CACHE[key][0])
        _CACHE.pop(oldest_key, None)
    _CACHE[normalized_domain] = (now, payload)
    return dict(payload)


def _merge_boolean_map(primary: dict[str, Any], secondary: dict[str, Any], keys: tuple[str, ...]) -> dict[str, bool]:
    return {
        key: bool(primary.get(key)) or bool(secondary.get(key))
        for key in keys
    }


def _merge_unique_list(*values: list[Any], limit: int = 12) -> list[Any]:
    result = []
    seen = set()
    for value_list in values:
        for item in value_list or []:
            marker = str(item)
            if marker in seen:
                continue
            seen.add(marker)
            result.append(item)
            if len(result) >= limit:
                return result
    return result


def merge_with_sitewide_signals(domain: str, extracted_signals: dict[str, Any]) -> dict[str, Any]:
    base = dict(extracted_signals or {})
    sitewide = collect_sitewide_signals(domain)

    base['policies'] = _merge_boolean_map(
        base.get('policies') or {},
        sitewide.get('policies') or {},
        ('refund', 'privacy', 'terms'),
    )
    base['contact'] = _merge_boolean_map(
        base.get('contact') or {},
        sitewide.get('contact') or {},
        ('email', 'phone', 'contact_page', 'address'),
    )

    payment_methods = base.get('payment_methods') or {}
    sitewide_payment_methods = sitewide.get('payment_methods') or {}
    base['payment_methods'] = {
        'methods': _merge_unique_list(payment_methods.get('methods') or [], sitewide_payment_methods.get('methods') or [], limit=14),
        'trusted_methods': _merge_unique_list(payment_methods.get('trusted_methods') or [], sitewide_payment_methods.get('trusted_methods') or [], limit=10),
        'risky_methods': _merge_unique_list(payment_methods.get('risky_methods') or [], sitewide_payment_methods.get('risky_methods') or [], limit=10),
        'risky_confidence': max(float(payment_methods.get('risky_confidence') or 0), float(sitewide_payment_methods.get('risky_confidence') or 0)),
        'risky_evidence_count': int(payment_methods.get('risky_evidence_count') or 0) + int(sitewide_payment_methods.get('risky_evidence_count') or 0),
        'risky_evidence': _merge_unique_list(payment_methods.get('risky_evidence') or [], sitewide_payment_methods.get('risky_evidence') or [], limit=12),
    }

    payment_form = base.get('payment_form_security') or {}
    sitewide_payment_form = sitewide.get('payment_form_security') or {}
    base['payment_form_security'] = {
        'has_raw_card_form_fields': bool(payment_form.get('has_raw_card_form_fields')) or bool(sitewide_payment_form.get('has_raw_card_form_fields')),
        'card_field_count': int(payment_form.get('card_field_count') or 0) + int(sitewide_payment_form.get('card_field_count') or 0),
        'expiry_field_count': int(payment_form.get('expiry_field_count') or 0) + int(sitewide_payment_form.get('expiry_field_count') or 0),
        'cvv_field_count': int(payment_form.get('cvv_field_count') or 0) + int(sitewide_payment_form.get('cvv_field_count') or 0),
        'card_form_signal_count': int(payment_form.get('card_form_signal_count') or 0) + int(sitewide_payment_form.get('card_form_signal_count') or 0),
        'secure_provider_detected': bool(payment_form.get('secure_provider_detected')) or bool(sitewide_payment_form.get('secure_provider_detected')),
        'secure_provider_iframe_count': int(payment_form.get('secure_provider_iframe_count') or 0) + int(sitewide_payment_form.get('secure_provider_iframe_count') or 0),
        'secure_provider_script_count': int(payment_form.get('secure_provider_script_count') or 0) + int(sitewide_payment_form.get('secure_provider_script_count') or 0),
        'secure_provider_action_count': int(payment_form.get('secure_provider_action_count') or 0) + int(sitewide_payment_form.get('secure_provider_action_count') or 0),
        'trusted_providers': _merge_unique_list(payment_form.get('trusted_providers') or [], sitewide_payment_form.get('trusted_providers') or [], limit=10),
        'raw_card_form_risk': bool(payment_form.get('raw_card_form_risk')) or bool(sitewide_payment_form.get('raw_card_form_risk')),
        'evidence': _merge_unique_list(payment_form.get('evidence') or [], sitewide_payment_form.get('evidence') or [], limit=12),
    }

    abn_signals = base.get('abn_signals') or {}
    sitewide_abn = sitewide.get('abn_signals') or {}
    merged_candidates = _merge_unique_list(abn_signals.get('candidates') or [], sitewide_abn.get('candidates') or [], limit=5)
    merged_labeled = _merge_unique_list(abn_signals.get('labeled_candidates') or [], sitewide_abn.get('labeled_candidates') or [], limit=5)
    merged_unlabeled = _merge_unique_list(abn_signals.get('unlabeled_candidates') or [], sitewide_abn.get('unlabeled_candidates') or [], limit=5)
    base['abn_signals'] = {
        'candidates': merged_candidates,
        'labeled_candidates': merged_labeled,
        'unlabeled_candidates': merged_unlabeled,
        'candidate_count': len(merged_candidates),
        'labeled_candidate_count': len(merged_labeled),
    }

    base['shipping_destinations'] = _merge_unique_list(
        base.get('shipping_destinations') or [],
        sitewide.get('shipping_destinations') or [],
        limit=5,
    )
    if not base.get('currency') and sitewide.get('currency'):
        base['currency'] = sitewide.get('currency')

    dom_features = base.get('dom_features') or {}
    sitewide_dom_features = sitewide.get('dom_features') or {}
    base['dom_features'] = {
        **dom_features,
        'checkout_route': bool(dom_features.get('checkout_route')) or bool(sitewide_dom_features.get('checkout_route')),
        'cart_route': bool(dom_features.get('cart_route')) or bool(sitewide_dom_features.get('cart_route')),
        'checkout_ui_markers': bool(dom_features.get('checkout_ui_markers')) or bool(sitewide_dom_features.get('checkout_ui_markers')),
    }

    base['_sitewide_enrichment'] = {
        'enabled': True,
        'pages_scanned': sitewide.get('pages_scanned') or [],
        'page_count': int(sitewide.get('page_count') or 0),
    }
    return base
