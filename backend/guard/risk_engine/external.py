from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
import ipaddress
import socket
import ssl
from typing import Any

import dns.exception
import dns.resolver
import requests
import whois


def _is_public_ip(ip_text: str) -> bool:
    try:
        ip_value = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    return ip_value.is_global


def _hostname_resolves_to_public_ips(domain: str) -> bool:
    try:
        addr_info = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False

    addresses = {item[4][0] for item in addr_info if item and item[4]}
    if not addresses:
        return False

    return all(_is_public_ip(address) for address in addresses)


def _normalize_datetime(value: Any) -> datetime | None:
    if isinstance(value, list):
        value = value[0] if value else None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    return None


@lru_cache(maxsize=2048)
def get_whois_data(domain: str) -> dict[str, Any]:
    try:
        data = whois.whois(domain)
    except Exception:
        return {}

    if data is None:
        return {}

    if not isinstance(data, dict):
        data = data.__dict__

    creation_date = _normalize_datetime(data.get('creation_date'))
    updated_date = _normalize_datetime(data.get('updated_date'))
    registrar = data.get('registrar')

    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None

    return {
        'creation_date': creation_date,
        'updated_date': updated_date,
        'registrar': str(registrar).strip() if registrar else None,
    }


@lru_cache(maxsize=2048)
def get_nameservers(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, 'NS', lifetime=2)
        nameservers = sorted({str(answer.target).rstrip('.').lower() for answer in answers})
        return nameservers
    except (dns.exception.DNSException, ValueError):
        return []


@lru_cache(maxsize=2048)
def get_https_info(domain: str) -> dict[str, Any]:
    result = {
        'has_https': False,
        'self_signed': False,
        'error': None,
    }

    context = ssl.create_default_context()
    try:
        if not _hostname_resolves_to_public_ips(domain):
            result['error'] = 'Domain resolves to non-public IP space.'
            return result

        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                certificate = secure_sock.getpeercert()

                subject = tuple(certificate.get('subject', []))
                issuer = tuple(certificate.get('issuer', []))
                result['has_https'] = True
                result['self_signed'] = bool(subject and issuer and subject == issuer)
                return result
    except Exception as exc:
        result['error'] = str(exc)
        return result


@lru_cache(maxsize=2048)
def has_wayback_history(domain: str) -> bool:
    url = 'https://web.archive.org/cdx/search/cdx'
    params = {
        'url': domain,
        'output': 'json',
        'from': '2000',
        'filter': 'statuscode:200',
        'limit': '1',
    }
    try:
        response = requests.get(url, params=params, timeout=3)
        response.raise_for_status()
        payload = response.json()
    except Exception:
        return False

    return isinstance(payload, list) and len(payload) > 1


class ExternalContext:
    def __init__(self, domain: str):
        self.domain = domain
        self._whois: dict[str, Any] | None = None
        self._nameservers: list[str] | None = None
        self._https: dict[str, Any] | None = None
        self._wayback: bool | None = None

    @property
    def whois(self) -> dict[str, Any]:
        if self._whois is None:
            self._whois = get_whois_data(self.domain)
        return self._whois

    @property
    def nameservers(self) -> list[str]:
        if self._nameservers is None:
            self._nameservers = get_nameservers(self.domain)
        return self._nameservers

    @property
    def https_info(self) -> dict[str, Any]:
        if self._https is None:
            self._https = get_https_info(self.domain)
        return self._https

    @property
    def has_wayback(self) -> bool:
        if self._wayback is None:
            self._wayback = has_wayback_history(self.domain)
        return self._wayback
