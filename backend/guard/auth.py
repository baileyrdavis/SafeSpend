from __future__ import annotations

import secrets

from django.conf import settings
from rest_framework.permissions import BasePermission


def _read_api_token_from_request(request) -> str:
    header_token = (request.headers.get('X-API-Token') or '').strip()
    if header_token:
        return header_token

    auth_header = (request.headers.get('Authorization') or '').strip()
    if auth_header.lower().startswith('bearer '):
        return auth_header[7:].strip()

    return ''


class ApiTokenPermission(BasePermission):
    message = 'Missing or invalid API token.'

    def has_permission(self, request, view) -> bool:
        configured_token = (getattr(settings, 'API_AUTH_TOKEN', '') or '').strip()
        if not configured_token:
            return True

        request_token = _read_api_token_from_request(request)
        if not request_token:
            return False

        return secrets.compare_digest(request_token, configured_token)
