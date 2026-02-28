from __future__ import annotations

import secrets

from django.conf import settings
from rest_framework.permissions import BasePermission

from guard.auth_service import get_valid_access_token, mark_access_token_used


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
        auth_required = bool(getattr(settings, 'API_REQUIRE_AUTH', False) or configured_token)

        request_token = _read_api_token_from_request(request)
        if not request_token:
            if auth_required:
                return False
            request.guard_auth_mode = 'anonymous'
            request.guard_user = None
            request.guard_access_token = None
            return True

        if configured_token and secrets.compare_digest(request_token, configured_token):
            request.guard_auth_mode = 'static-token'
            request.guard_user = None
            request.guard_access_token = None
            return True

        access_token = get_valid_access_token(request_token)
        if access_token is None:
            return False

        mark_access_token_used(access_token)
        request.guard_auth_mode = 'access-token'
        request.guard_user = access_token.user
        request.guard_access_token = access_token
        return True
