from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
from http import HTTPStatus
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from guard.models import ApiAccessToken, ApiRefreshToken, DeviceAuthSession, DeviceAuthStatus, SeenSite

USER_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    access_token_expires_at: datetime
    refresh_token: str
    refresh_token_expires_at: datetime
    access_record: ApiAccessToken
    refresh_record: ApiRefreshToken


class AuthServiceError(Exception):
    def __init__(self, code: str, message: str, http_status: int = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = int(http_status)


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def hash_install_identifier(install_hash: str) -> str:
    return hash_secret((install_hash or '').strip())


def normalize_user_code(value: str) -> str:
    compact = ''.join(char for char in (value or '').upper() if char.isalnum())
    if len(compact) != 8:
        return ''
    return f'{compact[:4]}-{compact[4:]}'


def _device_auth_interval_seconds() -> int:
    return min(max(int(getattr(settings, 'DEVICE_AUTH_INTERVAL_SECONDS', 5)), 3), 20)


def _device_auth_expiry_delta() -> timedelta:
    seconds = max(int(getattr(settings, 'DEVICE_AUTH_EXPIRES_SECONDS', 900)), 120)
    return timedelta(seconds=seconds)


def _access_token_expiry_delta() -> timedelta:
    seconds = max(int(getattr(settings, 'API_ACCESS_TOKEN_EXPIRES_SECONDS', 900)), 120)
    return timedelta(seconds=seconds)


def _refresh_token_expiry_delta() -> timedelta:
    seconds = max(int(getattr(settings, 'API_REFRESH_TOKEN_EXPIRES_SECONDS', 2592000)), 3600)
    return timedelta(seconds=seconds)


def _generate_user_code() -> str:
    token = ''.join(secrets.choice(USER_CODE_ALPHABET) for _ in range(8))
    return f'{token[:4]}-{token[4:]}'


def _expire_stale_device_sessions(now: datetime) -> None:
    DeviceAuthSession.objects.filter(
        status__in=[DeviceAuthStatus.PENDING, DeviceAuthStatus.APPROVED],
        expires_at__lte=now,
    ).update(status=DeviceAuthStatus.EXPIRED)


def create_device_auth_session(*, install_hash: str) -> tuple[DeviceAuthSession, str]:
    now = timezone.now()
    _expire_stale_device_sessions(now)
    interval_seconds = _device_auth_interval_seconds()
    expires_at = now + _device_auth_expiry_delta()
    hashed_install = hash_install_identifier(install_hash)

    for _ in range(6):
        raw_device_code = secrets.token_urlsafe(48)
        user_code = _generate_user_code()

        try:
            session = DeviceAuthSession.objects.create(
                device_code_hash=hash_secret(raw_device_code),
                user_code=user_code,
                install_hash=hashed_install,
                status=DeviceAuthStatus.PENDING,
                interval_seconds=interval_seconds,
                expires_at=expires_at,
            )
            return session, raw_device_code
        except IntegrityError:
            continue

    raise RuntimeError('Could not allocate device authorization session.')


@transaction.atomic
def approve_device_auth_session(*, user_code: str, user) -> DeviceAuthSession:
    normalized_code = normalize_user_code(user_code)
    if not normalized_code:
        raise AuthServiceError('invalid_user_code', 'Enter a valid verification code.')

    now = timezone.now()
    _expire_stale_device_sessions(now)

    try:
        session = DeviceAuthSession.objects.select_for_update().get(user_code=normalized_code)
    except DeviceAuthSession.DoesNotExist as exc:
        raise AuthServiceError('invalid_user_code', 'The verification code was not found.') from exc

    if session.expires_at <= now:
        if session.status != DeviceAuthStatus.EXPIRED:
            session.status = DeviceAuthStatus.EXPIRED
            session.save(update_fields=['status'])
        raise AuthServiceError('expired_token', 'This verification code has expired.')

    if session.status == DeviceAuthStatus.PENDING:
        session.status = DeviceAuthStatus.APPROVED
        session.approved_by = user
        session.approved_at = now
        session.save(update_fields=['status', 'approved_by', 'approved_at'])
        return session

    if session.status == DeviceAuthStatus.APPROVED:
        return session

    if session.status == DeviceAuthStatus.CONSUMED:
        raise AuthServiceError('already_used', 'This verification code has already been used.')

    if session.status == DeviceAuthStatus.DENIED:
        raise AuthServiceError('access_denied', 'This verification request was denied.')

    raise AuthServiceError('expired_token', 'This verification code has expired.')


def issue_token_pair(*, user, install_hash: str, created_from_device: DeviceAuthSession | None = None) -> TokenPair:
    now = timezone.now()
    hashed_install = hash_install_identifier(install_hash)
    access_expires_at = now + _access_token_expiry_delta()
    refresh_expires_at = now + _refresh_token_expiry_delta()
    raw_access_token = secrets.token_urlsafe(48)
    raw_refresh_token = secrets.token_urlsafe(64)

    access_record = ApiAccessToken.objects.create(
        token_hash=hash_secret(raw_access_token),
        user=user,
        install_hash=hashed_install,
        expires_at=access_expires_at,
        created_from_device=created_from_device,
    )
    refresh_record = ApiRefreshToken.objects.create(
        token_hash=hash_secret(raw_refresh_token),
        user=user,
        install_hash=hashed_install,
        expires_at=refresh_expires_at,
        access_token=access_record,
        created_from_device=created_from_device,
    )

    return TokenPair(
        access_token=raw_access_token,
        access_token_expires_at=access_expires_at,
        refresh_token=raw_refresh_token,
        refresh_token_expires_at=refresh_expires_at,
        access_record=access_record,
        refresh_record=refresh_record,
    )


@transaction.atomic
def exchange_device_code_for_tokens(*, device_code: str, install_hash: str) -> TokenPair:
    now = timezone.now()
    _expire_stale_device_sessions(now)

    session_hash = hash_secret(device_code)
    try:
        session = DeviceAuthSession.objects.select_for_update().get(
            device_code_hash=session_hash,
        )
    except DeviceAuthSession.DoesNotExist as exc:
        raise AuthServiceError('invalid_device_code', 'Device authorization code is invalid.', HTTPStatus.UNAUTHORIZED) from exc

    hashed_install = hash_install_identifier(install_hash)
    if not secrets.compare_digest(session.install_hash, hashed_install):
        raise AuthServiceError('invalid_install', 'Install identifier mismatch.', HTTPStatus.UNAUTHORIZED)

    if session.expires_at <= now:
        if session.status != DeviceAuthStatus.EXPIRED:
            session.status = DeviceAuthStatus.EXPIRED
            session.save(update_fields=['status'])
        raise AuthServiceError('expired_token', 'Device authorization has expired.', HTTPStatus.UNAUTHORIZED)

    if session.status == DeviceAuthStatus.PENDING:
        raise AuthServiceError('authorization_pending', 'Authorization is still pending.', HTTPStatus.PRECONDITION_REQUIRED)

    if session.status == DeviceAuthStatus.DENIED:
        raise AuthServiceError('access_denied', 'Authorization request was denied.', HTTPStatus.UNAUTHORIZED)

    if session.status == DeviceAuthStatus.CONSUMED:
        raise AuthServiceError('authorization_consumed', 'Device authorization code has already been used.', HTTPStatus.UNAUTHORIZED)

    if session.status != DeviceAuthStatus.APPROVED or not session.approved_by_id:
        raise AuthServiceError('invalid_state', 'Device authorization session is in an invalid state.', HTTPStatus.UNAUTHORIZED)

    token_pair = issue_token_pair(
        user=session.approved_by,
        install_hash=install_hash,
        created_from_device=session,
    )
    session.status = DeviceAuthStatus.CONSUMED
    session.consumed_at = now
    session.save(update_fields=['status', 'consumed_at'])
    return token_pair


def get_valid_access_token(raw_access_token: str) -> ApiAccessToken | None:
    if not raw_access_token:
        return None

    now = timezone.now()
    token_hash = hash_secret(raw_access_token)
    return (
        ApiAccessToken.objects.select_related('user')
        .filter(token_hash=token_hash, revoked_at__isnull=True, expires_at__gt=now)
        .first()
    )


def mark_access_token_used(access_token: ApiAccessToken) -> None:
    ApiAccessToken.objects.filter(pk=access_token.pk).update(last_used_at=timezone.now())


@transaction.atomic
def refresh_access_token(*, refresh_token: str, install_hash: str) -> TokenPair:
    now = timezone.now()
    refresh_hash = hash_secret(refresh_token)

    try:
        refresh_record = ApiRefreshToken.objects.select_for_update().select_related(
            'user',
            'access_token',
        ).get(token_hash=refresh_hash)
    except ApiRefreshToken.DoesNotExist as exc:
        raise AuthServiceError('invalid_grant', 'Refresh token is invalid.', HTTPStatus.UNAUTHORIZED) from exc

    if refresh_record.revoked_at or refresh_record.expires_at <= now:
        raise AuthServiceError('invalid_grant', 'Refresh token is expired or revoked.', HTTPStatus.UNAUTHORIZED)

    hashed_install = hash_install_identifier(install_hash)
    if not secrets.compare_digest(refresh_record.install_hash, hashed_install):
        raise AuthServiceError('invalid_install', 'Install identifier mismatch.', HTTPStatus.UNAUTHORIZED)

    if refresh_record.access_token.revoked_at is None:
        refresh_record.access_token.revoked_at = now
        refresh_record.access_token.save(update_fields=['revoked_at'])

    token_pair = issue_token_pair(
        user=refresh_record.user,
        install_hash=install_hash,
        created_from_device=refresh_record.created_from_device,
    )
    refresh_record.revoked_at = now
    refresh_record.replaced_by = token_pair.refresh_record
    refresh_record.save(update_fields=['revoked_at', 'replaced_by'])
    return token_pair


@transaction.atomic
def revoke_install_tokens(*, user_id: int, install_hash: str) -> tuple[int, int]:
    now = timezone.now()
    access_revoked = ApiAccessToken.objects.filter(
        user_id=user_id,
        install_hash=install_hash,
        revoked_at__isnull=True,
    ).update(revoked_at=now)
    refresh_revoked = ApiRefreshToken.objects.filter(
        user_id=user_id,
        install_hash=install_hash,
        revoked_at__isnull=True,
    ).update(revoked_at=now)
    return access_revoked, refresh_revoked


@transaction.atomic
def delete_user_account(*, user_id: int) -> None:
    install_hashes = set(
        ApiAccessToken.objects.filter(user_id=user_id).values_list('install_hash', flat=True),
    )
    install_hashes.update(
        ApiRefreshToken.objects.filter(user_id=user_id).values_list('install_hash', flat=True),
    )
    install_hashes.update(
        DeviceAuthSession.objects.filter(approved_by_id=user_id).values_list('install_hash', flat=True),
    )

    if install_hashes:
        SeenSite.objects.filter(user_install_hash__in=install_hashes).delete()

    DeviceAuthSession.objects.filter(approved_by_id=user_id).delete()
    user_model = get_user_model()
    user_model._default_manager.filter(id=user_id).delete()
