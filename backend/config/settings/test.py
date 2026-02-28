from .base import *  # noqa: F401,F403

DEBUG = False
API_REQUIRE_AUTH = False
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Keep tests isolated from external mail providers.
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
