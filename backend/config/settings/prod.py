from .base import *  # noqa: F401,F403

DEBUG = False
API_REQUIRE_AUTH = env.bool('API_REQUIRE_AUTH', default=True)

if SECRET_KEY == 'django-insecure-change-me':
    raise RuntimeError('DJANGO_SECRET_KEY must be set in production.')
if CORS_ALLOW_ALL_ORIGINS:
    raise RuntimeError('CORS_ALLOW_ALL_ORIGINS must be False in production.')

SECURE_SSL_REDIRECT = env.bool('SECURE_SSL_REDIRECT', default=True)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = env.int('SECURE_HSTS_SECONDS', default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
