from .base import *  # noqa: F401,F403

DEBUG = True
ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'backend']
CORS_ALLOW_ALL_ORIGINS = True
API_REQUIRE_AUTH = False
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# Avoid SMTP dependency during local development.
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
