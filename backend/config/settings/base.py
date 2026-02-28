import os
from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parents[2]

env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, ['localhost', '127.0.0.1']),
    CORS_ALLOW_ALL_ORIGINS=(bool, False),
    API_REQUIRE_AUTH=(bool, False),
    API_THROTTLE_SCAN=(str, '120/minute'),
    API_THROTTLE_TELEMETRY=(str, '240/minute'),
    API_THROTTLE_LOOKUP=(str, '180/minute'),
    API_THROTTLE_RESCAN=(str, '30/minute'),
    API_THROTTLE_AUTH_START=(str, '20/minute'),
    API_THROTTLE_AUTH_POLL=(str, '60/minute'),
    API_THROTTLE_AUTH_REFRESH=(str, '30/minute'),
    API_THROTTLE_DEFAULT=(str, '180/minute'),
    DEVICE_AUTH_EXPIRES_SECONDS=(int, 900),
    DEVICE_AUTH_INTERVAL_SECONDS=(int, 5),
    API_ACCESS_TOKEN_EXPIRES_SECONDS=(int, 900),
    API_REFRESH_TOKEN_EXPIRES_SECONDS=(int, 2592000),
    EMAIL_BACKEND=(str, 'django.core.mail.backends.smtp.EmailBackend'),
    EMAIL_HOST=(str, 'smtp.postmarkapp.com'),
    EMAIL_PORT=(int, 587),
    EMAIL_USE_TLS=(bool, True),
    EMAIL_USE_SSL=(bool, False),
    EMAIL_HOST_USER=(str, ''),
    EMAIL_HOST_PASSWORD=(str, ''),
)

environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

SECRET_KEY = env('DJANGO_SECRET_KEY', default='django-insecure-change-me')
DEBUG = env('DEBUG')
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS')
APP_VERSION = env('APP_VERSION', default='0.1.0')
API_AUTH_TOKEN = env('API_AUTH_TOKEN', default='')
API_REQUIRE_AUTH = env('API_REQUIRE_AUTH')
GUARD_FEEDBACK_EMAIL = env('GUARD_FEEDBACK_EMAIL', default='')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default='noreply@safespend.local')
EMAIL_BACKEND = env('EMAIL_BACKEND')
EMAIL_HOST = env('EMAIL_HOST')
EMAIL_PORT = env.int('EMAIL_PORT')
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS')
EMAIL_USE_SSL = env.bool('EMAIL_USE_SSL')
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
DEVICE_AUTH_EXPIRES_SECONDS = env.int('DEVICE_AUTH_EXPIRES_SECONDS')
DEVICE_AUTH_INTERVAL_SECONDS = env.int('DEVICE_AUTH_INTERVAL_SECONDS')
API_ACCESS_TOKEN_EXPIRES_SECONDS = env.int('API_ACCESS_TOKEN_EXPIRES_SECONDS')
API_REFRESH_TOKEN_EXPIRES_SECONDS = env.int('API_REFRESH_TOKEN_EXPIRES_SECONDS')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'guard',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

DATABASES = {
    'default': env.db_url(
        'DATABASE_URL',
        default='sqlite:///db.sqlite3',
    ),
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STORAGES = {
    'default': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
    },
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage',
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'guard.throttles.GuardScopedRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'scan': env('API_THROTTLE_SCAN'),
        'telemetry': env('API_THROTTLE_TELEMETRY'),
        'lookup': env('API_THROTTLE_LOOKUP'),
        'rescan': env('API_THROTTLE_RESCAN'),
        'auth_start': env('API_THROTTLE_AUTH_START'),
        'auth_poll': env('API_THROTTLE_AUTH_POLL'),
        'auth_refresh': env('API_THROTTLE_AUTH_REFRESH'),
        'default': env('API_THROTTLE_DEFAULT'),
    },
}

CORS_ALLOW_ALL_ORIGINS = env('CORS_ALLOW_ALL_ORIGINS')
CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=[])
CSRF_TRUSTED_ORIGINS = env.list('CSRF_TRUSTED_ORIGINS', default=[])

DATA_UPLOAD_MAX_MEMORY_SIZE = env.int('DATA_UPLOAD_MAX_MEMORY_SIZE', default=1048576)
FILE_UPLOAD_MAX_MEMORY_SIZE = env.int('FILE_UPLOAD_MAX_MEMORY_SIZE', default=1048576)

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
X_FRAME_OPTIONS = 'DENY'
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
LOGIN_URL = '/auth/login'
LOGIN_REDIRECT_URL = '/auth/device/verify'

if env('R2_BUCKET_NAME', default=''):
    AWS_ACCESS_KEY_ID = env('R2_ACCESS_KEY_ID', default='')
    AWS_SECRET_ACCESS_KEY = env('R2_SECRET_ACCESS_KEY', default='')
    AWS_STORAGE_BUCKET_NAME = env('R2_BUCKET_NAME', default='')
    AWS_S3_REGION_NAME = 'auto'
    AWS_S3_ENDPOINT_URL = env('R2_ENDPOINT_URL', default='')
    AWS_S3_ADDRESSING_STYLE = 'virtual'
    AWS_QUERYSTRING_AUTH = False
    STORAGES = {
        'default': {
            'BACKEND': 'storages.backends.s3.S3Storage',
        },
        'staticfiles': {
            'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage',
        },
    }

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': env('LOG_LEVEL', default='INFO'),
    },
}
