from django.apps import AppConfig


class GuardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'guard'

    def ready(self):
        from guard import signals  # noqa: F401
