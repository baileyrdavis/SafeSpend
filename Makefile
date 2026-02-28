PYTHON ?= python

.PHONY: backend-test test compose-up compose-down

backend-test:
	cd backend && DJANGO_SETTINGS_MODULE=config.settings.test $(PYTHON) manage.py check && DJANGO_SETTINGS_MODULE=config.settings.test $(PYTHON) manage.py makemigrations --check --dry-run && DJANGO_SETTINGS_MODULE=config.settings.test $(PYTHON) manage.py test

test: backend-test

compose-up:
	docker compose up --build

compose-down:
	docker compose down -v
