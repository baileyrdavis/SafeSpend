PYTHON ?= python

.PHONY: backend-test portal-build test compose-up compose-down

backend-test:
	cd backend && DJANGO_SETTINGS_MODULE=config.settings.test $(PYTHON) manage.py check && DJANGO_SETTINGS_MODULE=config.settings.test $(PYTHON) manage.py test

portal-build:
	cd portal && npm ci && npm run build

test: backend-test portal-build

compose-up:
	docker compose up --build

compose-down:
	docker compose down -v
