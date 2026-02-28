$ErrorActionPreference = "Stop"

Write-Host "Running backend checks and tests..."
Push-Location (Join-Path $PSScriptRoot "..\backend")
try {
  $env:DJANGO_SETTINGS_MODULE = "config.settings.test"
  python -m pip install -r requirements.txt
  python manage.py check
  python manage.py makemigrations --check --dry-run
  python manage.py test
} finally {
  Remove-Item Env:\DJANGO_SETTINGS_MODULE -ErrorAction SilentlyContinue
  Pop-Location
}

Write-Host "All checks complete."
