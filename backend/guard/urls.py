from django.urls import path

from guard import views

urlpatterns = [
    path('auth/device/start', views.DeviceAuthStartAPIView.as_view(), name='auth-device-start-api'),
    path('auth/device/poll', views.DeviceAuthPollAPIView.as_view(), name='auth-device-poll-api'),
    path('auth/token/refresh', views.TokenRefreshAPIView.as_view(), name='auth-token-refresh-api'),
    path('auth/session', views.AuthSessionAPIView.as_view(), name='auth-session-api'),
    path('auth/logout', views.LogoutAPIView.as_view(), name='auth-logout-api'),
    path('scan', views.ScanAPIView.as_view(), name='scan-api'),
    path('site/<str:domain>', views.SiteDetailAPIView.as_view(), name='site-detail-api'),
    path('site/<str:domain>/rescan', views.SiteRescanAPIView.as_view(), name='site-rescan-api'),
    path('sites', views.SiteListAPIView.as_view(), name='site-list-api'),
    path('telemetry/seen', views.SeenTelemetryAPIView.as_view(), name='seen-telemetry-api'),
    path('health', views.HealthAPIView.as_view(), name='health-api'),
]
