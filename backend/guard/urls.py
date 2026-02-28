from django.urls import path

from guard import views

urlpatterns = [
    path('scan', views.ScanAPIView.as_view(), name='scan-api'),
    path('site/<str:domain>', views.SiteDetailAPIView.as_view(), name='site-detail-api'),
    path('site/<str:domain>/rescan', views.SiteRescanAPIView.as_view(), name='site-rescan-api'),
    path('sites', views.SiteListAPIView.as_view(), name='site-list-api'),
    path('telemetry/seen', views.SeenTelemetryAPIView.as_view(), name='seen-telemetry-api'),
    path('health', views.HealthAPIView.as_view(), name='health-api'),
]
