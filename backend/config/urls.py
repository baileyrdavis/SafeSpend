from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('guard.urls')),
    path('auth/', include('guard.web_urls')),
]
