from django.urls import path

from guard.web_views import DeviceAuthVerifyView, SafeSpendLoginView, SafeSpendLogoutView

urlpatterns = [
    path('login', SafeSpendLoginView.as_view(), name='auth-login'),
    path('logout', SafeSpendLogoutView.as_view(), name='auth-logout'),
    path('device/verify', DeviceAuthVerifyView.as_view(), name='device-verify'),
]
