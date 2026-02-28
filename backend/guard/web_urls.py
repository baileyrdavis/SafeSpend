from django.urls import path

from guard.web_views import DeviceAuthVerifyView, SafeSpendLoginView, SafeSpendLogoutView, SafeSpendRegisterView

urlpatterns = [
    path('login', SafeSpendLoginView.as_view(), name='auth-login'),
    path('register', SafeSpendRegisterView.as_view(), name='auth-register'),
    path('logout', SafeSpendLogoutView.as_view(), name='auth-logout'),
    path('device/verify', DeviceAuthVerifyView.as_view(), name='device-verify'),
]
