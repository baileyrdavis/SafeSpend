from django import forms
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import gettext_lazy as _

from guard.auth_service import normalize_user_code


class EmailAuthenticationForm(AuthenticationForm):
    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(
            attrs={
                'autofocus': True,
                'autocomplete': 'email',
                'placeholder': 'you@example.com',
            },
        ),
    )
    username = forms.CharField(required=False, widget=forms.HiddenInput)

    def clean(self):
        email = (self.cleaned_data.get('email') or '').strip()
        password = self.cleaned_data.get('password')

        if email and password:
            user_model = get_user_model()
            email_lookup = {f'{user_model.EMAIL_FIELD}__iexact': email}
            user = user_model._default_manager.filter(**email_lookup).first()
            username = getattr(user, user_model.USERNAME_FIELD) if user else email

            self.user_cache = authenticate(self.request, username=username, password=password)
            if self.user_cache is None:
                raise forms.ValidationError(
                    self.error_messages['invalid_login'],
                    code='invalid_login',
                    params={'username': _('email')},
                )
            self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data


class DeviceApprovalForm(forms.Form):
    user_code = forms.CharField(
        max_length=16,
        label='Verification code',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'ABCD-EFGH',
                'autocomplete': 'one-time-code',
                'autocapitalize': 'characters',
            },
        ),
    )

    def clean_user_code(self) -> str:
        value = self.cleaned_data.get('user_code', '')
        normalized = normalize_user_code(value)
        if not normalized:
            raise forms.ValidationError('Enter the 8-character verification code from the extension.')
        return normalized
