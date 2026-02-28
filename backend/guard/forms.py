from django import forms

from guard.auth_service import normalize_user_code


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
