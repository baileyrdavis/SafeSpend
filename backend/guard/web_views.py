from django.contrib.auth import login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import redirect
from django.shortcuts import render
from django.views import View

from guard.auth_service import AuthServiceError, approve_device_auth_session
from guard.forms import DeviceApprovalForm, EmailAuthenticationForm, ExtensionRegistrationForm


class SafeSpendLoginView(LoginView):
    template_name = 'guard/login.html'
    redirect_authenticated_user = True
    authentication_form = EmailAuthenticationForm


class SafeSpendLogoutView(LogoutView):
    next_page = '/auth/login'
    http_method_names = ['get', 'post', 'head', 'options']

    def get(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)


class SafeSpendRegisterView(View):
    template_name = 'guard/register.html'

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('/auth/device/verify')
        return render(request, self.template_name, {'form': ExtensionRegistrationForm()})

    def post(self, request):
        if request.user.is_authenticated:
            return redirect('/auth/device/verify')

        form = ExtensionRegistrationForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {'form': form})

        user = form.save()
        login(request, user)
        return redirect('/auth/device/verify')


class DeviceAuthVerifyView(LoginRequiredMixin, View):
    template_name = 'guard/device_verify.html'

    def get(self, request):
        initial_code = request.GET.get('user_code', '')
        normalized = (initial_code or '').strip()
        if normalized:
            try:
                session = approve_device_auth_session(
                    user_code=normalized,
                    user=request.user,
                )
            except AuthServiceError:
                # Fall back to manual form when provided code is invalid/expired.
                pass
            else:
                return render(
                    request,
                    self.template_name,
                    {
                        'form': DeviceApprovalForm(initial={'user_code': session.user_code}),
                        'approved': True,
                        'approved_code': session.user_code,
                    },
                )

        form = DeviceApprovalForm(initial={'user_code': initial_code})
        return render(request, self.template_name, {'form': form, 'approved': False})

    def post(self, request):
        form = DeviceApprovalForm(request.POST)
        if form.is_valid():
            try:
                session = approve_device_auth_session(
                    user_code=form.cleaned_data['user_code'],
                    user=request.user,
                )
            except AuthServiceError as error:
                form.add_error('user_code', error.message)
            else:
                return render(
                    request,
                    self.template_name,
                    {
                        'form': DeviceApprovalForm(initial={'user_code': session.user_code}),
                        'approved': True,
                        'approved_code': session.user_code,
                    },
                )

        return render(request, self.template_name, {'form': form, 'approved': False})
