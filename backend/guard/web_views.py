from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import render
from django.views import View

from guard.auth_service import AuthServiceError, approve_device_auth_session
from guard.forms import DeviceApprovalForm, EmailAuthenticationForm


class SafeSpendLoginView(LoginView):
    template_name = 'guard/login.html'
    redirect_authenticated_user = True
    authentication_form = EmailAuthenticationForm


class SafeSpendLogoutView(LogoutView):
    next_page = '/auth/login'
    http_method_names = ['get', 'post', 'head', 'options']

    def get(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)


class DeviceAuthVerifyView(LoginRequiredMixin, View):
    template_name = 'guard/device_verify.html'

    def get(self, request):
        initial_code = request.GET.get('user_code', '')
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
