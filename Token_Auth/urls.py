from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token

from .views import resend_activation_email, registration_view, activate_account, ChangePasswordView, \
    password_token_check, request_reset_password

urlpatterns = [
    path('register/', registration_view),
    path('login/', obtain_auth_token),
    path('change_password', ChangePasswordView.as_view()),
    path('<str:user_email>/<str:token>', activate_account),
    path('resend_activation_email/', resend_activation_email),
    path('request_reset_password/', request_reset_password, name='request_reset_password'),
    path('password-reset/<str:uidb64>/<str:token>/',password_token_check, name='password-reset-token-validate')

]
