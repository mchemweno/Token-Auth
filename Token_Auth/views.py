import os

from django.shortcuts import render
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode
from rest_framework import generics
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from Token_Auth.serializers import *


@api_view(['POST'])
def registration_view(request, *args, **kwargs):
    data = request.data
    serializer = RegistrationSerializer(data=data)

    if serializer.is_valid():
        user = serializer.save()
        token = Token.objects.get(user=user)
        response_data = {'success': 'Regsitration Success'}
        protocol = 'https://' if request.is_secure() else 'http://'
        web_url = protocol + request.get_host()
        subject = f'Account activation.'
        message = f' Follow the below link to activate your account {web_url}/auth/{user.email}/{token}'
        send_mail(subject, message, os.environ.get('EMAIL'), [user.email])
        return Response(data=response_data, status=200)
    else:
        return Response(serializer.errors, status=400)


class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": "Wrong password."}, status=400)
            # check if both passwords match
            if serializer.data.get("new_password") != serializer.data.get("re_new_password"):
                return Response({"new_password": "Passwords don't match."}, status=400)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': 200,
                'message': 'Password updated successfully'
            }
            return Response(response)
        return Response(serializer.errors, status=400)


@api_view(['GET'])
def activate_account(request, token, *args, **kwargs):
    try:
        user = User.objects.get(auth_token=token)
        user.is_active = True
        user.save()
        return Response(status=200)
    except User.DoesNotExist:
        return Response(status=400)


@api_view(['POST'])
def resend_activation_email(request, *args, **kwargs):
    try:
        data = request.data
        user = User.objects.get(email=data['email'])
        if user.is_active:
            return Response(status=400, data={'Error': 'User already active.'})
        token = Token.objects.get(user=user)
        response_data = {'success': 'Success'}
        protocol = 'https://' if request.is_secure() else 'http://'
        web_url = protocol + request.get_host()
        subject = f'Resend Activation Email.'
        message = f' Follow the below link to activate your account {web_url}/auth/{user.email}/{token}'
        send_mail(subject, message, os.environ.get('EMAIL'), [user.email])
        return Response(data=response_data, status=200)
        return Response(status=200)
    except User.DoesNotExist:
        return Response(status=400, data={'Error': 'User not found.'})


@api_view(['POST'])
def request_reset_password(request, *args, **kwargs):
    data = {'request': request, 'data': request.data}
    serializer = ResetPasswordEmailRequestSerializer(data=data['data'], context={'request': request})
    serializer.is_valid(True)
    return Response({'success': 'Success'}, status=200)


@api_view(['GET', 'POST'])
def password_token_check(request, uidb64, token):
    if request.method == 'GET':
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return render(request, 'Token_Auth/invalid_token.html')
            return render(request, 'Token_Auth/password_reset_form.html', {
                'uidb64': uidb64,
                'token': token
            })
        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user, token):
                return render(request, 'Token_Auth/invalid_token.html')
    else:
        try:
            data = request.data
            serializer = SetNewPasswordSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            return render(request, 'Token_Auth/password_reset_successful.html')
        except Exception as e:
            return render(request, 'Token_Auth/password_reset_unsuccessful.html', {
                'error': e
            })

