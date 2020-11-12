from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.encoding import smart_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from Token_Auth.models import User
import os


class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'phone', 'first_name', 'last_name', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        validated_data.pop('password2')
        return User.objects.create_user(**validated_data)

    def validate(self, attrs):
        if attrs.get('password') != attrs.get('password2'):
            raise serializers.ValidationError({'password': 'password must match'})
        return super().validate(attrs)


class ChangePasswordSerializer(serializers.Serializer):
    model = User

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    re_new_password = serializers.CharField(required=True)


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']

    def validate(self, attrs, *args, **kwargs):
        email = attrs.get('email', '')
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError({'Email': 'User with this email does not exist.'})
        user = User.objects.get(email=email)
        request = self.context.get('request')
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        current_site = request.get_host()
        relative_link = reverse('password-reset-token-validate', kwargs={'uidb64': uidb64, 'token': token})
        protocol = 'https://' if request.is_secure() else 'http://'
        web_url = protocol + current_site + relative_link
        subject = f'Password Reset.'
        message = f' Follow the below link to reset your account {web_url}'
        send_mail(subject, message, os.environ.get('EMAIL'), [user.email])
        return super().validate(attrs)



class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'password2', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            if password != password2:
                raise serializers.ValidationError({'password': 'password must match'})

            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uid)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

        except Exception as e:
            raise e
        return super().validate(attrs)
