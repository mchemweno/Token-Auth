from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token


class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **kwargs):
        if username is None:
            raise TypeError('Users should have a username.')
        if email is None:
            raise TypeError('Users should have an Email.')
        user = self.model(username=username, email=self.normalize_email(email),**kwargs)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **kwargs):
        if username is None:
            raise TypeError('Users should have a username.')
        if email is None:
            raise TypeError('Users should have an Email.')
        if password is None:
            raise TypeError('Users should have a password.')

        user = self.create_user(username, email, password, **kwargs)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.save()
        return user


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(verbose_name='email', max_length=40, unique=True, null=False, blank=False)
    username = models.CharField(verbose_name='username', max_length=10, unique=True, db_index=True, null=False,
                                blank=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    phone = models.IntegerField(null=True, blank=True)
    first_name = models.CharField(null=False, blank=False, max_length=10)
    last_name = models.CharField(null=False, blank=False, max_length=10)

    REQUIRED_FIELDS = ['username']

    USERNAME_FIELD = 'email'

    # Tell django how to manage these objects
    objects = UserManager()

    def __str__(self):
        return 'Email: ' + self.email + '   Username: ' + self.username + '  Verified: ' + str(self.is_verified)


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
