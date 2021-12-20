from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

# Create your models here.
class AccountManager(BaseUserManager):

    def create_superuser(self, username, password, email, **other_fields):

        other_fields.setdefault('is_staff', 1)
        other_fields.setdefault('is_superuser', 1)
        other_fields.setdefault('is_active', 1)


        return self.create_user(username, password, email, **other_fields)

    def create_user(self, username, password, email, **other_fields):
        
        user = self.model(username = username, email = email, **other_fields)
        user.set_password(password)
        user.save()
        return user

class User(AbstractBaseUser, PermissionsMixin):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(unique=True, max_length=150)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    password = models.CharField(max_length=128)
    email = models.CharField(unique=True, max_length=254)
    last_login = models.DateTimeField(blank = True, null = True)
    is_superuser = models.IntegerField(default = 0)
    is_staff = models.IntegerField(default = 1)
    is_active = models.IntegerField(default = 1)
    date_joined = models.DateTimeField(default = timezone.now)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['password', 'email']

    objects = AccountManager()

    class Meta:
        managed = True
        db_table = 'user'
        unique_together = (('username', 'email'),)
    

    def __str__(self):
        return self.username