from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.db.models.constraints import UniqueConstraint
from django.db.models.deletion import CASCADE
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
    email = models.EmailField(unique=True, max_length=254)
    last_login = models.DateTimeField(blank = True, null = True)
    is_superuser = models.BooleanField(default= False)
    is_staff = models.BooleanField(default= True)
    is_active = models.BooleanField(default= False)
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

class Poll(models.Model):
    poll_id = models.AutoField(primary_key=True)
    poll_name = models.CharField(max_length=150)
    choices = [("0", "Inactive"), ("1", "Ongoing"), ("2", "Closed")]
    poll_status = models.CharField(max_length= 2, choices=choices)
    public_key = models.CharField(max_length=256)
    private_key_l = models.CharField(max_length=256)
    private_key_m = models.CharField(max_length=256)
    description = models.CharField(max_length =500, null=True)

    class Meta:
        managed = True
        db_table = 'poll'

    def __str__(self):
        return self.poll_name

class PollOptions(models.Model):
    option_id = models.AutoField(primary_key=True)
    option_num = models.IntegerField(null=True)
    option_name = models.CharField(max_length=150)
    poll_id = models.ForeignKey(Poll, on_delete=models.CASCADE)
    
    class Meta:
        managed = True
        db_table = 'poll_options'
        constraints = [
            models.UniqueConstraint(fields = ['option_id', 'option_name', 'option_num'], name ='option_id_name_num_unique')
        ]

    def __str__(self):
        return self.option_name

class UserVote(models.Model):
    poll_id = models.ForeignKey(Poll, on_delete=models.CASCADE)
    option_num = models.ForeignKey(PollOptions, on_delete=models.CASCADE)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    user_choice = models.IntegerField(default = 0)

    class Meta:
        managed = True
        db_table = 'user_vote'

class UserPoll(models.Model):
    poll_id = models.ForeignKey(Poll, on_delete=models.CASCADE)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        managed = True
        db_table = 'user_poll'
        constraints = [
            models.UniqueConstraint(fields = ['poll_id', 'user_id'], name ='userpoll_poll_user_id_unique')
        ]

class UserBallot(models.Model):
    poll_id = models.ForeignKey(Poll, on_delete=models.CASCADE)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    option_num = models.ForeignKey(PollOptions, on_delete=models.CASCADE)
    user_choice = models.CharField(max_length=256)

    class Meta:
        managed = True
        db_table = 'user_ballot'
        constraints = [
            models.UniqueConstraint(fields = ['poll_id', 'user_id', 'option_num'], name ='userballot_poll_user_id_option_unique')
        ]