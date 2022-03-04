from distutils.command.upload import upload
from tkinter import Widget
from django import forms
from .models import User, Poll, PollOptions, UserVote

POLL_CHOICES = [("0", "Inactive"), ("1", "Ongoing"), ("2", "Closed")]

USER_STATUS_CHOICES = [("0", "Inactive"), ("1", "Active")]

class RegisterUser(forms.Form):
    username = forms.CharField(label = "Username", max_length = 150)
    first_name = forms.CharField(label = "First Name", max_length = 150)
    last_name = forms.CharField(label = "Last Name", max_length = 150)
    email = forms.CharField(label = "Email", max_length = 254)
    password1 = forms.CharField(label=("Password"), widget=forms.PasswordInput)
    password2 = forms.CharField(label=("Confirm Password"), widget=forms.PasswordInput)

class LoginUser(forms.Form):
    username = forms.CharField(label = "Username", max_length = 150)
    password = forms.CharField(label = "Password", max_length = 128, widget=forms.PasswordInput())

class CreateUser(forms.ModelForm):
    username = forms.CharField(label = "Username", max_length = 150)
    first_name = forms.CharField(label = "First Name", max_length = 150)
    last_name = forms.CharField(label = "Last Name", max_length = 150)
    email = forms.CharField(label = "Email", max_length = 254)
    is_active = forms.CharField(label =("Status"), widget=forms.HiddenInput, initial=True)

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "is_active"]

class UploadFileForm(forms.Form):
    file = forms.FileField()

class ChangePassword(forms.Form):
    oldpassword = forms.CharField(label=("Old Password"), widget=forms.PasswordInput)
    newpassword = forms.CharField(label=("New Password"), widget=forms.PasswordInput)
    newpassword2 = forms.CharField(label=("New Password2"), widget=forms.PasswordInput)

class ResetPassword(forms.Form):
    newpassword = forms.CharField(label=("New Password"), widget=forms.PasswordInput)
    newpassword2 = forms.CharField(label=("New Password2"), widget=forms.PasswordInput)

class UpdateUserDetail(forms.Form):
    username = forms.CharField(label = "Username", max_length = 150, widget=forms.TextInput(attrs={"readonly":"readonly"}))
    first_name = forms.CharField(label = "First Name", max_length = 150)
    last_name = forms.CharField(label = "Last Name", max_length = 150)
    email = forms.CharField(label = "Email", max_length = 254)

    def clean_email(self):
        email = self.cleaned_data.get("email")
        username = self.cleaned_data.get("username")

        current_user = User.objects.get(username = username)

        exclude_email_list = []

        if email == current_user.email:
            return email

        else:
            exclude_email = User.objects.exclude(email = current_user.email)

            for user in exclude_email:
                exclude_email_list.append(user.email)

            if email in exclude_email_list:
                raise forms.ValidationError('This email address is already in use, please provide a different email address.')
            else:
                return email
            

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email"]

class UpdateUser(forms.ModelForm):
    username = forms.CharField(label = "Username", max_length = 150)
    first_name = forms.CharField(label = "First Name", max_length = 150)
    last_name = forms.CharField(label = "Last Name", max_length = 150)
    email = forms.CharField(label = "Email", max_length = 254)
    is_active = forms.ChoiceField(label = ("Status"), choices=USER_STATUS_CHOICES)

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "is_active"]

class CreatePoll(forms.ModelForm):
    poll_name = forms.CharField(label = "Poll's Name", max_length = 150)
    poll_status = forms.ChoiceField(label = ("Status"), choices=POLL_CHOICES)
    description = forms.CharField(label = "Description", max_length = 500, widget=forms.Textarea, required=False)

    class Meta:
        model = Poll
        fields = ["poll_name", "poll_status", "description"]

class CreatePollOption(forms.ModelForm):
    option_name = forms.CharField(label = "Option Name", max_length = 150)
    option_num = forms.IntegerField(label = "Option Num")

    class Meta:
        model = PollOptions
        fields = ["option_num", "option_name"]
        widgets = {
            "option_num": forms.HiddenInput()
        }

class AddUserToPoll(forms.Form):
    username = forms.CharField(label = "Username", max_length = 150)
    first_name = forms.CharField(label = "First Name", max_length = 150)
    last_name = forms.CharField(label = "Last Name", max_length = 150)
    invited = forms.BooleanField(label = "Invited")

class UpdatePoll(forms.ModelForm):
    poll_name = forms.CharField(label = "Poll Name", max_length = 150)
    poll_status = forms.ChoiceField(label = ("Status"), choices=POLL_CHOICES)
    description = forms.CharField(label = "Description", max_length = 500, widget=forms.Textarea, required=False)

    class Meta:
        model = Poll
        fields = ["poll_name", "poll_status", "description"]