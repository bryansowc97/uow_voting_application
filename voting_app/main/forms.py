from django import forms

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

class CreateUser(forms.Form):
    username = forms.CharField(label = "Username", max_length = 150)
    first_name = forms.CharField(label = "First Name", max_length = 150)
    last_name = forms.CharField(label = "Last Name", max_length = 150)
    email = forms.CharField(label = "Email", max_length = 254)


