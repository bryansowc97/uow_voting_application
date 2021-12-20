from django.http.response import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.contrib.auth import login, authenticate, get_user_model, logout
from django.contrib.auth.hashers import make_password, check_password
from .models import User
from .forms import RegisterUser, LoginUser
import string, random
from django.http import JsonResponse

# Create your views here.
def home(response):
    return render(response, "home.html")

def register_user(response):
    if response.method == "POST":
        form = RegisterUser(response.POST)

        if form.is_valid():
            username = form.cleaned_data["username"]
            email = form.cleaned_data["email"]
            firstname = form.cleaned_data["first_name"]
            lastname = form.cleaned_data["last_name"]
            password = form.cleaned_data["password1"]

            user = User()
            user.username = username
            user.email = email
            user.first_name = firstname
            user.last_name = lastname


            # Hashing of user's password using hashing library
            user.password = make_password(password)
            user.save()

            return HttpResponseRedirect("/account_created/")
    
    else:
        form = RegisterUser()

    return render(response, "register.html", {"form" : form})

def login_user(request):

    logout(request)
    username = password = ""

    if request.POST:
        form = LoginUser(request.POST)
        
        if form.is_valid():
            username = request.POST['username']
            password = request.POST['password']

            user = get_user_model()
        
            user = authenticate(username = username, password = password)

            if user is not None:
                if user.is_active:
                    login(request, user)
                    return HttpResponseRedirect('/home/')
    
    else:
        form = LoginUser()

    return render(request, "login.html", {"form" : form})

def post_registration(response):
    return render(response, "postregistration.html")

def account_details(response):
    return render(response, "accountdetail.html")

def logout_user(request):
    logout(request)
    return render(request, "logout.html")

def create_user(response):

    def generate_random_password():
        length = 8
        characters = string.ascii_letters + string.digits + string.punctuation

        password = "".join(random.choices(characters), length)

        return password

    if response.method == "POST":
        form = RegisterUser(response.POST)

        if form.is_valid():
            username = form.cleaned_data["username"]
            email = form.cleaned_data["email"]
            firstname = form.cleaned_data["first_name"]
            lastname = form.cleaned_data["last_name"]

            password = generate_random_password()

            user = User()
            user.username = username
            user.email = email
            user.first_name = firstname
            user.last_name = lastname

            # Hashing of user's password using hashing library
            user.password = make_password(password)
            user.save()

            return HttpResponseRedirect("/account_created/")
    
    else:
        form = RegisterUser()

def manage_user(response):
    all_user = User.objects.all()
    return render(response, "manageaccount.html", {"all_user" : all_user})

def get_user(request):
    all_user = User.objects.all()
    return JsonResponse({"all_user":list(all_user.values())})






    


