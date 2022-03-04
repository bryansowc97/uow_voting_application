from base64 import urlsafe_b64decode, urlsafe_b64encode
from email import message
import math
from re import I
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.views.decorators.csrf import csrf_exempt
from django.http.response import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth import login, authenticate, get_user_model, logout
from django.contrib.auth.hashers import make_password, check_password
from .models import PollOptions, User, Poll,  UserPoll, UserBallot, UserVote
from .forms import ChangePassword, CreatePoll, CreateUser, RegisterUser, LoginUser, ResetPassword, UpdatePoll, UpdateUser, UpdateUserDetail, UploadFileForm
from django.template.loader import render_to_string
import string, random
from django.http import JsonResponse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import json
from django.contrib import messages
from fhe import paillier
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from .tokens import account_activation_token, password_reset_token
from django.contrib.auth.decorators import login_required
import csv

# Create your views here.

def login_index(request):
    logout(request)
    username = password = ""

    if request.POST:
        form = LoginUser(request.POST)

        if form.is_valid():
            username = request.POST['username']
            password = request.POST['password']

            try:
                user = User.objects.get(username = username)

                if user.is_active:
    
                    user = get_user_model()
            
                    user = authenticate(username = username, password = password)

                    if user is not None:
                        login(request, user)
                        return HttpResponseRedirect('/home/')
                
                    else:
                        return HttpResponseRedirect('login_failed/')

                else:
                    return HttpResponseRedirect("/account_not_activated/")

            except User.DoesNotExist:
                return HttpResponseRedirect('login_failed/')
                
        else:
            return HttpResponseRedirect('login_failed/')
        
    else:
        form = LoginUser()
        
    return render(request, "index.html", {"form":form})

def login_failed(request):

    message = "Login failed, Wrong Username or Password!"

    logout(request)
    username = password = ""

    if request.POST:
        form = LoginUser(request.POST)

        context = {
            "form":form,
            "message":message
        }

        if form.is_valid():
            username = request.POST['username']
            password = request.POST['password']

            try:
                user = User.objects.get(username = username)
                
                if user.is_active:
    
                    user = get_user_model()
            
                    user = authenticate(username = username, password = password)

                    if user is not None:
                        login(request, user)
                        return HttpResponseRedirect('/home/')
                
                    else:
                        return HttpResponseRedirect('/login_failed/')

                else:
                    return HttpResponseRedirect("/account_not_activated/")

            except User.DoesNotExist:
                return HttpResponseRedirect('/login_failed/')

                
        else:
            return HttpResponseRedirect('/login_failed/')

    else:
        form = LoginUser()

        context = {
            "form":form,
            "message":message
        }
        
    return render(request, "index.html", context)

def account_not_activated(request):
    return render(request, "account_not_activated.html")


def home(request):
    #random_voter_vote()
    return render(request, "home.html")

def reset_password_page(request):

    if request.method == "POST":

        to_email = []

        input_email = request.POST.get("email")

        try:
            validate_email(input_email)

            to_email.append(input_email)

            user = User.objects.get(email = input_email)
            current_site = get_current_site(request)
            domain = current_site.domain
            uid = urlsafe_b64encode(force_bytes(user.pk)).decode()
            token = password_reset_token.make_token(user)
            email_subject = "Reset Password"

            context={
                "user":user,
                "domain":domain,
                "uid":uid,
                "token":token,
            }

            message = render_to_string("reset_password_email_format.html", context)

            email = EmailMessage(
                email_subject,
                message,
                "noreply@semycolon.com",
                to_email,
            )

            email.send(fail_silently=False)

            messages.success(request,"Email has been sent to the email provided")
            
        except ValidationError as e:
            messages.error(request, "Please enter a valid email address")

            return HttpResponseRedirect("/reset_password_page/")

        except User.DoesNotExist:

            messages.error(request, "An account with that email does not exists")

            return HttpResponseRedirect("/reset_password_page/")
        

    return render(request, "reset_password.html")

def reset_password(request, uidb64, token):

    uid = force_text(urlsafe_b64decode(uidb64))
    user = User.objects.get(pk = uid)
    
    form = ResetPassword()

    if password_reset_token.check_token(user, token):
        
        if request.method == "POST":
            form = ResetPassword(request.POST)

            if form.is_valid():
                newpassword = form.cleaned_data["newpassword"]
                newpassword2 = form.cleaned_data["newpassword2"]

                if newpassword == newpassword2:
        
                    # Change the user password to the new password
                    user.password = make_password(newpassword)

                    # Updates it into the database
                    user.save()

                    return HttpResponseRedirect("/reset_password_sucesss/")
            
                else:
                    messages.error(request, "Password change failed, password mismatch!")

            else:
                messages.error(request, "Password change failed, password mismatch!")

        return render(request, "reset_password_email.html", {"form":form})
    
    else:
        return HttpResponseRedirect("/email_link_expired/")

def reset_password_sucesss(request):
    return render(request, "reset_password_success.html")


def email_link_expired(request):
    return render(request, "email_link_expired.html")

def register_user(request):
    
    if request.method == "POST":

        form = RegisterUser(request.POST)

        if form.is_valid():
            username = form.cleaned_data["username"]
            email = form.cleaned_data["email"]
            firstname = form.cleaned_data["first_name"]
            lastname = form.cleaned_data["last_name"]
            password2 = form.cleaned_data["password2"]

            user = User()
            user.username = username
            user.email = email
            user.first_name = firstname
            user.last_name = lastname

            # Hashing of user's password using hashing library
            user.set_password(make_password(password2))
            user.save()

            token = account_activation_token.make_token(user)
            email_subject = "Account activation"
            current_site = get_current_site(request)
            domain = current_site.domain
            uid = urlsafe_b64encode(force_bytes(user.pk)).decode()

            context={
                "user":user,
                "domain":domain,
                "uid":uid,
                "token":token,
            }

            message = render_to_string("activate_email_format.html", context)

            email = EmailMessage(
                email_subject,
                message,
                "noreply@semycolon.com",
                [email],
            )

            email.send(fail_silently=False)

            return HttpResponseRedirect("/account_created/")
        
    else:
        form = RegisterUser()

    return render(request, "register.html", {"form" : form})

def activate_account(request, uidb64, token):

    uid = force_text(urlsafe_b64decode(uidb64))
    user = User.objects.get(pk = uid)

    if account_activation_token.check_token(user, token):

        user.is_active = 1

        user.save()

        return HttpResponseRedirect("/activate_account_success/")
    
    else:
        return HttpResponseRedirect("/email_link_expired/")

def activate_account_success(request):
    return render(request,"activate_account_success.html")

@csrf_exempt
def usernameValidation(request):

    if request.method == "POST":
        data = json.loads(request.body)
        username = data["username"]

        if not str(username).isalnum():
            return JsonResponse({"username_error": "Username should contain only alphanumeric characters!"}, status=400)

        if User.objects.filter(username = username).exists():
            return JsonResponse({"username_error": "Username is in use!"}, status=409)
        
        return JsonResponse({"username_valid": True})

@csrf_exempt
def emailValidation(request):

    if request.method == "POST":
        data = json.loads(request.body)
        email = data["email"]

        if User.objects.filter(email = email).exists():
                return JsonResponse({"email_error": "Email is in use!"}, status= 409)

        try:
            validate_email(email)
        except ValidationError as e:
            return JsonResponse({"email_error": "Email is invalid!"}, status= 400)

        return JsonResponse({"email_valid": True})
            

def post_registration(request):
    return render(request, "post_registration.html")

@login_required
def update_user_detail(request):

    current_user = request.user

    initial_dict ={
        "username": current_user.username,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "email": current_user.email,
        "current_user": current_user
    }

    if request.method == "POST":

        form = UpdateUserDetail(request.POST)

        if form.is_valid():

            username = form.cleaned_data["username"]
            firstname = form.cleaned_data["first_name"]
            lastname = form.cleaned_data["last_name"]
            email = form.clean_email()

            current_user.username = username
            current_user.first_name = firstname
            current_user.last_name = lastname
            current_user.email = email
            
            current_user.save()

            messages.success(request, "Form submission successful")

            return HttpResponseRedirect("/account_details/")

    else:
        form = UpdateUserDetail(initial=initial_dict)

    return render(request, "account_detail.html", {"form":form})

@login_required
def change_password(request):

    if request.method == "POST":
        form = ChangePassword(request.POST)

        # Get the current login user
        current_user = request.user

        if form.is_valid():

            oldpassword = form.cleaned_data["oldpassword"]
            newpassword = form.cleaned_data["newpassword"]
            newpassword2 = form.cleaned_data["newpassword2"]

            checkvalid = check_password(oldpassword, current_user.password)

            if checkvalid:
                if newpassword == newpassword2:

                    # Change the user password to the new password
                    current_user.password = make_password(newpassword)

                    # Updates it into the database
                    current_user.save()
                    return HttpResponseRedirect("/change_password/success/")
                    
                else:
                    messages.error(request, "Password change failed, current password or password mismatch!")
                    return HttpResponseRedirect("/change_password/")
            else:
                messages.error(request, "Password change failed, current password or password mismatch!")
                return HttpResponseRedirect("/change_password/")
    else:
        form = ChangePassword()

    return render(request, "change_password.html", {"form":form})

def password_changed_successfully(request):
    return render(request, "change_password_success.html")

@login_required
def logout_user(request):
    logout(request)
    return render(request, "logout.html")

@login_required
def user_list(request):
    users_list = User.objects.filter(is_superuser = 0).order_by("user_id")
    page = request.GET.get('page', 1)

    paginator = Paginator(users_list, 10)

    try:
        users = paginator.page(page)

    except PageNotAnInteger:
        users = paginator.page(1)

    except EmptyPage:
        users = paginator.page(paginator.num_pages)

    context ={
        "users" : users
    }

    return render (request, "manage_account.html", context)

def add_user(request):

    def generate_random_password():
        length = 8
        characters = string.ascii_letters + string.digits + string.punctuation

        password = "".join(random.choice(characters) for i in range(length))

        return password

    if (request.method =="POST"):
        form = CreateUser(request.POST)
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
            user.is_active = True
            # Hashing of user's password using hashing library
            user.password = make_password(password)
            user.save()

            email_subject = "Account created by admin"
            current_site = get_current_site(request)
            domain = current_site.domain

            context ={
                "username":username,
                "domain":domain,
                "password":password
            }

            message = render_to_string("send_user_password_format.html", context)

            email = EmailMessage(
                email_subject,
                message,
                "noreply@semycolon.com",
                [email],
            )

            

            email.send(fail_silently=False)
    else:
        form = CreateUser()

    return user_save_all(request, form, "create_account.html")

def create_multiple_user(request):

    def generate_random_password():
        length = 8
        characters = string.ascii_letters + string.digits + string.punctuation

        password = "".join(random.choice(characters) for i in range(length))

        return password

    if request.method == "POST":

        csv_file = request.FILES["csv_file"]

        file_data = csv_file.read().decode("utf-8")
        
        lines = file_data.split("\n")

        lines.pop(0)

        existing_username_list = []
        existing_email_list = []
        count = 0

        for line in lines:
            if line != "":
                user = User()
                fields = line.split(",")

                for field in fields:
                    if field == "":
                        print("Invalid data")

                username = fields[0]
                firstname = fields[1]
                lastname = fields[2]
                email = fields[3].strip("\r")

                exist_username = User.objects.filter(username = username)
                exist_email = User.objects.filter(email = email)
            
                if exist_email and exist_username:
                    existing_username_list.append(username)
                    existing_email_list.append(email)
                
                elif exist_email:
                    existing_email_list.append(email)

                elif exist_username:
                    existing_username_list.append(username)

                else:
                    password = generate_random_password()
                    user.username = username
                    user.password = make_password(password)
                    user.first_name = firstname
                    user.last_name  = lastname
                    user.email = email
                    user.is_active = True
                    user.save()
                    count += 1

                    # Only works if the emails provided are actual real emails, not dummy emails
                    """
                    email_subject = "Account created by admin"
                    current_site = get_current_site(request)
                    domain = current_site.domain

                    context ={
                        "username":username,
                        "domain":domain,
                        "password": password
                    }

                    message = render_to_string("send_user_password_format.html", context)

                    email = EmailMessage(
                        email_subject,
                        message,
                        "noreply@semycolon.com",
                        [email],
                    )

                    email.send(fail_silently=False)
                    """
      
                    

        if bool(existing_username_list) == True or bool(existing_email_list) == True:


            context = {
                "existing_username_list":existing_username_list,
                "existing_email_list":existing_email_list
            }

            return render(request, "csv_upload_fail.html", context)

        else:
            update_text = "{} Records successfully created.".format(count)
            messages.success(request, update_text)
            return HttpResponseRedirect("/manage_account/")

    data = render_to_string("create_multiple_account.html", request=request)
    return JsonResponse(data, safe=False)

def update_user(request, user_id):

    user = get_object_or_404(User, user_id = user_id)

    if (request.method == "POST"):
        form = UpdateUser(request.POST, instance = user)
    else:
        form = UpdateUser(instance = user)
    
    return user_save_all(request, form, "update_user.html")

def user_save_all(request, form, template_name):
    data = dict()
    if request.method == 'POST':
        if form.is_valid():
            form.save()
            data['form_is_valid'] = True
            
            user_list = User.objects.all()
            username = request.POST.get("username")
            index = 0

            for i in range(0, len(user_list)):
                if (user_list[i].username == username):
                    index = i

            rounduppage = math.ceil(index/10)*10

            if index <= 10:
                users = User.objects.filter(is_superuser = 0)[:rounduppage]
            else:
                users = User.objects.filter(is_superuser = 0)[rounduppage-10:rounduppage]

            data['user_list'] = render_to_string('manage_account2.html',{'users':users})
        else:
            data['form_is_valid'] = False
    context = {
	    'form':form
	    }
    
    data['html_form'] = render_to_string(template_name,context,request=request)
    return JsonResponse(data)

@login_required
def delete_user(request, user_id):
    user = User.objects.get(user_id = user_id)
    user_list = User.objects.filter(is_superuser = 0)
    index = 0
    username = str(User.objects.filter(user_id = user.user_id)[0])
    for i in range(0, len(user_list)):
        if user_list[i].username == username:
            index = i
    if (index%10 == 0):
        rounduppage = math.ceil(index/10) + 1
    else:
        rounduppage = math.ceil(index/10)
    user.delete()
    return redirect("/manage_account/?page=" + str(rounduppage))

@login_required
def view_poll(request):

    polls = Poll.objects.all()

    userpolllist = []
    uservotedlist = []

    for poll in polls:
        userpoll = UserPoll.objects.filter(poll_id = poll.poll_id)

        # Filter by poll id, then get all distinct value of user_id
        userballot = UserBallot.objects.filter(poll_id = poll.poll_id).values("user_id").distinct()

        userpolllist.append(userpoll.count())
        uservotedlist.append(userballot.count())

    context = {
        "polls":polls,
        "userpolllist":userpolllist,
        "uservotedlist":uservotedlist
    }

    return render(request, "view_poll.html", context)

@login_required
def sort_account(request):
    
    sortby = request.GET.get("sortby")
    
    users_list = User.objects.filter(is_superuser = 0).order_by(sortby)

    page = request.GET.get('page', 1)

    paginator = Paginator(users_list, 10)

    try:
        users = paginator.page(page)

    except PageNotAnInteger:
        users = paginator.page(1)

    except EmptyPage:
        users = paginator.page(paginator.num_pages)

    context ={
        "users" : users,
        "sortby": sortby
    }

    return render (request, "sort_account.html", context)

@login_required
def search_account(request):

    search = request.GET.get("search")

    users_lists = []

    users_username_list = User.objects.filter(is_superuser = 0).filter(username__contains = search)
    users_first_name_list = User.objects.filter(is_superuser = 0).filter(first_name__contains = search)
    users_last_name_list = User.objects.filter(is_superuser = 0).filter(last_name__contains = search)
    users_email_list = User.objects.filter(is_superuser = 0).filter(email__contains = search)

    for user in users_username_list:
        users_lists.append(user)
    
    for user in users_first_name_list:
        users_lists.append(user)

    for user in users_last_name_list:
        users_lists.append(user)

    for user in users_email_list:
        users_lists.append(user)

    # Remove duplicates
    users_lists = list(dict.fromkeys(users_lists))

    page = request.GET.get('page', 1)

    paginator = Paginator(users_lists, 10)

    try:
        users = paginator.page(page)

    except PageNotAnInteger:
        users = paginator.page(1)

    except EmptyPage:
        users = paginator.page(paginator.num_pages)

    context ={
        "users" : users,
        "search": search,
    }

    return render(request, "search_account.html", context)

@login_required
def filter_account(request):

    filterby = request.GET.get("filterby")
    
    if filterby == "active":
        filterby = True
    else:
        filterby = False

    users_list = User.objects.filter(is_superuser = 0).filter(is_active = filterby).order_by("user_id")

    page = request.GET.get('page', 1)

    paginator = Paginator(users_list, 10)

    try:
        users = paginator.page(page)

    except PageNotAnInteger:
        users = paginator.page(1)

    except EmptyPage:
        users = paginator.page(paginator.num_pages)

    context ={
        "users" : users,
        "filterby": filterby
    }

    return render (request, "filter_account.html", context)

# Display polls details
@login_required
def poll_detail_view(request, poll_id):
    obj = get_object_or_404(Poll, poll_id = poll_id)
    context = {
        "obj":obj,
    }
    return render(request, "viewpolldetail.html", context)

# Create poll
def create_poll(request):
    # Count for number of options
    counter = 1

    data = {}

    if request.method == "POST":
        
        poll_form = CreatePoll(request.POST)
        
        if poll_form.is_valid():

            # Create a poll model
            poll = Poll()

            # Set all the attribute of the poll model
            poll_name = poll_form.cleaned_data["poll_name"]
            poll_status = poll_form.cleaned_data["poll_status"]
            poll_description = poll_form.cleaned_data["description"]
            poll.poll_name = poll_name
            poll.poll_status = poll_status
            poll.description = poll_description

            priv, pub = paillier.generate_keypair(128)

            poll.private_key_l = priv[0]
            poll.private_key_m = priv[1]
            poll.public_key = pub

            # Save the poll into the database
            poll.save()

            # Get all user input with the name option
            optionlist = request.POST.getlist("option")

            for option in optionlist:
                polloptions = PollOptions()
                polloptions.option_num = counter
                polloptions.option_name = option
                polloptions.poll_id = poll
                counter += 1
                polloptions.save()

            messages.success(request, "Poll has been created.")

            return HttpResponseRedirect("/view_poll/")
    else:
        poll_form = CreatePoll()

    data = render_to_string("create_poll.html", {"poll_form":poll_form}, request=request)

    return JsonResponse(data, safe=False)

def update_poll(request, poll_id):
    poll = get_object_or_404(Poll, poll_id = poll_id)

    poll_option_list = []

    poll_option = PollOptions.objects.filter(poll_id = poll_id)

    for polloptions in poll_option:
        poll_option_list.append(polloptions.option_name)

    if request.method == "POST":

        form = UpdatePoll(instance = poll)

        poll_name = request.POST.get("poll_name")
        poll_status = request.POST.get("poll_status")
        poll_description = request.POST.get("description")
        poll_options = request.POST.getlist("option")

        poll.poll_name = poll_name
        poll.poll_status = poll_status
        poll.description = poll_description

        for i in range(0, len(poll_option)):
            poll_option[i].option_name = poll_options[i]
            poll_option[i].save()

        poll.save()

        return HttpResponseRedirect("/view_poll/")

    else:
        form = UpdatePoll(instance = poll)

    context ={
        "form":form,
        "poll_option": poll_option_list
    }

    data = render_to_string("update_poll.html", context, request=request)

    return JsonResponse(data, safe=False)

@login_required
def delete_poll(request, poll_id):
    poll = Poll.objects.get(poll_id = poll_id)
    poll.delete()
    return redirect("/view_poll/")

@login_required
def close_poll(request, poll_id):

    poll = Poll.objects.get(poll_id = poll_id)
    poll.poll_status = 2;
    poll.save()
    return redirect("/view_poll/")

# Invite user to poll
@login_required
def invite_user_poll(request, poll_id):

    # Get all invited user from the user_poll table
    invited_user_list = UserPoll.objects.filter(poll_id = poll_id)

    # Empty list to append invited user's user_id
    invited_list = []

    # To append invited user's user_id
    for user in invited_user_list:
        invited_list.append(user.user_id.user_id)

    # Filter all users who are invited and are superusers
    users = User.objects.filter(is_superuser = 0).exclude(user_id__in = invited_list)

    context ={
        "users" : users,
        "invited_user_list" : invited_user_list
    }

    if request.method == "POST":

        invitelist = request.POST.getlist("invite")
        removelist = request.POST.getlist("remove")

        redirectlink = "/view_poll/" + poll_id + "/add_to_poll"

        # Inviting voter
        for key in invitelist:

            poll = get_object_or_404(Poll, poll_id = poll_id)

            inviteduser = User.objects.get(user_id = key)

            userpoll = UserPoll()

            userpoll.poll_id = poll
            userpoll.user_id = inviteduser

            userpoll.save()


        # Removing voter
        for key in removelist:

            poll = get_object_or_404(Poll, poll_id = poll_id)

            inviteduser = User.objects.get(user_id = key)

            userpoll = UserPoll.objects.get(user_id = inviteduser, poll_id = poll)

            userpoll.delete()

        return HttpResponseRedirect(redirectlink)

    
    return render(request, "invite_to_poll.html", context)

@login_required
def user_view_poll(request):

    # Filter all poll belonging to user and are ongoing or closed
    currentuserpoll = UserPoll.objects.filter(user_id = request.user.user_id).exclude(poll_id__poll_status__contains = 0)

    userpoll_list = []
    userpolllist = []
    uservotedlist = []

    for poll in currentuserpoll:
        userpoll_list.append(poll)

    for poll in userpoll_list:
        userpoll = UserPoll.objects.filter(poll_id = poll.poll_id)

        # Filter by poll id, then get all distinct value of user_id
        userballot = UserBallot.objects.filter(poll_id = poll.poll_id).values("user_id").distinct()

        userpolllist.append(userpoll.count())
        uservotedlist.append(userballot.count())


    context = {
        "currentuserpoll": currentuserpoll,
        "userpolllist":userpolllist,
        "uservotedlist":uservotedlist
    }

    return render(request, "user_view_poll.html", context)

@login_required
def user_vote_poll(request, poll_id):

    poll = get_object_or_404(Poll, poll_id = poll_id)

    polloptions = PollOptions.objects.filter(poll_id = poll_id)

    current_user = request.user

    userballot = UserBallot.objects.filter(poll_id = poll).filter(user_id = current_user)

    user_receipt = ""

    for ballot in userballot:
        if paillier.decrypt(int(poll.private_key_l), int(poll.private_key_m), int(poll.public_key), int(ballot.user_choice)) == 2:
            user_receipt = ballot.user_choice
        
    context = {
        "user_receipt":user_receipt,
        "poll": poll,
        "polloptions": polloptions,
    }

    return render(request, "user_vote_poll.html", context)

# Temporary holding variables
temp_receipt = ""
temp_receipt_list = []

@login_required
def user_vote(request, poll_id):
    poll = get_object_or_404(Poll, poll_id = poll_id)

    polloptions = PollOptions.objects.filter(poll_id = poll_id)

    if request.method == "POST":

        user_choice = str(request.POST.get("form[0][value]"))

        for i in range(0, len(polloptions)):
            if user_choice == str(polloptions[i].option_num):
                receipt = str(paillier.encrypt(int(poll.public_key), int(2)))
                temp_receipt = receipt
                temp_receipt_list.append(receipt)
            else:
                receipt = str(paillier.encrypt(int(poll.public_key), int(1)))
                temp_receipt_list.append(receipt)
    
    context = {
        "poll":poll,
        "polloptions":polloptions,
        "receipt": temp_receipt,
    }

    data = render_to_string("vote_menu.html", context, request=request)

    return JsonResponse(data, safe=False)

@login_required
def decrypt_vote(request, poll_id):
    poll = get_object_or_404(Poll, poll_id = poll_id)

    polloptions = PollOptions.objects.filter(poll_id = poll_id)

    if request.method == "POST":

        receipt_list = temp_receipt_list

        index = 0

        user_choice = ""

        receipt = ""

        for i in range(0, len(receipt_list)):
            if paillier.decrypt(int(poll.private_key_l), int(poll.private_key_m), int(poll.public_key), int(receipt_list[i])) == 2:
                receipt = receipt_list[i]
                index = i + 1

        for option in polloptions:
            if option.option_num == index:
                user_choice = option.option_name

        temp_receipt_list.clear()

    context = {
        "user_choice": user_choice,
        "receipt": receipt,
    }

    data = render_to_string("decrypt_menu.html", context, request=request)

    return JsonResponse(data, safe=False)

@login_required
def submit_vote(request, poll_id):

    poll = get_object_or_404(Poll, poll_id = poll_id)

    polloptions = PollOptions.objects.filter(poll_id = poll_id)

    # Get the current login user
    user = User.objects.get(user_id = request.user.user_id)

    if request.method == "POST":

        user_choice_receipt = request.POST.get("receipt")

        into_db = []
        temp_db = []

        receipt_list = temp_receipt_list

        for i in range(0, len(receipt_list)):
            if user_choice_receipt == receipt_list[i]:
                into_db.append(receipt_list[i])
                temp_db.append(paillier.decrypt(int(poll.private_key_l), int(poll.private_key_m), int(poll.public_key), int(receipt_list[i])))

                option = PollOptions.objects.get(poll_id = poll_id, option_num = i + 1)

                userballot = UserBallot()

                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = receipt_list[i]
                userballot.option_num = option
                userballot.save()


            else:
                into_db.append(receipt_list[i])
                temp_db.append(paillier.decrypt(int(poll.private_key_l), int(poll.private_key_m), int(poll.public_key), int(receipt_list[i])))

                option = PollOptions.objects.get(poll_id = poll_id, option_num = i + 1)

                userballot = UserBallot()

                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = receipt_list[i]
                userballot.option_num = option
                userballot.save()


        # Clear the temp_receipt_list array
        temp_receipt_list.clear()

        return JsonResponse("/user_view_poll/", safe=False)

    return JsonResponse("/user_view_poll/",safe = False)

def random_voter_vote():
    poll = Poll.objects.get(poll_id = 19)

    userpoll = UserPoll.objects.filter(poll_id = poll)

    polloptions = PollOptions.objects.filter(poll_id = 19)
    
    for i in range (0, len(userpoll)):

        rand_num = random.randrange(1, 3)
        rand_num2 = random.randrange(1, 3)

        user = User.objects.get(user_id = userpoll[i].user_id.user_id)

        # Option 1
        if rand_num == 1:

            # Vote Yes
            if rand_num2 == 1:
                
                userballot = UserBallot()
                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = paillier.encrypt(int(poll.public_key), int(2))
                userballot.option_num = polloptions[0]

                userballot.save()
                
                userballot = UserBallot()
                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = paillier.encrypt(int(poll.public_key), int(1))
                userballot.option_num = polloptions[1]

                userballot.save()

            # Vote No
            else:
                userballot = UserBallot()
                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = paillier.encrypt(int(poll.public_key), int(1))
                userballot.option_num = polloptions[0]

                userballot.save()

                userballot = UserBallot()
                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = paillier.encrypt(int(poll.public_key), int(2))
                userballot.option_num = polloptions[1]

                userballot.save()

        # Option 2
        else:
            # Vote Yes
            if rand_num2 == 1:
                
                userballot = UserBallot()
                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = paillier.encrypt(int(poll.public_key), int(2))
                userballot.option_num = polloptions[0]

                userballot.save()

                userballot = UserBallot()
                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = paillier.encrypt(int(poll.public_key), int(1))
                userballot.option_num = polloptions[1]

                userballot.save()

            # Vote No
            else:

                userballot = UserBallot()
                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = paillier.encrypt(int(poll.public_key), int(1))
                userballot.option_num = polloptions[0]

                userballot.save()

                userballot = UserBallot()
                userballot.poll_id = poll
                userballot.user_id = user
                userballot.user_choice = paillier.encrypt(int(poll.public_key), int(2))
                userballot.option_num = polloptions[1]

                userballot.save()
            
    

@login_required
def show_result(request, poll_id):
    
    poll = Poll.objects.get(poll_id = poll_id)

    # Get all the options belonging to the requested poll
    polloptions = PollOptions.objects.filter(poll_id = poll_id)

    current_user = request.user

    userballot = UserBallot.objects.filter(poll_id = poll).filter(user_id = current_user)
    user_receipt = ""

    for ballot in userballot:
        if paillier.decrypt(int(poll.private_key_l), int(poll.private_key_m), int(poll.public_key), int(ballot.user_choice)) == 2:
            user_receipt = ballot.user_choice

    count_list = []
    choicecount = []

    # Total invited voter
    userpoll = UserPoll.objects.filter(poll_id = poll.poll_id).count()

    
    for i in range(0, len(polloptions)):

        userballot = UserBallot.objects.filter(poll_id = poll).filter(option_num = polloptions[i])
        sum = paillier.encrypt(int(poll.public_key), int(1))

        for n in range(0, len(userballot)):
            
            if polloptions[i] == userballot[n].option_num:
                sum = paillier.sum_cipher(int(poll.public_key), int(userballot[n].user_choice), sum)
        
        count_list.append(sum)


    for i in range (0, len(count_list)):
        total_count = paillier.decrypt(int(poll.private_key_l), int(poll.private_key_m), int(poll.public_key), count_list[i]) - 1 - len(userballot)
        choicecount.append(total_count)
    

    highest_count = max(choicecount)

    # If there are tied count
    max_list_index = []
    for i in range(0, len(choicecount)):
        if choicecount[i] == highest_count:
            max_list_index.append(i + 1)

    max_choice_list = []

    for i in range(0, len(max_list_index)):

        for n in range(0, len(polloptions)):

            if max_list_index[i] == polloptions[n].option_num:
                max_choice_list.append(polloptions[n].option_name)
        
    context = {
        "poll":poll,
        "choicecount":choicecount,
        "userpoll":userpoll,
        "polloptions":polloptions,
        "highest_count":highest_count,
        "max_choice_list":max_choice_list,
        "user_receipt": user_receipt
    }

    return render(request, "show_result.html", context)

