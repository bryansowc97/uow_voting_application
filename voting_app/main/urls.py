from django.urls import path
from .import views

urlpatterns = [
    path("register/", views.register_user, name = "register"),
    path("login/", views.login_user, name = "login"),
    path("home/", views.home, name = "home"),
    path("account_created/", views.post_registration, name = "post_registation"),
    path("account_details/", views.account_details, name = "account_details"),
    path("logout/", views.logout_user, name ="logout"),
    path("manage_account/", views.manage_user, name="manage_account"),
    path("manage_account/get_user/", views.get_user, name="get_user"),
]