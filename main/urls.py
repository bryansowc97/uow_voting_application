from django.urls import path
from .import views

urlpatterns = [

    # Index
    path("", views.login_index, name ="index"),

    # Home
    path("home/", views.home, name = "home"),

    # User login/registration
    path("register/", views.register_user, name = "register"),
    path("register/validate_username/", views.usernameValidation, name = "validate_username"),
    path("register/validate_email/", views.emailValidation, name = "validate_email"),
    path("account_created/", views.post_registration, name = "post_registation"),
    path("login_failed/", views.login_failed, name = "login_failed"),
    path("logout/", views.logout_user, name ="logout"),
    path("activate_account/?<uidb64>?<token>/", views.activate_account, name = 'activate_account'),
    path("activate_account_success/", views.activate_account_success, name= "activate_account_successs"),
    path("account_not_activated/", views.account_not_activated, name="account_not_activated"),
    path("reset_password_page/", views.reset_password_page, name = "reset_password_page"),
    path("reset_password/?<uidb64>?<token>/", views.reset_password, name = 'reset_password'),
    path("reset_password_sucesss/", views.reset_password_sucesss, name = "reset_password_sucesss"),
    path("email_link_expired/", views.email_link_expired, name = "email_link_expired"),
    
    # User profile management
    path("account_details/", views.update_user_detail, name = "account_details_update"),
    path("change_password/", views.change_password, name ="change_password"),
    path("change_password/success/", views.password_changed_successfully, name ="password_changed_successfully"),
    
    # User view poll
    path("user_view_poll/", views.user_view_poll, name ="user_view_poll"),
    path("user_view_poll/<poll_id>/vote/", views.user_vote_poll, name = "user_vote_poll"),
    path("user_view_poll/<poll_id>/view_result/", views.show_result, name = "user_view_result"),
    path("user_view_poll/<poll_id>/vote/vote_menu/", views.user_vote, name = "vote_menu"),
    path("user_view_poll/<poll_id>/vote/decrypt_menu/", views.decrypt_vote, name = "decrypt_menu"),
    path("user_view_poll/<poll_id>/vote/confirm_vote/", views.submit_vote, name = "confirm_vote"),

    # Admin account management
    path("manage_account/", views.user_list, name="manage_account"),
    path("manage_account/update_user/<user_id>/", views.update_user, name="update_user"),
    path("manage_account/delete_user/<user_id>", views.delete_user, name= "delete_user"),
    path("create_account/", views.add_user, name = "create_user"),
    path("create_multiple_account/", views.create_multiple_user, name = "create_multiple_account"),
    path("manage_account/sort/", views.sort_account, name="sort_account"),
    path("manage_account/search/", views.search_account, name="search_account"),
    path("manage_account/filter/", views.filter_account, name="filter_account"),

    # Admin create poll
    path("create_poll/", views.create_poll, name="create_poll"),
    path("view_poll/", views.view_poll, name = "view_poll"),
    path("view_poll/<poll_id>", views.poll_detail_view, name = "poll_detail_view"),
    path("view_poll/update_poll/<poll_id>", views.update_poll, name="update_poll"),
    path("view_poll/<poll_id>/add_to_poll/", views.invite_user_poll, name = "invite_user_poll"),
    path("view_poll/<poll_id>/delete_poll/", views.delete_poll, name = "delete_poll"),
    path("view_poll/<poll_id>/close_poll/", views.close_poll, name = "close_poll"),
]