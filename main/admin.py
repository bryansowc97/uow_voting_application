from django.contrib import admin
from .models import User, Poll, PollOptions, UserPoll, UserVote, UserBallot

# Register your models here.

class PollOptionsInline(admin.StackedInline):
    model = PollOptions
    extra = 0
    fields = ['option_num', 'option_name']

class UserVoteInline(admin.StackedInline):
    model = UserVote
    extra = 0
    list_display = ['poll_id', 'option_id', 'user_id', 'user_choice']

class PollAdmin(admin.ModelAdmin):
    inlines = [PollOptionsInline, UserVoteInline]
    list_display = ['poll_id', 'poll_name']

class PollInline(admin.StackedInline):
    model = Poll
    extra = 0

admin.site.register(Poll, PollAdmin)
admin.site.register(User)
admin.site.register(PollOptions)
admin.site.register(UserVote)
admin.site.register(UserPoll)
admin.site.register(UserBallot)

