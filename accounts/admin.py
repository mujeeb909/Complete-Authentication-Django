from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, OneTimePasscode

class UserDetail(UserAdmin):
    list_display = ("get_full_name", "email", "is_active", "is_staff", "is_superuser")
    ordering = ["email"]
    exclude = ("date_joined", "last_login", )

admin.site.register(User, UserDetail)
admin.site.register(OneTimePasscode)
