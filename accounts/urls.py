from django.urls import path
from .views import RegisterUserView, VerifyUserEmail, LoginUserView, testAuthenticationView, UserPasswordChangeView, SendPasswordResetEmailView, UserPasswordResetView, UserLogoutView

urlpatterns = [
    path("register",RegisterUserView.as_view(), name="register_user"),
    path("verify-email",VerifyUserEmail.as_view(), name="verify-email"),
    path("login", LoginUserView.as_view(), name="login"),
    path("test-view", testAuthenticationView.as_view(), name="test"),
    path("change-password", UserPasswordChangeView.as_view(), name="change-password"),
    path("send-reset-password-email", SendPasswordResetEmailView.as_view(), name="send-reset-password-link"),
    path("reset/<uid>/<token>", UserPasswordResetView.as_view(), name="reset-password"),
    path("logout", UserLogoutView.as_view(), name="logout"),

]
