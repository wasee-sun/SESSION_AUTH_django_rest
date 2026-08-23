from django.urls import path
from . import views

urlpatterns = [
    path("csrf-token/", views.CSRFTokenView.as_view(), name="csrf-token"),
    path(
        "recaptcha-verify/",
        views.RecaptchaValidationView.as_view(),
        name="recaptcha-verify",
    ),
    path("login/", views.LoginView.as_view(), name="login"),
    path("two-fa-login/", views.TwoFAView.as_view(), name="two-fa-login"),
    path("refresh/", views.RefreshSessionView.as_view(), name="refresh"),
    path("social-login/", views.SocialLoginView.as_view(), name="social-login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("fcm-register/", views.FCMTokenView.as_view(), name="fcm-register"),
    path("resend-otp/", views.ResendOTPView.as_view(), name="resend-otp"),
    path(
        "req-change-password/",
        views.RequestChangePasswordView.as_view(),
        name="req-change-password",
    ),
    path(
        "change-password/",
        views.ChangePasswordView.as_view(),
        name="change-password",
    ),
]
