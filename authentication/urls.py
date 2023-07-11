from django.urls import path
from .views import (
    RegisterView, LoginApiView, VerifyEmail, PasswordTokenCheckAPIView, 
    RequestPasswordResetEmailAPIView, SetNewPasswordAPIView
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('login/', LoginApiView.as_view(), name="login"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPIView.as_view(), name='password-reset-confirm'),
    path('email-reset/', RequestPasswordResetEmailAPIView.as_view(), name='email-reset'),
    path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name='password-reset'),

    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

]






# pip install django-cors-headers