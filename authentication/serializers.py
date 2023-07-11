from rest_framework import serializers
from .models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def validate(self, attrs):
        username = attrs.get('username', '')
        email = attrs.get('email', '')

        if not username.isalnum():
            raise serializers.ValidationError('Username can only contain alphanumeric characters')
        
        return attrs

        # return super().validate(attrs)


    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    

class EmailVerificationSerializer(serializers.ModelSerializer):

    token = serializers.CharField(max_length = 555)

    class Meta:
        model = User
        fields = ['token', ]


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField()
    email = serializers.EmailField(read_only=True)
    password = serializers.CharField(write_only=True)
    tokens = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'tokens', ]


    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')
        user = auth.authenticate(username=username, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again!')
        
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin!')
        
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified!')
        
        return {
            'username': user.username,
            'email': user.email,
            'tokens': user.tokens,
        }

        return super().validate(attrs)


class ResetPasswordEmailRequestSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        model = User
        fields = ['email', ]

    # def validate(self, data):
    #     attrs = data['data']
    #     request = data['request']

    #     print("data: ", data)
    #     print("attrs: ", attrs)
    #     print("request:", request)

    #     email = attrs.get('email', '')
    #     user = User.objects.get(email=email)
    #     if user:
    #         uidb64 = urlsafe_base64_encode(user.id)
    #         token = PasswordResetTokenGenerator().make_token(user)

    #         current_site = get_current_site(request=request).domain
    #         relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
    #         absurl = 'http://' + current_site + relativeLink
    #         email_body = 'Hi ' + user.username + ', you can use the link below to reset your password \n' + absurl
    #         data = {'email_body': email_body, 'to_email': user.email,
    #                 'email_subject': 'Reset your password'}

    #         Util.send_email(data)
    
    #     return super().validate(attrs)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        model = User
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            
            user.set_password(password)
            user.save()
            return user
            
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        