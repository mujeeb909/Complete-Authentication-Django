from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMessage
import os

class UserRegisterSerializer(serializers.ModelSerializer):
  password = serializers.CharField(max_length = 255, min_length =8, write_only = True)
  password2 = serializers.CharField(max_length = 255, min_length =8, write_only = True)

  class Meta:
    model = User
    fields = ['email', 'first_name','last_name','password', 'password2']

  def validate(self, attrs):
    email = attrs.get('email')
    password = attrs.get('password')
    password2 = attrs.get('password2')

    if not email or not password or not password2:
      raise ValueError("Invalid email or password")
    if password != password2:
      raise serializers.ValidationError("Password doesnot match")
    
    return attrs

  def create(self, validated_data):
    user = User.objects.create_user(
      email = validated_data['email'],
      first_name = validated_data['first_name'],
      last_name = validated_data['last_name'],
      password = validated_data['password']

    )
    return user

class LoginUserSerializer(serializers.ModelSerializer):
  
  email = serializers.EmailField(max_length=50)
  password = serializers.CharField(max_length = 255, min_length =8, write_only = True)
  full_name = serializers.CharField(max_length = 255, read_only = True)
  access_token = serializers.CharField(max_length = 255,  read_only = True)
  refresh_token = serializers.CharField(max_length = 255, read_only = True)

  class Meta:
    model = User
    fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']
  
  def validate(self, attrs):
    email= attrs.get('email')
    password=attrs.get('password')
    request=self.context.get('request')
    user=authenticate(request, email=email, password=password)
    if not user:
      raise AuthenticationFailed("invalid credentials try again")
    if not user.is_verified:
      raise AuthenticationFailed ("Email is not verified")
    user_tokens=user.tokens ()
    return {
      'email' :user.email,
      'full_name': user.get_full_name,
      'access_token': str(user_tokens.get('access')),
      'refresh_token': str(user_tokens.get('refresh'))
}
  
class UserChangePasswordSerializer(serializers.ModelSerializer):
  password = serializers.CharField( max_length=255, style={'input_type': 'password'}, write_only=True)
  password2 = serializers.CharField( max_length=255, style={'input_type': 'password'}, write_only=True)
  class Meta:
    model = User
    fields = ['password', 'password2']
    
  def validate(self, data):
    password = data['password']
    password2 = data['password2']
    user = self.context.get('user')

    if password != password2:
      raise serializers.ValidationError({'Error': "Password mismatch"})
    if len(password) < 8:
      raise serializers.ValidationError({'Error': "Password must be greater than 8 characters"})
    user.set_password(password)
    user.save()

    return data
  
class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email']
    
    def validate(self, data):
        email = data['email']
        if User.objects.filter(email = email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print( "Encoded ID",uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("Token", token)
            link = "http://localhost:8000/api/v1/auth/reset/"+uid+"/"+token
            print(link)
            # Send Email
            body = "Click following link to reset " + link
            subject = "Password Reset Link"
          
            email = EmailMessage(
            subject=subject,
            body=body,
            from_email=os.environ.get('EMAIL_HOST_USER'),  # Replace with your actual email address
            to=[email],  # Use square brackets for a list of email addresses
        )
            email.send(fail_silently=True)
            return data

            
        else:
            raise serializers.ValidationError({'Error': "Email Does not exist"})

class UserPasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField( max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField( max_length=255, style={'input_type': 'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['password', 'password2']
    
    def validate(self, data):
        try:
            password = data['password']
            password2 = data['password2']
            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError({'Error': "Password mismatch"})
        
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError({'Error': "Invalid Token or Expired"})
            user.set_password(password)
            user.save()
        
            return data
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError({'Error': "Invalid Token or expired"}) 


class UserLogoutSerializer(serializers.ModelSerializer):
  refresh_token = serializers.CharField()

  default_error_messages = {
     'Bad_Token': "Token is invalid or expired"
  }

  def validate(self, attrs):
    self.token = attrs.get('refresh_token')
    return attrs
  

  def save(self, **kwargs):
    try:
      token = RefreshToken(self.token)
      token.blacklist()
        
    except TokenError:
      return self.fail('Bad_Token')

    return super().save(**kwargs)
        