from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from .serializers import UserRegisterSerializer, LoginUserSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer, UserPasswordResetSerializer, UserLogoutSerializer
from rest_framework.response import Response
from .utils import send_code_to_user
from .models import OneTimePasscode 
from rest_framework.permissions import IsAuthenticated


class RegisterUserView(GenericAPIView):
  serializer_class = UserRegisterSerializer



  def post(self, request):
    data = request.data
    serializer = self.serializer_class(data=data)
    if serializer.is_valid(raise_exception=True):
      serializer.save()
      user = serializer.data

      send_code_to_user(user['email'])
      return Response({
        'Message': f' Successfully {user['first_name']} is created!!',
        'Data':  user
         })
    return Response( serializer.error_messages )


class VerifyUserEmail(GenericAPIView):

  def post(self, request):
    otp = request.data.get('otp')

    try:
      one_time_passcode = OneTimePasscode.objects.get(code = otp)
      user = one_time_passcode.user
      if not user.is_verified:
        user.is_verified = True
        user.save()
        return Response({
          'messgae': "Email verified",
        })
      return Response({
          'messgae': "Invalid Token or expired",
        })

    
    except OneTimePasscode.DoesNotExist:
      return Response({
          'messgae': "Token is not provided",
        })


class LoginUserView(GenericAPIView):
  serializer_class = LoginUserSerializer

  def post(self, request):
    serializer = self.serializer_class(data = request.data, context ={'request': request})
    serializer.is_valid(raise_exception=True)

    return Response({
      "message": serializer.data
    })

class testAuthenticationView(GenericAPIView):
  permission_classes = [IsAuthenticated]

  def get(self,request):
    msg = "Its Worked"

    return Response({'message': msg})
  

class UserPasswordChangeView(GenericAPIView):
  
  permission_classes = [IsAuthenticated]
  
  def post(self, request):
    serializer = UserChangePasswordSerializer(data = request.data, context= {'user':request.user})
    if not serializer.is_valid():
      return Response({'status': 403, 'message': serializer.errors} )
    return Response({'status': 200, 'MSG':"Password Changed Successfully", })

class SendPasswordResetEmailView(GenericAPIView):
  

  def post(self, request):
    serializer = SendPasswordResetEmailSerializer(data = request.data)
    if not serializer.is_valid():
      return Response({'status': 403, 'message': serializer.errors} )
    return Response({'status': 200, 'MSG':"Password Reset email sent, Please check your email"})
  

class UserPasswordResetView(GenericAPIView):
  

  def post(self, request, uid, token):
    serializer = UserPasswordResetSerializer(data = request.data, context={"uid": uid, "token": token})
    if not serializer.is_valid():
      return Response({'status': 403, 'message': serializer.errors} )
    return Response({'status': 200, 'MSG':"Password Reset Successfully"})
  
class UserLogoutView(GenericAPIView):
  permission_classes = [IsAuthenticated]
  serializer_class = UserLogoutSerializer

  def post(self, request):
    serializer = self.serializer_class(data= request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save()

    return Response({"Status":204})