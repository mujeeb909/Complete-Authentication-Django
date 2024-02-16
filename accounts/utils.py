import random
from django.core.mail import EmailMessage
from .models import User, OneTimePasscode
import os


def OtpGenerate():
  otp = ""
  for i in range(6):
    otp += str(random.randint(0,9))
  return otp


def send_code_to_user(email):
  Subject = "One time OTP Passcode for Email Verification"
  otp_code = OtpGenerate()
  
  user = User.objects.get(email = email)
  current_site = "ABC.com"
  email_body = f"{user.first_name} {user.last_name} thanks for signing up on {current_site} please verify your email address with OTP {otp_code}"
  #email_body = "Email Sent!!"
  from_email = os.environ.get('EMAIL_HOST_USER')

  OneTimePasscode.objects.create(user = user, code= otp_code)
  d_email = EmailMessage(subject=Subject, body=email_body, from_email=from_email, to = [email] )

  d_email.send(fail_silently=True)



