from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
  def email_validator(self,email):
    try:
      validate_email(email)
    except ValidationError :
      raise ValueError(_("Please enter an email address"))
    
  def create_user(self, email, first_name, last_name, password, **extra_fields):
        
    if email:
      email = self.normalize_email(email)
      self.email_validator(email)
    else:
      raise ValueError(_('ENTER Email'))
    if not first_name:
      raise ValueError(_('Enter First Name'))
    if not last_name:
      raise ValueError(_('ENTER Last Name'))
        
    user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            **extra_fields
        )
        
    user.is_superuser = False
    user.set_password(password)
    user.save(using = self._db)

    return user
  
  def create_superuser(self, email, first_name, last_name, password, **extra_fields):
    extra_fields.setdefault("is_staff", True)
    extra_fields.setdefault("is_superuser", True)
    extra_fields.setdefault("is_verified", True)

    if extra_fields.get("is_staff") is not True:
      raise ValueError(_('is_staff must be true for superusers and admins'))
    if extra_fields.get("is_superuser") is not True:
      raise ValueError(_('is_superuser must be true for superusers and admins'))
    
        
    user = self.create_user(email, first_name, last_name, password, **extra_fields)
    user.is_staff = True
    user.is_superuser = True
    
    user.save(using = self._db)
    return user
