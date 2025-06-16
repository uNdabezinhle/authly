# users/validators.py

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class PasswordComplexityValidator:
    """
    Validate whether the password contains at least one uppercase letter,
    one lowercase letter, one digit, and one special character.
    """
    
    def __init__(self, min_length=12):
        self.min_length = min_length
    
    def validate(self, password, user=None):
        errors = []
        
        # Check for minimum length
        if len(password) < self.min_length:
            errors.append(ValidationError(
                _("Password must be at least %(min_length)d characters long."),
                code='password_too_short',
                params={'min_length': self.min_length},
            ))
        
        # Check for uppercase letters
        if not re.search(r'[A-Z]', password):
            errors.append(ValidationError(
                _("Password must contain at least one uppercase letter."),
                code='password_no_upper',
            ))
        
        # Check for lowercase letters
        if not re.search(r'[a-z]', password):
            errors.append(ValidationError(
                _("Password must contain at least one lowercase letter."),
                code='password_no_lower',
            ))
        
        # Check for digits
        if not re.search(r'\d', password):
            errors.append(ValidationError(
                _("Password must contain at least one digit."),
                code='password_no_digit',
            ))
        
        # Check for special characters
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append(ValidationError(
                _("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."),
                code='password_no_special',
            ))
        
        if errors:
            raise ValidationError(errors)
    
    def get_help_text(self):
        return _(
            "Your password must be at least %(min_length)d characters long and contain "
            "at least one uppercase letter, one lowercase letter, one digit, and "
            "one special character (!@#$%^&*(),.?\":{}|<>)."
        ) % {'min_length': self.min_length}