from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import six

class ResetTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) + 
            six.text_type(user.password)
        )

class ActivateTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) + 
            six.text_type(user.is_active)
        )    
password_reset_token = ResetTokenGenerator()
account_activation_token = ActivateTokenGenerator()