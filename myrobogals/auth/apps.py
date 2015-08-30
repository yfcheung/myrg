from django.apps import AppConfig
from myrobogals.auth.checks import check_user_model
from django.core import checks
from django.db.models.signals import post_migrate
from django.utils.translation import ugettext_lazy as _

from .management import create_permissions


class AuthConfig(AppConfig):
    name = 'myrobogals.auth'
    verbose_name = _("Authentication and Authorization")

    def ready(self):
        post_migrate.connect(create_permissions,
            dispatch_uid="myrobogals.auth.management.create_permissions")
        checks.register(check_user_model, checks.Tags.models)
