import warnings

from django.utils.deprecation import RemovedInDjango19Warning

warnings.warn(
    "The myrobogals.admin.util module has been renamed. "
    "Use myrobogals.admin.utils instead.", RemovedInDjango19Warning)

from myrobogals.admin.utils import *  # NOQA isort:skip
