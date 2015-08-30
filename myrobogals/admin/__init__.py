# ACTION_CHECKBOX_NAME is unused, but should stay since its import from here
# has been referenced in documentation.
from myrobogals.admin.decorators import register
from myrobogals.admin.helpers import ACTION_CHECKBOX_NAME
from myrobogals.admin.options import (HORIZONTAL, VERTICAL,
    ModelAdmin, StackedInline, TabularInline)
from myrobogals.admin.filters import (ListFilter, SimpleListFilter,
    FieldListFilter, BooleanFieldListFilter, RelatedFieldListFilter,
    ChoicesFieldListFilter, DateFieldListFilter, AllValuesFieldListFilter,
    RelatedOnlyFieldListFilter)
from myrobogals.admin.sites import AdminSite, site
from django.utils.module_loading import autodiscover_modules

__all__ = [
    "register", "ACTION_CHECKBOX_NAME", "ModelAdmin", "HORIZONTAL", "VERTICAL",
    "StackedInline", "TabularInline", "AdminSite", "site", "ListFilter",
    "SimpleListFilter", "FieldListFilter", "BooleanFieldListFilter",
    "RelatedFieldListFilter", "ChoicesFieldListFilter", "DateFieldListFilter",
    "AllValuesFieldListFilter", "RelatedOnlyFieldListFilter", "autodiscover",
]


def autodiscover():
    autodiscover_modules('admin', register_to=site)


default_app_config = 'myrobogals.admin.apps.AdminConfig'
