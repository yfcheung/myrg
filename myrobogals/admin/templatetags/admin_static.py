from django.apps import apps
from django.template import Library
from django.utils.encoding import iri_to_uri
from myrobogals import settings

register = Library()

_static = None


@register.simple_tag
def static(path):
    return iri_to_uri(settings.MEDIA_URL + 'media/' + path)
