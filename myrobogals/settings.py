"""
Django settings for myrobogals project.

Generated by 'django-admin startproject' using Django 1.8.3.

For more information on this file, see
https://docs.djangoproject.com/en/1.8/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.8/ref/settings/
"""

import os

# The directory where you checked out the "myrobogals" repo,
# which is one level above this directory.
# Do not put a trailing slash.
ROBOGALS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.8/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'q-^0dr%6xtf3k*%@i&y-r&a+=sfmmfd!#_zvyw(%owrn*2i5hg'

API_SECRET = 'k290gj2apoz0'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

ADMINS = (
        ('myRobogals', 'my@robogals.org'),
)
MANAGERS = ADMINS

AUTHENTICATION_BACKENDS = ('myrobogals.auth.backends.ModelBackend',)

LOGIN_URL = '/login/'

LOGOUT_URL = '/logout/'

LOGIN_REDIRECT_URL = '/accounts/profile/'

# Application definition

INSTALLED_APPS = (
    'django_extensions',
    'myrobogals.auth',
    'myrobogals.admin',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'myrobogals.rgmain',
    'myrobogals.rgprofile',
    'myrobogals.rgchapter',
    'myrobogals.rgteaching',
    'myrobogals.rgmessages',
    'myrobogals.rgweb',
    'myrobogals.filters',
    'myrobogals.rgforums',
    'myrobogals.rgconf',
    'tinymce',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'myrobogals.auth.middleware.AuthenticationMiddleware',
    'myrobogals.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)

ROOT_URLCONF = 'myrobogals.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(ROBOGALS_DIR, 'rgtemplates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.request',
                'myrobogals.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'myrobogals.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.8/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(ROBOGALS_DIR, 'db.sqlite3'),
    }
}

LANGUAGES = (
        ('en', 'English'),
        ('nl', 'Dutch'),
        ('ja', 'Japanese'),
)

SITE_ID = 1

# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

LANGUAGE_CODE = 'en'

TIME_ZONE = 'Etc/UTC'
DATE_FORMAT = 'D j M y'
DATE_FORMAT_LONG = 'l j F Y'
TIME_FORMAT = 'g:i a'
DATETIME_FORMAT = 'g:i a, D j M y'
DATETIME_FORMAT_LONG = 'g:i a, l j F Y'

USE_I18N = True

# USE_L10N = True

# USE_TZ = True

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = os.path.join(ROBOGALS_DIR, 'rgmedia/')

# URL that handles the media in "rgmedia"
# Put a trailing slash if there is a path component (optional in other cases).
# The default '/rgmedia' will work when using the Django dev server and debug = True
MEDIA_URL = '/rgmedia/'

TINYMCE_JS_URL = MEDIA_URL + '/js/tiny_mce/tiny_mce.js'
TINYMCE_JS_ROOT = os.path.join(MEDIA_ROOT, "js/tiny_mce/")
TINYMCE_DEFAULT_CONFIG = {
	'theme_advanced_buttons1' : "bold,italic,underline,strikethrough,|,justifyleft,justifycenter,justifyright,justifyfull,|,formatselect,fontselect,fontsizeselect",
	'theme_advanced_buttons2' : "bullist,numlist,|,outdent,indent,blockquote,|,undo,redo,|,link,unlink,anchor,image,cleanup,help,code,|,forecolor",
	'theme_advanced_buttons3' : "hr,removeformat,visualaid,|,sub,sup,|,charmap",
	'theme_advanced_toolbar_location' : "top",
	'theme_advanced_toolbar_align' : "left",
	'theme_advanced_statusbar_location' : "bottom",
	'theme_advanced_resizing' : False,
	'width' : 585,
	'height' : 500,
	'theme' : "advanced",
	'relative_urls': False,
}
TINYMCE_SPELLCHECKER = False
TINYMCE_COMPRESSOR = False
TINYMCE_FILEBROWSER = False
