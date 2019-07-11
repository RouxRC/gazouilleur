#!/usr/bin/env python
# -*- coding: utf-8 -*-

from os import environ
from ast import literal_eval

def bool_str(s):
    return s.lower() in ['true', 'yes', 'y', '1']

def obj_str(env_var, default='{}'):
    return literal_eval(environ.get(env_var, default))

HOST = environ.get('GAZOUILLEUR_IRC_HOST', 'adams.freenode.net')
PORT = int(environ.get('GAZOUILLEUR_IRC_PORT', 6667))
SSL = bool_str(environ.get('GAZOUILLEUR_SSL', False))
BOTNAME = environ.get('GAZOUILLEUR_BOT_NICKNAME', 'gazouilleur2')
BOTPASS = environ.get('GAZOUILLEUR_BOT_PASSWORD', '')

MONGODB = {
  'HOST': 'mongo',
  'PORT': 27017,
  'DATABASE': BOTNAME,
  'USER': BOTNAME,
  'PSWD': BOTPASS
}

COMMAND_CHARACTER = environ.get('GAZOUILLEUR_COMMAND_CHARACTER', '!')

GLOBAL_USERS = obj_str('GAZOUILLEUR_GLOBAL_USERS', '[]')

BACK_HOURS = int(environ.get('GAZOUILLEUR_BACK_HOURS', 6))

CHANNELS = obj_str('GAZOUILLEUR_CHANNELS')

SOLITARY = bool_str(environ.get('GAZOUILLEUR_SOLITARY', False))

URL_STATS = environ.get('GAZOUILLEUR_URL_WEB', None)
URL_MANET = environ.get('GAZOUILLEUR_URL_MANET', 'https://manet.herokuapp.com/')

COLOR_LOGS = True

EXTRA_COMMANDS = obj_str('GAZOUILLEUR_EXTRA_COMMANDS', '[]')

DEBUG = bool_str(environ.get('GAZOUILLEUR_DEBUG', False))

ADMINS = GLOBAL_USERS
