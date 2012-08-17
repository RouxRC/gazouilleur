#!/bin/python
# -*- coding: utf-8 -*-

import sys, re
sys.path.append('..')
import config

re_clean_blanks = re.compile(r'[\s ]+')
cleanblanks = lambda x: re_clean_blanks.sub(r' ', x.strip())

re_shortdate = re.compile(r'^....-(..)-(..)( ..:..).*$')
shortdate = lambda x: re_shortdate.sub(r'\2/\1\3', str(x))

re_sending_error = re.compile(r'^.* status (\d+) .*\n.*"error":"([^"]*)".*$', re.I)
sending_error = lambda x: re_sending_error.sub(r'ERROR \1: \2', str(x))

re_clean_doc = re.compile(r'\.?\s*/[^/]+$')
clean_doc = lambda x: re_clean_doc.sub('.', x).strip()

re_clean_identica = re.compile(r'(and posts a ♻ status)? on Identi\.ca( and)?( as a)?', re.I)
clean_identica = lambda x: re_clean_identica.sub('', x)

# URL recognition adapted from Twitter's
# https://github.com/BonsaiDen/twitter-text-python/blob/master/ttp.py
UTF_CHARS = ur'a-z0-9_\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u00ff'
PRE_CHARS = ur'(?:^|$|[\s"<>\':!=])'
DOMAIN_CHARS = ur'[^\s_\!\.\/]+(?:[\.-]|[^\s_\!\.\/])+\.[a-z]{2,3}(?::[0-9]+)?'
PATH_CHARS = ur'(?:[\.,]?[%s!\*\'\(\);:=\+\$/%s#\[\]\-_,~@])' % (UTF_CHARS, '%')
QUERY_CHARS = ur'[a-z0-9!\*\'\(\);:&=\+\$/%#\[\]\-_\.,~]'
PATH_ENDING_CHARS = r'[%s\)=#/]' % UTF_CHARS
QUERY_ENDING_CHARS = '[a-z0-9_&=#]'
END_CHARS = ur'(?:$|[\s"<>\':!=])'
URL_REGEX = re.compile('(%s)(https?://|www\\.)?%s(\/%s*%s?)?(\?%s*%s)?(%s)' % (PRE_CHARS, DOMAIN_CHARS, PATH_CHARS, PATH_ENDING_CHARS, QUERY_CHARS, QUERY_ENDING_CHARS, PRE_CHARS), re.I)

#re_url = re.compile(r'(^|\s)(https?://)?\S+\.[a-z0-9]{2,3}/?\S*(\s|$)', re.I)
def countchars(text):
    text = text.strip()
#    while re_url.search(text):
#        text = re_url.sub(r'\1http://t.co/xxxxxxxx\3', text)
    res = URL_REGEX.search(text)
    while res:
        print res.groups()
        text = URL_REGEX.sub(r'\1http://t.co/xxxxxxxx\5', text)
        res = URL_REGEX.search(text)
    print text
    return len(text)

re_handle_quotes = re.compile(r'("[^"]*")')
re_handle_simple_quotes = re.compile(r"('[^']*')")
def _handle_quotes(args, regexp):
    res = regexp.search(args)
    if res:
        for m in res.groups():
            args = args.replace(m, m[1:-1].replace(' ', '\s'))
    return args

def handle_quotes(args):
    return _handle_quotes(_handle_quotes(args, re_handle_quotes), re_handle_simple_quotes)

def safeint(n):
    try:
        return int(n.strip())
    except:
        return 0

def chanconf(chan, conf=None):
    if conf:
        return conf
    if chan:
        chan = chan.lstrip('#')
    try:
        return config.CHANNELS[chan]
    except:
        return None

def chan_has_protocol(chan, protocol, conf=None):
    conf = chanconf(chan, conf)
    return conf and protocol.upper() in conf

def chan_has_identica(chan, conf=None):
    return chan_has_protocol(chan, 'IDENTICA', conf)

def chan_has_twitter(chan, conf=None):
    return chan_has_protocol(chan, 'TWITTER', conf)

def is_user_admin(nick):
    return nick in config.ADMINS

def is_user_global(nick):
    return nick in config.GLOBAL_USERS

def is_user_auth(nick, channel, conf=None):
    conf = chanconf(channel, conf)
    return conf and (is_user_global(nick) or is_user_admin(nick) or ('USERS' in conf and nick in conf['USERS']))

def has_user_rights_in_doc(nick, channel, command_doc, conf=None):
    if command_doc is None:
        return True if is_user_admin(nick) else False
    conf = chanconf(channel, conf)
    if command_doc.endswith('/TWITTER') and not (chan_has_twitter(channel, conf) and (chan_has_identica(channel, conf) or 'twitter' in clean_doc(command_doc).lower())):
        return False
    if is_user_auth(nick, channel, conf):
        return True
    if command_doc.endswith('/AUTH') or command_doc.endswith('/TWITTER'):
        return False
    return True

