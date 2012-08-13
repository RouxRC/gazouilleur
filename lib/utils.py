#!/bin/python
# -*- coding: utf-8 -*-

import sys, re
sys.path.append('..')
import config

re_clean_blanks = re.compile(r'[\s ]+')
cleanblanks = lambda x: re_clean_blanks.sub(r' ', x.strip())

re_shortdate = re.compile(r'^....-(..)-(..)( ..:..).*$')
shortdate = lambda x: re_shortdate.sub(r'\2/\1\3', str(x))

re_url = re.compile(r'(https?://\S+|\S+\.[a-z]{2,3})', re.I)
countchars = lambda x: len(re_url.sub(r'http://t.co/xxxxxxxx', x))

re_sending_error = re.compile(r'^.* status (\d+) .*\n.*"error":"([^"]*)".*$', re.I)
sending_error = lambda x: re_sending_error.sub(r'ERROR \1: \2', str(x))

def safeint(n):
    try:
        return int(n.strip())
    except:
        return 0

def chanconf(chan):
    if chan:
        chan = chan.lstrip('#')
    try:
        return config.CHANNELS[chan]
    except:
        return None

def chan_has_protocol(chan, protocol, conf=None):
    if conf is None:
        conf = chanconf(chan)
    return conf and protocol.upper() in conf

def chan_has_identica(chan, conf=None):
    return chan_has_protocol(chan, 'IDENTICA', conf)

def chan_has_twitter(chan, conf=None):
    return chan_has_protocol(chan, 'TWITTER', conf)
