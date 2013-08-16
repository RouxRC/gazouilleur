#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from colifrapy.tools.colorize import colorize
from twisted.python import log

def colr(text, color, bold=True):
    return colorize(text, color, style='bold' if bold else '')

def _logg(text, color=None, channel=None, action=None, error=False):
    if color:
        text = colr(text, color)
    elif error:
        text = colr(text, 'red')
    tmp = ""
    if action:
        tmp += colr(action, 'green')
    if channel and action:
        tmp += "/"
    if channel:
        tmp += colr(channel, 'blue')
    if tmp:
        text = "[%s] %s" % (tmp, text)
    if error:
        text = "%s %s" % (colr("ERROR", 'red'), text)
    return text

def logg(text, color=None, channel=None, action=None, error=False):
    return log.msg(_logg(text, color, channel, action, error))

def loggirc(text, chan=None):
    return logg(text, color="cyan", action="IRC", channel=chan)

def loggirc2(text, chan=None):
    return logg(text, color="magenta", action="IRC", channel=chan)

def loggerr(text, chan=None, action=None):
    return logg(text, error=True, action=action, channel=chan)

def loggvar(text, chan=None, action=None):
    return logg(text, color="yellow", action=action, channel=chan)

def logerr(text):
    return sys.stderr.write(_logg("%s\n" % text, error=True))

