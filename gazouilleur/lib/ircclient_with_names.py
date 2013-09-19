#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Freely adapted from Smackshow on StackOverflow 
# http://stackoverflow.com/questions/6671620/list-users-in-irc-channel-using-twisted-python-irc-framework

from twisted.words.protocols import irc
from twisted.internet import defer

class NamesIRCClient(irc.IRCClient):
    def __init__(self, *args, **kwargs):
        self._namescallback = {}

    def _names(self, channel):
        channel = channel.lower()
        d = defer.Deferred()
        if channel not in self._namescallback:
            self._namescallback[channel] = ([], [])
        self._namescallback[channel][0].append(d)
        self.sendLine("NAMES %s" % channel)
        return d

    def irc_RPL_NAMREPLY(self, prefix, params):
        channel = params[2].lower()
        nicklist = params[3].split(' ')
        if channel not in self._namescallback:
            return
        n = self._namescallback[channel][1]
        n += nicklist

    def irc_RPL_ENDOFNAMES(self, prefix, params):
        channel = params[1].lower()
        if channel not in self._namescallback:
            return
        callbacks, namelist = self._namescallback[channel]
        for cb in callbacks:
            cb.callback(namelist)
        del self._namescallback[channel]

