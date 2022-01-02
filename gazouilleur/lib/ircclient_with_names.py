#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Freely adapted from Smackshow on StackOverflow
# http://stackoverflow.com/questions/6671620/list-users-in-irc-channel-using-twisted-python-irc-framework

from twisted.words.protocols.irc import IRCClient
from twisted.internet import defer
from twisted.internet.defer import Deferred
from textwrap import wrap

class NamesIRCClient(IRCClient):
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

    def irc_CAP(self, prefix, params):
        if params[1] != 'ACK' or params[2].split() != ['sasl']:
            print 'sasl not available'
            self.quit('')
        sasl = ('{0}\0{0}\0{1}'.format(self.nickname, self.password)).encode('base64').strip()
        self.sendLine('AUTHENTICATE PLAIN')
        self.sendLine('AUTHENTICATE ' + sasl)

    def irc_903(self, prefix, params):
        self.sendLine('CAP END')

    def irc_904(self, prefix, params):
        print 'sasl auth failed', params
        self.quit('')
    irc_905 = irc_904

    # Redefinition of IRCClient's msg and sendLine methods to:
    # - send messages to multiple chans in parallel
    # - forbid url-breaking when splitting long messages

    def connectionMade(self):
        if self.sasl:
            self._queue = {"default": []}
            self._queueEmptying = {"default": None}
            self.sendLine('CAP REQ :sasl')
            self.deferred = Deferred()
        IRCClient.connectionMade(self)
        self._queue = {"default": []}
        self._queueEmptying = {"default": None}

    def joined(self, channel):
        lowchan = channel.lower()
        self._queue[lowchan] = []
        self._queueEmptying[lowchan] = None

    def sendLine(self, line, chan="default", original=""):
        if self.lineRate is None or chan not in self._queue or chan not in self._queueEmptying:
            self._reallySendLine(line)
        else:
            self._queue[chan].append((line, original))
            if not self._queueEmptying[chan]:
                self._sendLine(chan)

    def _sendLine(self, chan="default"):
        if self._queue[chan]:
            line, original = self._queue[chan].pop(0)
            self._reallySendLine(line)
            self._queueEmptying[chan] = reactor.callLater(self.lineRate, self._sendLine, chan)
        else:
            self._queueEmptying[chan] = None

    def msg(self, target, message, length=None):
        fmt = 'PRIVMSG %s :' % (target,)
        if length is None:
            length = self._safeMaximumLineLength(fmt)
        minimumLength = len(fmt) + 2
        if length <= minimumLength:
            raise ValueError("Maximum length must exceed %d for message to %s" % (minimumLength, target))
        for line in split_no_urlbreak(message, length - minimumLength):
            self.sendLine(fmt + line, target.lower(), original=message)

def split_no_urlbreak(s, length=80):
    return [chunk.encode('utf-8') for line in s.decode('utf-8').split('\n') for chunk in wrap(line, length, break_on_hyphens=False)]

