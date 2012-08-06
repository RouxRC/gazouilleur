#!/bin/python
# -*- coding: utf-8 -*-

import sys, time
import lxml.html
from twisted.internet import reactor, task, defer, protocol
from twisted.python import log
from twisted.words.protocols import irc
from twisted.web.client import getPage
from twisted.application import internet, service

config = __import__('config')

class ChanLogger:
    def __init__(self, file):
        self.file = file

    def log(self, message):
        timestamp = time.strftime("[%H:%M:%S]", time.localtime(time.time()))
        self.file.write('%s %s\n' % (timestamp, message))
        self.file.flush()

    def close(self):
        self.file.close()

class IRCBot(irc.IRCClient):
    nickname = config.BOTNAME
    username = config.BOTNAME
    password = config.BOTPASS

    def connectionMade(self):
        irc.IRCClient.connectionMade(self)
        self.msg("NickServ", 'identify '+self.username+' '+self.password); 
        log.msg('Connection made')
        self.logger = {self.username: ChanLogger(open(self.username+".log", "a"))}
        self.logger[self.username].log("[connected at %s]" % time.asctime(time.localtime(time.time())))

    def connectionLost(self, reason):
        irc.IRCClient.connectionLost(self, reason)
        log.msg('Connection lost because: %s.' % (reason,))
        self.logger[self.username].log("[disconnected at %s]" % time.asctime(time.localtime(time.time())))
        self.logger[self.username].close()

    def signedOn(self):
        log.msg("Signed on as %s." % (self.nickname,))
        for channel in self.factory.channels:
            self.join(channel)

    def nickChanged(self, nick):
        self.logger[self.nickname] = self.logger[self.username]

    def joined(self, channel):
        log.msg("Joined %s." % (channel,))
        self.logger[channel] = ChanLogger(open(self.username+"_"+channel+".log", "a"))
        self.logger[channel].log("[joined at %s]" % time.asctime(time.localtime(time.time())))

    def left(self, channel):          
        log.msg("Joined %s." % (channel,))
        self.logger[channel].log("[disconnected at %s]" % time.asctime(time.localtime(time.time())))
        self.logger[channel].close()

    def noticed(self, user, channel, message):
        if channel == "*":
            channel = self.username
        self.logger[channel].log("%s: %s" % (user, message))

    def privmsg(self, user, channel, message):
        nick, _, host = user.partition('!')
        message = message.strip()
        d = None
        if not message.startswith('!'):
            if self.nickname.lower() in message.lower():
                d = defer.maybeDeferred(lambda x: x+": Oui?", nick)
            return
        command, sep, rest = message.lstrip('!').partition(' ')
        func = getattr(self, 'command_' + command.lower(), None)
        if func is None:
            # TODO ADD MSSG FONCTION INEXISTANTE CALL !HELP
            return
        # maybeDeferred will always return a Deferred. It calls func(rest), and
        # if that returned a Deferred, return that. Otherwise, return the return
        # value of the function wrapped in twisted.internet.defer.succeed. If
        # an exception was raised, wrap the traceback in
        # twisted.internet.defer.fail and return that.
        if d is None:
            d = defer.maybeDeferred(func, rest, nick)
        d.addErrback(self._show_error)
        if channel == self.nickname:
            d.addCallback(self._send_message, nick)
        else:
            d.addCallback(self._send_message, channel, nick)

    def _check_user_rights(self, nick):
        if nick not in config.AUTH_USERS:
            return 'Sorry only registered users are allowed to use me'
        return

    def _send_message(self, msg, target, nick=None):
        if nick:
            msg = '%s: %s' % (nick, msg)
        self.msg(target, msg)

    def _show_error(self, failure):
        return failure.getErrorMessage()

    def command_help(self, rest, nick=None):
        if rest == '':
            return 'My commands are:  '+' ;  '.join([c.replace('command_', '!') for c in dir(self) if c.startswith('command_')])

    def command_ping(self, rest, nick=None):
        return 'Pong.'

# TODO
    def command_lastseen(self, rest, nick=None):
        return "TODO"

    def command_saylater(self, rest, nick=None):
        when, sep, msg = rest.partition(' ')
        when = int(when)
        d = defer.Deferred()
        # A small example of how to defer the reply from a command. callLater
        # will callback the Deferred with the reply after so many seconds.
        reactor.callLater(when, d.callback, msg)
        # Returning the Deferred here means that it'll be returned from
        # maybeDeferred in privmsg.
        return d

    def command_title(self, url, nick=None):
        d = getPage(url)
        # Another example of using Deferreds. twisted.web.client.getPage returns
        # a Deferred which is called back when the URL requested has been
        # downloaded. We add a callback to the chain which will parse the page
        # and extract only the title. If we just returned the deferred instead,
        # the function would still work, but the reply would be the entire
        # contents of the page.
        # After that, we add a callback that will extract the title
        # from the parsed tree lxml returns
        d.addCallback(self._parse_pagetitle, url)
        return d

    def _parse_pagetitle(self, page_contents, url):
        # Parses the page into a tree of elements:
        pagetree = lxml.html.fromstring(page_contents)
        # Extracts the title text from the lxml document using xpath
        title = u' '.join(pagetree.xpath('//title/text()')).strip()
        # Since lxml gives you unicode and unicode data must be encoded
        # to send over the wire, we have to encode the title. Sadly IRC predates
        # unicode, so there's no formal way of specifying the encoding of data
        # transmitted over IRC. UTF-8 is our best bet, and what most people use.
        title = title.encode('utf-8')
        # Since we're returning this value from a callback, it will be passed in
        # to the next callback in the chain (self._send_message).
        return '%s -- "%s"' % (url, title)

class IRCBotFactory(protocol.ReconnectingClientFactory):
    protocol = IRCBot
    channels = ["#" + c for c in config.CHANNELS]

if __name__ == '__main__':
    reactor.connectTCP(config.HOST, config.PORT, IRCBotFactory())
    log.startLogging(sys.stdout)
    reactor.run()
# This runs the program in the background. __name__ is __builtin__ when you use
# twistd -y on a python module.
elif __name__ == '__builtin__':
    ircService = internet.TCPClient(config.HOST, config.PORT, IRCBotFactory())
    ircService.setServiceParent(application)

