#!/bin/python
# -*- coding: utf-8 -*-

import sys, time, os.path
import lxml.html
from twisted.internet import reactor, defer, protocol
from twisted.python import log
from twisted.words.protocols import irc
from twisted.web.client import getPage
from twisted.application import internet
import config

class ChanLogger:
    def __init__(self, channel=''):
        filename = config.BOTNAME
        if channel:
            filename += '_' + channel
        filename += '.log'
        self.file = open(os.path.join('log', filename), "a")

    def log(self, message):
        timestamp = time.strftime("[%H:%M:%S]", time.localtime(time.time()))
        self.file.write('%s %s\n' % (timestamp, message))
        self.file.flush()

    def close(self):
        self.file.close()

class IRCBot(irc.IRCClient):
    #NickServ identification handled automatically
    nickname = config.BOTNAME
    username = config.BOTNAME
    password = config.BOTPASS

    nicks = {}
    sourceURL = 'https://github.com/RouxRC/gazouilleur'

    def connectionMade(self):
        irc.IRCClient.connectionMade(self)
        log.msg('Connection made')
        self.logger = {config.BOTNAME: ChanLogger()}
        self.logger[config.BOTNAME].log("[connected at %s]" % time.asctime(time.localtime(time.time())))

    def connectionLost(self, reason):
        irc.IRCClient.connectionLost(self, reason)
        for channel in self.factory.channels:
            self.left(channel)
        log.msg('Connection lost because: %s.' % (reason,))
        self.logger[config.BOTNAME].log("[disconnected at %s]" % time.asctime(time.localtime(time.time())))
        self.logger[config.BOTNAME].close()

    def signedOn(self):
        log.msg("Signed on as %s." % (self.nickname,))
        for channel in self.factory.channels:
            self.join(channel)

    @defer.inlineCallbacks                                                                                                                                                
    def reclaimNick(self):
        yield self.msg("NickServ", 'regain %s %s' % (config.BOTNAME, config.BOTPASS,))
        yield self.msg("NickServ", 'identify %s %s' % (config.BOTNAME, config.BOTPASS,))
        log.msg("Reclaimed ident as %s." % (config.BOTNAME,))

    def nickChanged(self, nick):
        log.msg("Identified as %s." % (nick,))
        if nick != config.BOTNAME:
            self.reclaimNick()

    def noticed(self, user, channel, message):
        if 'is not a registered nickname' in message and 'NickServ' in user:
            self.reclaimNick()
        if channel == "*" or channel == self.nickname:
            channel = config.BOTNAME
        self.logger[channel].log("%s: %s" % (user, message))

    def joined(self, channel):
        log.msg("Joined %s." % (channel,))
        self.logger[channel] = ChanLogger(channel)
        self.logger[channel].log("[joined at %s]" % time.asctime(time.localtime(time.time())))

    def left(self, channel):          
        log.msg("Left %s." % (channel,))
        self.logger[channel].log("[left at %s]" % time.asctime(time.localtime(time.time())))
        self.logger[channel].close()


    def privmsg(self, user, channel, message):
        logchan = config.BOTNAME if channel == "*" or channel == self.nickname else channel
        nick, userid, host = user.partition('!')
        message = message.strip()
        if channel not in self.nicks:
            self.nicks[channel] = {}
        if nick not in self.nicks[channel] or self.nicks[channel][nick] != (userid, host):
            self.logger[logchan].log("%s: %s" % (user, message))
            self.nicks[channel][nick] = (userid,host)
        else:
            self.logger[logchan].log("%s: %s" % (nick, message))
        d = None
        if not message.startswith('!'):
            if self.nickname.lower() in message.lower():
                d = defer.maybeDeferred(lambda x: x+": Oui?", nick)
            return
        log.msg("[%s] Received command from user %s: %s" % (channel, user, message))
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
            logchan = target
        else:
            logchan = config.BOTNAME
        self.msg(target, msg)
        self.logger[logchan].log("%s: %s" % (self.nickname, msg))

    def _show_error(self, failure):
        return failure.getErrorMessage()

    def command_help(self, rest, nick=None):
        rest = rest.replace('!', '')
        commands = [c.replace('command_', '!') for c in dir(self) if c.startswith('command_')]
        if rest == '':
            return 'My commands are:  '+' ;  '.join(commands)+'\nType "!help <command>" to get more details.'
        elif rest in commands:
#TODO
            return

    def command_ping(self, rest, nick=None):
        """!ping\nPing test, should answer pong"""
        return 'Pong.'

    def command_source(self,rest, nick=None):
        return 'My sourcecode is under free GPL 3.0 licence and available at the following address: %s' % self.sourceURL

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
    channels = ["#" + c['name'] for c in config.CHANNELS]

if __name__ == '__main__':
    reactor.connectTCP(config.HOST, config.PORT, IRCBotFactory())
    log.startLogging(sys.stdout)
    reactor.run()
# This runs the program in the background. __name__ is __builtin__ when you use
# twistd -y on a python module.
elif __name__ == '__builtin__':
    ircService = internet.TCPClient(config.HOST, config.PORT, IRCBotFactory())
    ircService.setServiceParent(application)
# TODO add log in service
