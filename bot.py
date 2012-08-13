#!/bin/python
# -*- coding: utf-8 -*-

import sys, os, os.path, types, re
import datetime, time
import lxml.html
import pymongo
from inspect import getdoc
from twisted.internet import reactor, defer, protocol
from twisted.python import log
from twisted.words.protocols import irc
from twisted.web.client import getPage
from twisted.application import internet, service
import config

def sint(s):
    try:
        return int(s.strip())
    except:
        return 0

def chanconf(channel):
    if channel:
        channel = channel.lstrip('#')
    return config.CHANNELS[channel]

class FileLogger:
    def __init__(self, channel=''):
        filename = config.BOTNAME
        if channel:
            filename += '_' + channel
        filename += '.log'
        if not os.path.isdir('log'):
            os.mkdir('log')
        self.file = open(os.path.join('log', filename), "a")

    def log(self, message):
        timestamp = time.strftime("[%H:%M:%S]", time.localtime(time.time()))
        self.file.write('%s %s\n' % (timestamp, message))
        self.file.flush()

    def close(self):
        self.file.close()

class IRCBot(irc.IRCClient):

    def __init__(self):
        #NickServ identification handled automatically
        self.nickname = config.BOTNAME
        self.username = config.BOTNAME
        self.password = config.BOTPASS
        self.nicks = {}
        self.sourceURL = 'https://github.com/RouxRC/gazouilleur'
        self.db = pymongo.Connection(config.MONGODB['HOST'], config.MONGODB['PORT'])[config.MONGODB['DATABASE']]
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])

    def log(self, message, user=None, channel=config.BOTNAME):
        if user:
            nick, _, host = user.partition('!')
            if channel not in self.nicks:
                self.nicks[channel] = {}
            if nick not in self.nicks[channel] or self.nicks[channel][nick] != host:
                self.nicks[channel][nick] = host
            else:
                user = nick
            host = self.nicks[channel][nick]
            self.db['logs'].insert({'timestamp': datetime.datetime.today(), 'channel': channel, 'user': nick.lower(), 'screenname': nick, 'host': host, 'message': message})
            if nick+" changed nickname to " in message:
                oldnick = message[1:-1].replace(nick+" changed nickname to ", '')
                self.db['logs'].insert({'timestamp': datetime.datetime.today(), 'channel': channel, 'user': oldnick.lower(), 'screenname': oldnick, 'host': host, 'message': message})
            message = "%s: %s" % (user, message)
        if channel == "*" or channel == self.nickname or channel not in self.logger:
            channel = config.BOTNAME
        self.logger[channel].log(message)

    def connectionMade(self):
        irc.IRCClient.connectionMade(self)
        log.msg('Connection made')
        self.logger = {config.BOTNAME: FileLogger()}
        self.log("[connected at %s]" % time.asctime(time.localtime(time.time())))

    def connectionLost(self, reason):
        irc.IRCClient.connectionLost(self, reason)
        for channel in self.factory.channels:
            self.left(channel)
        log.msg('Connection lost because: %s.' % (reason,))
        self.log("[disconnected at %s]" % time.asctime(time.localtime(time.time())))
        self.logger[config.BOTNAME].close()

    def signedOn(self):
        log.msg("Signed on as %s." % (self.nickname,))
        for channel in self.factory.channels:
            self.join(channel)

    @defer.inlineCallbacks
    def _reclaimNick(self):
        if config.BOTPASS:
            yield self.msg("NickServ", 'regain %s %s' % (config.BOTNAME, config.BOTPASS,))
            yield self.msg("NickServ", 'identify %s %s' % (config.BOTNAME, config.BOTPASS,))
            log.msg("Reclaimed ident as %s." % (config.BOTNAME,))

    def nickChanged(self, nick):
        log.msg("Identified as %s." % (nick,))
        if nick != config.BOTNAME:
            self._reclaimNick()

    def noticed(self, user, channel, message):
        if 'is not a registered nickname' in message and 'NickServ' in user:
            self._reclaimNick()
        self.log(message, user)

    def joined(self, channel):
        log.msg("Joined %s." % (channel,))
        self.logger[channel] = FileLogger(channel)
        self.log("[joined at %s]" % time.asctime(time.localtime(time.time())), None, channel)

    def left(self, channel):
        log.msg("Left %s." % (channel,))
        self.log("[left at %s]" % time.asctime(time.localtime(time.time())), None, channel)
        self.logger[channel].close()

    def userJoined(self, user, channel):
        self.log("[%s joined]" % user, user, channel)

    def userLeft(self, user, channel, message=None):
        if message:
            message = "[%s left (%s)]" % (user, message)
        else:
            message = "[%s left]" % user
        self.log(message, user, channel)

    def _get_user_channels(self, nick):
        res = []
        for c in self.factory.channels:
            last_log = self.db['logs'].find_one({'channel': c, 'user': nick.lower(), 'message': re.compile(r'^\[[^\[]*'+nick+'[\s\]]', re.I)}, fields=['message'], sort=[('timestamp', pymongo.DESCENDING)])
            if last_log and not last_log['message'].endswith(' left]'):
                res.append(c)
        return res

    def userQuit(self, user, quitMessage):
        nick, _, _ = user.partition('!')
        for c in self._get_user_channels(nick):
            self.userLeft(nick, c, quitMessage)

    def userRenamed(self, oldnick, newnick):
        for c in self._get_user_channels(oldnick):
            self.log("[%s changed nickname to %s]" % (oldnick, newnick), oldnick, c)

    def _find_command_function(self, command):
        return getattr(self, 'command_' + command.lower(), None)

    def privmsg(self, user, channel, message):
        nick, _, _ = user.partition('!')
        message = message.strip()
        self.log(message, user, channel)
        d = None
        if not message.startswith('!'):
            if self.nickname.lower() in message.lower():
                d = defer.maybeDeferred(self.command_test)
            else:
                return
        log.msg("[%s] Received command from user %s: %s" % (channel, user, message))
        command, _, rest = message.lstrip('!').partition(' ')
        func = self._find_command_function(command)
        if func is None and d is None:
            d = defer.maybeDeferred(self.command_help, command, channel)
        if d is None:
            d = defer.maybeDeferred(func, rest, channel, nick)
        d.addErrback(self._show_error)
        if channel == self.nickname:
            d.addCallback(self._send_message, nick)
        else:
            d.addCallback(self._send_message, channel, nick)

#TODO apply
    def _check_user_rights(self, nick, channel):
        if nick not in config.GLOBAL_USERS and channel in self.factory.channels and ('USERS' not in chanconf(channel) or nick not in chanconf(channel)['USERS']):
            return 'Sorry only registered users are allowed to use me'
        return

    @defer.inlineCallbacks
    def _send_message(self, msg, target, nick=None):
        if not isinstance(msg, types.ListType):
            msgs = [(1, m) for m in msg.split('\n')]
        for m in [msg for (res, msg) in msgs if res]:
            if nick:
                m = '%s: %s' % (nick, m)
            yield self.msg(target, m)
            yield self.log(m, self.nickname, target)

    def _show_error(self, failure):
        return failure.getErrorMessage()

    def command_help(self, rest, channel=None, *args):
        """!help [<command>]: Prints general help or help for specific <command>."""
        rest = rest.lstrip('!').lower()
        commands = [c.lstrip('command_') for c in dir(IRCBot) if c.startswith('command_')]
        if channel not in self.factory.channels or 'TWITTER' not in chanconf(channel):
            commands = [c for c in commands if not 'twitter' in self._find_command_function(c).__doc__.lower()]
        def_msg = 'My commands are:  !'+' ;  !'.join(commands)+'\nType "!help <command>" to get more details.'
        if rest == '':
            return def_msg
        elif rest in commands:
            return self._find_command_function(rest).__doc__
        return '!%s is not a valid command. %s' % (rest, def_msg)

    def command_ping(self, *args):
        """!ping : Ping test, should answer pong."""
        return 'Pong.'

    def command_test(self, *args):
        """!test : Simple test to check whether I'm present, similar as !ping."""
        return 'Hello! Type "!help" to list my commands.'

    def command_source(self, *args):
        """!source : Gives the link to my sourcecode."""
        return 'My sourcecode is under free GPL 3.0 licence and available at the following address: %s' % self.sourceURL

    re_extract_digit = re.compile(r'(^|[^t])\s+(\d)+\s+')
    def _extract_digit(self, string):
        if string.strip().isdigit():
            return int(string), ''
        string = " %s " % string
        nb = 1
        res = self.re_extract_digit.search(string)
        if res:
            nb = sint(res.group(2))
            string = self.re_extract_digit.sub(r'\1 ', string, 1)
        return nb, string

    def command_lastfrom(self, rest, channel=None, nick=None):
        """!lastfrom <nick> [<N>] : Alias for "!last --from", prints the last or <N> (max 5) last message(s) from user <nick>."""
        nb, fromnick = self._extract_digit(rest)
        return self.command_last("%s --from %s" % (nb, fromnick), channel, nick)

    def command_lastwith(self, rest, channel=None, nick=None):
        """!lastwith <word> [<N>] : Alias for "!last --with", prints the last or <N> (max 5) last message(s) matching <word>."""
        nb, word = self._extract_digit(rest)
        return self.command_last("%s --with %s" % (nb, word), channel, nick)

    re_shortdate = re.compile(r'^....-(..)-(..)( ..:..).*$')
    def _shortdate(self, date):
        return self.re_shortdate.sub(r'\2/\1\3', str(date))

    re_lastcommand = re.compile(r'^!last', re.I)
    re_optionstart = re.compile(r'\s*--start\s*(\d*)\s*', re.I)
    def command_lastmore(self, rest, channel=None, nick=None):
        """!lastmore [<N>] : Prints 1 or <N> more result(s) (max 5) from previous !last !lastwith or !lastfrom command"""
        nb, rest = self._extract_digit(rest)
        ct = 0
        st = 0
        tmprest = ""
        last = self.db['logs'].find({'channel': channel, 'message': self.re_lastcommand, 'user': nick.lower()}, fields=['message'], sort=[('timestamp', pymongo.DESCENDING)], skip=1)
        for m in last:
            command, _, text = str(m['message']).lstrip('!').partition(' ')
            if command == "lastseen":
                continue
            res = self.re_optionstart.search(text)
            if res:
                st = sint(res.group(1))
                text = self.re_optionstart.sub(' ', text)
            ct2, text = self._extract_digit(text)
            ct += min(ct2, 5)
            if command == "lastmore":
                tmprest += " %s" % text
            else:
                function = self._find_command_function(command)
                rest = " ".join([text, tmprest, rest])
                if function:
                    return function("%s %s --start %s" % (nb, rest, st+ct), channel, nick)
        return ""

    re_clean_blanks = re.compile(r'\s+')
    def command_last(self, rest, channel=None, nick=None):
        """!last [<N>] [--from <nick>] [--with <text>] [--start <nb>] : Prints the last or <N> (max 5) last message(s), optionnally starting back <nb> results earlier and filtered by user <nick> and by <word>."""
        if channel == self.nickname:
            channel = self.factory.channels[0]
        query = {'channel': channel, 'message': {'$not': self.re_lastcommand}, '$or': [{'user': {'$ne': self.nickname.lower()}}, {'message': {'$not': re.compile(r'^('+nick+': |[^\s:]+: (!|\[\d))')}}]}
        nb = 1
        st = 0
        current = ""
        rest = self.re_clean_blanks.sub(' ', rest)
        for arg in rest.split(' '):
            if current == "f":
                query['user'] = arg.lower()
                current = ""
            elif current == "w":
                query['message']['$regex'] = re.compile("%s" % arg, re.I)
                current = ""
            elif current == "s":
                st = max(st, sint(arg))
                current = ""
            elif arg.isdigit():
                nb = max(nb, min(sint(arg), 5))
            elif arg == "--from":
                current = "f"
            elif arg == "--with":
                current = "w"
            elif arg == "--start":
                current = "s"
        matches = list(self.db['logs'].find(query, sort=[('timestamp', pymongo.DESCENDING)], fields=['timestamp', 'screenname', 'message'], limit=nb, skip=st))
        if len(matches) == 0:
            more = " more" if st > 1 else ""
            return "No"+more+" match found in my history log."
        matches.reverse()
        return "\n".join(['[%s] %s — %s' % (self._shortdate(l['timestamp']), l['screenname'].encode('utf-8'), l['message'].encode('utf-8')) for l in matches])

    def command_lastseen(self, rest, channel=None, *args):
        """!lastseen <nickname> : Prints the last time <nickname> was seen logging off and in."""
        nick, _, msg = rest.partition(' ')
        re_nick = re.compile(r'^\[[^\[]*'+nick, re.I)
        res = list(self.db['logs'].find({'channel': channel, 'user': nick.lower(), 'message': re_nick}, fields=['timestamp', 'message'], sort=[('timestamp', pymongo.DESCENDING)], limit=2))
        msg = "Cannot find traces of %s in my history log." % nick
        if res:
            res.reverse()
            msg = " —— ".join(["%s %s" % (self._shortdate(m['timestamp']), m['message'].encode('utf-8')[1:-1]) for m in res])
        return msg

    def command_saylater(self, rest, *args):
        """!saylater <seconds> <message> : Makes me say <message> in <seconds> seconds."""
        when, _, msg = rest.partition(' ')
        when = sint(when)
        d = defer.Deferred()
        # A small example of how to defer the reply from a command. callLater
        # will callback the Deferred with the reply after so many seconds.
        reactor.callLater(when, d.callback, msg)
        # Returning the Deferred here means that it'll be returned from
        # maybeDeferred in privmsg.
        return d

    def command_title(self, url, *args):
        """!title <url> : Prints the title of the webpage at <url>."""
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
    channels = ["#" + c for c in config.CHANNELS.keys()]

if __name__ == '__main__':
    reactor.connectTCP(config.HOST, config.PORT, IRCBotFactory())
    log.startLogging(sys.stdout)
    reactor.run()
# This runs the program in the background. __name__ is __builtin__ when you use
# twistd -y on a python module.
elif __name__ == '__builtin__':
    application = service.Application('Gazouilleur IRC Bot')
    ircService = internet.TCPClient(config.HOST, config.PORT, IRCBotFactory())
    ircService.setServiceParent(application)
    log.startLogging(open(os.path.relpath('run.log'), 'w'))
