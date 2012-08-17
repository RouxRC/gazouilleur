#!/bin/python
# -*- coding: utf-8 -*-

import sys, os.path, types, re
import datetime, time
import lxml.html
import pymongo
from twisted.internet import reactor, defer, protocol, threads
from twisted.python import log
from twisted.words.protocols import irc
from twisted.web.client import getPage
from twisted.application import internet, service
import config
sys.path.append('lib')
from filelogger import FileLogger
from utils import *
from microblog import *

class IRCBot(irc.IRCClient):

    def __init__(self):
        #NickServ identification handled automatically by twisted
        self.nickname = config.BOTNAME
        self.username = config.BOTNAME
        self.password = config.BOTPASS
        self.nicks = {}
        self.sourceURL = 'https://github.com/RouxRC/gazouilleur'
        self.db = pymongo.Connection(config.MONGODB['HOST'], config.MONGODB['PORT'])[config.MONGODB['DATABASE']]
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])

    # Double logger (mongo / files)
    def log(self, message, user=None, channel=config.BOTNAME):
        if channel == "*" or channel == self.nickname or channel not in self.logger:
            channel = config.BOTNAME
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
        self.logger[channel].log(message)
        if user:
            return nick, user

  # -------------------
  # Connexion loggers

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

    def joined(self, channel):
        log.msg("Joined %s." % (channel,))
        self.logger[channel] = FileLogger(channel)
        self.log("[joined at %s]" % time.asctime(time.localtime(time.time())), None, channel)

    def left(self, channel):
        log.msg("Left %s." % (channel,))
        self.log("[left at %s]" % time.asctime(time.localtime(time.time())), None, channel)
        self.logger[channel].close()

  # ----------------------------------
  # Identification when nickname used

    def _reclaimNick(self):
        if config.BOTPASS:
            self.msg("NickServ", 'regain %s %s' % (config.BOTNAME, config.BOTPASS,))
            self.msg("NickServ", 'identify %s %s' % (config.BOTNAME, config.BOTPASS,))
            log.msg("Reclaimed ident as %s." % (config.BOTNAME,))

    def nickChanged(self, nick):
        log.msg("Identified as %s." % (nick,))
        if nick != config.BOTNAME:
            self._reclaimNick()

    def noticed(self, user, channel, message):
        if 'is not a registered nickname' in message and 'NickServ' in user:
            self._reclaimNick()
        self.log(message, user)

  # ------------------------
  # Users connexions logger

    def userJoined(self, user, channel):
        self.log("[%s joined]" % user, user, channel)

    def userLeft(self, user, channel, reason=None):
        msg = "[%s left" % user
        if reason:
            msg += " (%s)]" % reason
        msg += "]"
        self.log(msg, user, channel)

    def _get_user_channels(self, nick):
        res = []
        for c in self.factory.channels:
            last_log = self.db['logs'].find_one({'channel': c, 'user': nick.lower(), 'message': re.compile(r'^\[[^\[]*'+nick+'[\s\]]', re.I)}, fields=['message'], sort=[('timestamp', pymongo.DESCENDING)])
            if last_log and not last_log['message'].encode('utf-8').endswith(' left]'):
                res.append(c)
        return res

    def userQuit(self, user, quitMessage):
        nick, _, _ = user.partition('!')
        for c in self._get_user_channels(nick):
            self.userLeft(nick, c, quitMessage)

    def userRenamed(self, oldnick, newnick):
        for c in self._get_user_channels(oldnick):
            self.log("[%s changed nickname to %s]" % (oldnick, newnick), oldnick, c)

  # -------------------
  # Command controller

    # Identify function corresponding to a parsed command
    def _find_command_function(self, command):
        return getattr(self, 'command_' + command.lower(), None)

    def _get_command_doc(self, command):
        if not isinstance(command, types.MethodType):
            command = self._find_command_function(command)
        return command.__doc__

    def _can_user_do(self, nick, channel, command, conf=None):
        return has_user_rights_in_doc(nick, channel, self._get_command_doc(command))

    def privmsg(self, user, channel, message):
        try:
            message = message.decode('utf-8')
        except UnicodeDecodeError:
            try:
                message = message.decode('iso-8859-1')
            except UnicodeDecodeError:
                message = message.decode('cp1252')
        message = cleanblanks(message)
        nick, user = self.log(message, user, channel)
        d = None
        if not message.startswith('!'):
            if self.nickname.lower() in message.lower():
                d = defer.maybeDeferred(self.command_test)
            else:
                return
        message = message.encode('utf-8')
        if config.DEBUG:
            log.msg("[%s] COMMAND: %s: %s" % (channel, user, message))
        command, _, rest = message.lstrip('!').partition(' ')
        func = self._find_command_function(command)
        if func is None and d is None:
            d = defer.maybeDeferred(self.command_help, command, channel)
        target = nick if channel == self.nickname else channel
        if d is None:
            if self._can_user_do(nick, channel, func):
                d = defer.maybeDeferred(func, rest, channel, nick)
            else:
               return self._send_message("Sorry, you don't have the rights to use this command in this channel.", target, nick)
        d.addCallback(self._send_message, target, nick)
        d.addErrback(self._show_error, target, nick)

    def _send_message(self, msgs, target, nick=None):
        if config.DEBUG:
            log.msg("[%s] REPLIED: %s" % (target, msgs))
        if msgs is None:
            return
        if not isinstance(msgs, types.ListType):
            msgs = str(msgs).strip()
            msgs = [(True, m) for m in msgs.split('\n')]
        uniq = {}
        for res, msg in msgs:
            if not res:
                self._show_error(msg, target, nick)
            elif msg in uniq:
                continue
            else:
                uniq[msg] = None
            if nick and target != nick:
                msg = '%s: %s' % (nick, msg)
            self.msg(target, msg)
            self.log(msg.decode('utf-8'), self.nickname, target)

    def _show_error(self, failure, target, nick=None):
        failure.trap(Exception)
        log.msg("ERROR: %s" % failure)
        msg = "%s: Woooups, something is wrong..." % nick
        if config.DEBUG:
            msg += "\n%s" % failure.getErrorMessage()
        self.msg(target, msg)
        if config.ADMINS:
            for user in config.ADMINS:
                self.msg(user, "[%s] %s" % (target, str(failure)))

  # -----------------
  # Default commands

    def command_help(self, rest, channel=None, nick=None):
        """!help [<command>]: Prints general help or help for specific <command>."""
        rest = rest.lstrip('!')
        conf = chanconf(channel)
        commands = [c for c in [c.replace('command_', '') for c in dir(IRCBot) if c.startswith('command_')] if self._can_user_do(nick, channel, c, conf)]
        def_msg = 'My commands are:  !'+' ;  !'.join(commands)+'\nType "!help <command>" to get more details.'
        if rest is None or rest == '':
            return def_msg
        elif rest in commands:
            return clean_doc(self._get_command_doc(rest))
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

  # ------------------
  # LogQuery commands

    re_extract_digit = re.compile(r'(^|[^t])\s+(\d)+\s+')
    def _extract_digit(self, string):
        if string.strip().isdigit():
            return int(string), ''
        string = " %s " % string
        nb = 1
        res = self.re_extract_digit.search(string)
        if res:
            nb = safeint(res.group(2))
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
            command, _, text = m['message'].encode('utf-8').lstrip('!').partition(' ')
            if command == "lastseen":
                continue
            res = self.re_optionstart.search(text)
            if res:
                st = safeint(res.group(1))
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

    def command_last(self, rest, channel=None, nick=None, reverse=False):
        """!last [<N>] [--from <nick>] [--with <text>] [--start <nb>] : Prints the last or <N> (max 5) last message(s), optionnally starting back <nb> results earlier and filtered by user <nick> and by <word>."""
        # For private queries, give priority to first listed chan for the use of !last commands
        if channel == self.nickname:
            channel = self.factory.channels[0]
        query = {'channel': channel, 'message': {'$not': self.re_lastcommand}, '$or': [{'user': {'$ne': self.nickname.lower()}}, {'message': {'$not': re.compile(r'^('+self.nickname+' —— )?('+nick+': \D|[^\s:]+: (!|\[\d))')}}]}
        nb = 1
        st = 0
        current = ""
        rest = cleanblanks(handle_quotes(rest))
        for arg in rest.split(' '):
            if current == "f":
                query['user'] = arg.lower()
                current = ""
            elif current == "w":
                query['message']['$regex'] = re.compile("%s" % arg, re.I)
                current = ""
            elif current == "s":
                st = max(st, safeint(arg))
                current = ""
            elif arg.isdigit():
                nb = max(nb, min(safeint(arg), 5))
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
        if reverse:
            matches.reverse()
        return "\n".join(['[%s] %s — %s' % (shortdate(l['timestamp']), l['screenname'].encode('utf-8'), l['message'].encode('utf-8')) for l in matches])

    def command_lastseen(self, rest, channel=None, nick=None):
        """!lastseen <nickname> : Prints the last time <nickname> was seen logging off and in."""
        user, _, msg = rest.partition(' ')
        if user == '':
            return "Please ask for a specific nickname."
        re_user = re.compile(r'^\[[^\[]*'+user, re.I)
        res = list(self.db['logs'].find({'channel': channel, 'user': user.lower(), 'message': re_user}, fields=['timestamp', 'message'], sort=[('timestamp', pymongo.DESCENDING)], limit=2))
        if res:
            res.reverse()
            return " —— ".join(["%s %s" % (shortdate(m['timestamp']), m['message'].encode('utf-8')[1:-1]) for m in res])
        return self.command_lastfrom(user, channel, nick)

  # ---------------
  # Count commands

    def command_count(self, rest, *args):
        """!count <text> : Prints the character length of <text> (spaces will be trimmed, urls will be shortened to 20 chars)."""
        return threads.deferToThread(lambda x: str(countchars(x))+" characters (max 140)", rest)

    def command_lastcount(self, rest, channel=None, nick=None):
        """!lastcount : Prints the latest !count command and its result"""
        return self.command_last("2 --with ^!count|\S+:\s\d+\scharacters", channel, nick, True)

  # -------------------------------------
  # Twitter / Identi.ca sending commands

    re_nolimit = re.compile(r'\s*--nolimit\s*')
    def _match_nolimit(self, text):
        if self.re_nolimit.search(text):
            return self.re_nolimit.sub(' ', text).strip(), True
        return text, False

    def _send_via_protocol(self, protocol, command, channel, nick, **kwargs):
        conf = chanconf(channel)
        if not chan_has_protocol(channel, protocol, conf):
            return "No %s account is set for this channel." % protocol
        if 'tweet' in kwargs:
            kwargs['tweet'], nolimit = self._match_nolimit(kwargs['tweet'])
            ct = countchars(kwargs['tweet'])
            if ct < 30 and not nolimit:
                return "Do you really want to send such a short message? (%s chars) add --nolimit to override" % ct
            elif ct > 140:
                return "Too long (%s characters)" % ct
        a = Sender(protocol, conf)
        command = getattr(a, command, None)
        return command(**kwargs)

    def command_identica(self, tweet, channel=None, nick=None):
        """!identica <text> [--nolimit]: Posts message <text> on Identi.ca (--nolimit overrides the minimum 30 characters rule)./TWITTER"""
        return threads.deferToThread(self._send_via_protocol, 'identica', 'microblog', channel, nick, tweet=tweet)

    def command_twitteronly(self, tweet, channel=None, nick=None):
        """!twitteronly <text> [--nolimit]: Posts message <text> on Twitter (--nolimit overrides the minimum 30 characters rule)./TWITTER"""
        return threads.deferToThread(self._send_via_protocol, 'twitter', 'microblog', channel, nick, tweet=tweet)

    def command_twitter(self, tweet, channel=None, nick=None):
        """!twitter <text> [--nolimit] : Posts message <text> on Identi.ca and Twitter (--nolimit overrides the minimum 30 characters rule)./TWITTER"""
        d1 = defer.maybeDeferred(self.command_twitteronly, tweet, channel, nick)
        d2 = defer.maybeDeferred(self.command_identica, tweet, channel, nick)
        return defer.DeferredList([d1, d2])

    def command_rt(self, tweetid, channel=None, nick=None):
        """!rt <tweet_id> : (twitter)./TWITTER"""
        # + post sur identica RT
        return TODO

    def command_answer(self, rest, channel=None, nick=None):
        """!answer <tweetid> <text> : ./TWITTER"""
        #TODO parse rest
        return threads.deferToThread(self._send_via_protocol, 'twitter', 'answer', channel, nick, tweetid=tweetid, tweet=text)

    def command_dm(self, rest, channel=None, nick=None):
        """!dm <user> <text> : ./TWITTER"""
        #TODO parse rest
        return threads.deferToThread(self._send_via_protocol, 'twitter', 'directmsg', channel, nick, user=user, tweet=text)

  # ----------------------------
  # Twitter monitoring commands

    def command_follow(self, tweet, *args):
        """!follow <text> : ./AUTH"""
        return "TODO"

    def command_unfollow(self, tweet, *args):
        """!unfollow <text> : ./AUTH"""
        return "TODO"

    def command_lasttweet(self, tweet, *args):
        """!lasttweet <text> : ./AUTH"""
        return "TODO"

  # ------------------
  # Other commands...

    def command_saylater(self, rest, *args):
        """!saylater <seconds> <message> : Makes me say <message> in <seconds> seconds."""
        when, _, msg = rest.partition(' ')
        when = min(1, safeint(when))
        d = defer.Deferred()
        reactor.callLater(when, d.callback, msg)
        return d

    def command_title(self, url, *args):
        """!title <url> : Prints the title of the webpage at <url>."""
        d = getPage(url)
        d.addCallback(self._parse_pagetitle, url)
        return d

    def _parse_pagetitle(self, page_contents, url):
        pagetree = lxml.html.fromstring(page_contents)
        title = u' '.join(pagetree.xpath('//title/text()')).strip()
        title = title.encode('utf-8')
        return '%s -- "%s"' % (url, title)


# Auto-reconnecting Factory
class IRCBotFactory(protocol.ReconnectingClientFactory):
    protocol = IRCBot
    channels = ["#" + c for c in config.CHANNELS.keys()]


# Run as 'python bot.py' ...
if __name__ == '__main__':
    reactor.connectTCP(config.HOST, config.PORT, IRCBotFactory())
    log.startLogging(sys.stdout)
    reactor.run()
# ... or in the background when called with 'twistd -y bot.py'
elif __name__ == '__builtin__':
    application = service.Application('Gazouilleur IRC Bot')
    ircService = internet.TCPClient(config.HOST, config.PORT, IRCBotFactory())
    ircService.setServiceParent(application)
    log.startLogging(open(os.path.relpath('run.log'), 'w'))

