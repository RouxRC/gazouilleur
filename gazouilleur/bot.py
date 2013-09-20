#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gazouilleur.lib.tests
from gazouilleur import config

import sys, os.path, types, re
import random, time
from datetime import datetime
import lxml.html
import pymongo
from twisted.internet import reactor, defer, protocol, threads
from twisted.words.protocols.irc import IRCClient
from twisted.web.client import getPage
from twisted.application import internet, service
from twisted.python import log
from gazouilleur.lib.ircclient_with_names import NamesIRCClient
from gazouilleur.lib.log import *
from gazouilleur.lib.utils import *
from gazouilleur.lib.filelogger import FileLogger
from gazouilleur.lib.microblog import Microblog
from gazouilleur.lib.feeds import FeederFactory
from gazouilleur.lib.stats import Stats

reactor.suggestThreadPoolSize(15*len(config.CHANNELS))

class IRCBot(NamesIRCClient):

    lineRate = 0.75

    def __init__(self):
        #NickServ identification handled automatically by twisted
        NamesIRCClient.__init__(self)
        self.nickname = config.BOTNAME
        self.username = config.BOTNAME
        self.password = config.BOTPASS
        self.breathe = datetime.today()
        self.nicks = {}
        self.tasks = []
        self.feeders = {}
        self.filters = {}
        self.silent = {}
        self.lastqueries = {}
        self.twitter_users = {}
        self.sourceURL = 'https://github.com/RouxRC/gazouilleur'
        self.db = pymongo.Connection(config.MONGODB['HOST'], config.MONGODB['PORT'])[config.MONGODB['DATABASE']]
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        self.db['logs'].ensure_index([('channel', pymongo.ASCENDING), ('timestamp', pymongo.DESCENDING)], background=True)
        self.db['logs'].ensure_index([('channel', pymongo.ASCENDING), ('user', pymongo.ASCENDING), ('timestamp', pymongo.DESCENDING)], background=True)
        self.db['feeds'].ensure_index([('channel', pymongo.ASCENDING), ('database', pymongo.ASCENDING), ('timestamp', pymongo.DESCENDING)], background=True)
        self.db['filters'].ensure_index([('channel', pymongo.ASCENDING), ('keyword', pymongo.ASCENDING), ('timestamp', pymongo.DESCENDING)], background=True)
        self.db['tweets'].ensure_index([('channel', pymongo.ASCENDING), ('id', pymongo.ASCENDING), ('timestamp', pymongo.DESCENDING)], background=True)
        self.db['lasttweets'].ensure_index([('channel', pymongo.ASCENDING)], background=True)
        self.db['tweets'].ensure_index([('channel', pymongo.ASCENDING), ('user', pymongo.ASCENDING), ('timestamp', pymongo.DESCENDING)], background=True)
        self.db['tweets'].ensure_index([('uniq_rt_hash', pymongo.ASCENDING)], background=True)
        self.db['news'].ensure_index([('channel', pymongo.ASCENDING), ('timestamp', pymongo.DESCENDING)], background=True)
        self.db['news'].ensure_index([('channel', pymongo.ASCENDING), ('source', pymongo.ASCENDING), ('timestamp', pymongo.DESCENDING)], background=True)

    # Double logger (mongo / files)
    def log(self, message, user=None, channel=config.BOTNAME, filtered=False):
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
            self.db['logs'].insert({'timestamp': datetime.today(), 'channel': channel, 'user': nick.lower(), 'screenname': nick, 'host': host, 'message': message, 'filtered': filtered})
            if nick+" changed nickname to " in message:
                oldnick = message[1:-1].replace(nick+" changed nickname to ", '')
                self.db['logs'].insert({'timestamp': datetime.today(), 'channel': channel, 'user': oldnick.lower(), 'screenname': oldnick, 'host': host, 'message': message})
            message = "%s: %s" % (user, message)
        self.logger[channel].log(message, filtered)
        if user:
            return nick, user

  # -------------------
  # Connexion loggers

    def connectionMade(self):
        loggirc('Connection made')
        self.logger = {config.BOTNAME: FileLogger()}
        self.log("[connected at %s]" % time.asctime(time.localtime(time.time())))
        IRCClient.connectionMade(self)

    def connectionLost(self, reason):
        for channel in self.factory.channels:
            self.left(channel)
        loggirc2('Connection lost because: %s.' % reason)
        self.log("[disconnected at %s]" % time.asctime(time.localtime(time.time())))
        self.logger[config.BOTNAME].close()
        IRCClient.connectionLost(self, reason)

    def signedOn(self):
        loggirc("Signed on as %s." % self.nickname)
        for channel in self.factory.channels:
            self.join(channel)

    def joined(self, channel):
        loggirc("Joined.", channel)
        self.logger[channel] = FileLogger(channel)
        self.log("[joined at %s]" % time.asctime(time.localtime(time.time())), None, channel)
        if channel == "#gazouilleur":
            return
        self.lastqueries[channel] = {'n': 1, 'skip': 0}
        self.filters[channel] = [keyword['keyword'] for keyword in self.db['filters'].find({'channel': channel}, fields=['keyword'])]
        self.silent[channel] = datetime.today()
        self.feeders[channel] = {}
        conf = chanconf(channel)
        if 'TWITTER' in conf and 'USER' in conf['TWITTER']:
        # Get OAuth2 tokens for twitter search
            try:
                oauth2_token = Microblog("twitter", conf, get_token=True).get_oauth2_token()
                loggvar("Got OAuth2 token for %s on Twitter." % conf['TWITTER']['USER'], channel, "twitter")
        # Follow Searched Tweets matching queries set for this channel with !follow via Twitter's API App only extra limitrate
                self.feeders[channel]['twitter_search'] = FeederFactory(self, channel, 'tweets', 90, twitter_token=oauth2_token)
            except Exception as e:
                oauth2_token = None
                loggerr("Could not get an OAuth2 token from Twitter for user @%s: %s" % (conf['TWITTER']['USER'], e), channel, "twitter")
        # Follow Searched Tweets matching queries set for this channel with !follow via more rate limited Twitter's regular API
                self.feeders[channel]['twitter_search'] = FeederFactory(self, channel, 'tweets', 180)
        # Follow Searched Tweets matching queries set for this channel with !follow via Twitter's streaming API
            self.feeders[channel]['stream'] = FeederFactory(self, channel, 'stream', 20, twitter_token=oauth2_token)
        # Follow Stats for Twitter USER
            if chan_has_twitter(channel, conf):
                self.feeders[channel]['stats'] = FeederFactory(self, channel, 'stats', 600)
        # Follow Tweets sent by Twitter USER
                self.feeders[channel]['mytweets_T'] = FeederFactory(self, channel, 'mytweets', 10 if oauth2_token else 20, twitter_token=oauth2_token)
            # Deprecated 
            # Follow Tweets sent by and mentionning Twitter USER via IceRocket.com
            #   self.feeders[channel]['mytweets'] = FeederFactory(self, channel, 'tweets', 289, 20, [getIcerocketFeedUrl('%s+OR+@%s' % (conf['TWITTER']['USER'], conf['TWITTER']['USER']))], tweetsSearchPage='icerocket')
            # ... or via IceRocket.com old RSS feeds
            #   self.feeders[channel]['mytweets'] = FeederFactory(self, channel, 'tweets', 89, 20, [getIcerocketFeedUrl('%s+OR+@%s' % (conf['TWITTER']['USER'], conf['TWITTER']['USER']), rss=True)])
            # ... or via Topsy.com
            #   self.feeders[channel]['mytweets'] = FeederFactory(self, channel, 'tweets', 289, 20, [getTopsyFeedUrl('%s+OR+@%s' % (conf['TWITTER']['USER'], conf['TWITTER']['USER']))], tweetsSearchPage='topsy')
        # Follow ReTweets of tweets sent by Twitter USER
                self.feeders[channel]['retweets'] = FeederFactory(self, channel, 'retweets', 360)
        # Follow Mentions of Twitter USER in tweets
            self.feeders[channel]['mentions'] = FeederFactory(self, channel, 'mentions', 90)
        # Follow DMs sent to Twitter USER
            self.feeders[channel]['dms'] = FeederFactory(self, channel, 'dms', 90)
        else:
        # Follow Searched Tweets matching queries set for this channel with !follow via IceRocket.com since no Twitter account is set
            self.feeders[channel]['tweets'] = FeederFactory(self, channel, 'tweets', 277, 25, tweetsSearchPage='icerocket')
        # ... or via Topsy.com
        #   self.feeders[channel]['tweets'] = FeederFactory(self, channel, 'tweets', 277, 25, tweetsSearchPage='icerocket')
        # Follow RSS Feeds matching url queries set for this channel with !follow
        self.feeders[channel]['news'] = FeederFactory(self, channel, 'news', 299, 20)
        n = self.factory.channels.index(channel.lower()) + 1
        for i, f in enumerate(self.feeders[channel].keys()):
            threads.deferToThread(reactor.callLater, 7*(i+1)*n, self.feeders[channel][f].start)

    def left(self, channel):
        for chan in self.feeders.keys():
            if channel.lower() == chan.lower():
                channel = chan
        if channel in self.feeders:
            for f in self.feeders[channel].keys():
                self.feeders[channel][f].end()
        if channel in self.logger:
            self.logger[channel].close()
        loggirc2("Left.", channel)
        self.log("[left at %s]" % time.asctime(time.localtime(time.time())), None, channel)

  # ----------------------------------
  # Identification when nickname used

    def _reclaimNick(self):
        if config.BOTPASS and config.BOTPASS != '':
            self.msg("NickServ", 'regain %s %s' % (config.BOTNAME, config.BOTPASS,))
            self.msg("NickServ", 'identify %s %s' % (config.BOTNAME, config.BOTPASS,))
            loggirc("Reclaimed ident as %s." % config.BOTNAME)
        self.nickname = config.BOTNAME

    def nickChanged(self, nick):
        loggirc("Identified as %s." % nick)
        if nick != config.BOTNAME:
            self._reclaimNick()

    def noticed(self, user, channel, message):
        loggirc("SERVER NOTICE [%s]: %s" % (user, message), channel)
        if 'is not a registered nickname' in message and 'NickServ' in user:
            self._reclaimNick()

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

    def getMasterChan(self, channel):
        if channel == self.nickname:
            channel = get_master_chan()
        return channel

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

    re_catch_command = re.compile(r'^\s*%s[:,\s]*%s' % (config.BOTNAME, config.COMMAND_CHARACTER), re.I)
    def privmsg(self, user, channel, message, tasks=None):
        try:
            message = message.decode('utf-8')
        except UnicodeDecodeError:
            try:
                message = message.decode('iso-8859-1')
            except UnicodeDecodeError:
                message = message.decode('cp1252')
        message = cleanblanks(message)
        message = self.re_catch_command.sub(config.COMMAND_CHARACTER, message)
        nick, user = self.log(message, user, channel)
        d = None
        if channel == "#gazouilleur" and not message.startswith("%schans" % config.COMMAND_CHARACTER):
            return
        if not message.startswith(config.COMMAND_CHARACTER):
            if self.nickname.lower() in message.lower() and chan_is_verbose(channel):
                d = defer.maybeDeferred(self.command_test)
            else:
                return
        message = message.encode('utf-8')
        if config.DEBUG:
            loggvar("COMMAND: %s: %s" % (user, message), channel)
        command, _, rest = message.lstrip(config.COMMAND_CHARACTER).partition(' ')
        func = self._find_command_function(command)
        if func is None and d is None:
            if chan_is_verbose(channel):
                d = defer.maybeDeferred(self.command_help, command, channel, nick)
            else:
                return
        target = nick if channel == self.nickname else channel
        if d is None:
            if self._can_user_do(nick, channel, func):
                d = defer.maybeDeferred(func, rest, channel, nick)
            else:
                if chan_is_verbose(channel):
                    return self._send_message("Sorry, you don't have the rights to use this command in this channel.", target, nick)
                return
        d.addCallback(self._send_message, target, nick, tasks=tasks)
        d.addErrback(self._show_error, target, nick)

    re_tweets = re.compile(r' — http://twitter.com/[^/\s]*/statuses/[0-9]*$', re.I)
    def msg(self, target, msg, talk=False):
        msg_utf = msg.decode('utf-8')
        skip = False
        if not talk and self.re_tweets.search(msg) and target in self.filters:
            low_msg_utf = msg_utf.lower()
            for keyword in self.filters[target]:
                if keyword and ("%s" % keyword in low_msg_utf or (keyword.startswith('@') and low_msg_utf.startswith(keyword[1:]+': '))):
                    skip = True
                    reason = keyword
                    break
        if not talk and target in self.silent and self.silent[target] > datetime.today():
            skip = True
            reason = "fuckoff until %s" % self.silent[target]
        self.log(msg_utf, self.nickname, target, filtered=skip)
        if not skip:
            IRCClient.msg(self, target, msg, 450)
        elif config.DEBUG:
            try:
                loggvar("FILTERED: %s [%s]" % (str(msg), reason), target)
            except:
                print colr("ERROR encoding filtered msg", 'red'), msg, reason
                loggvar("FILTERED: %s [%s]" % (msg, reason), target)

    re_clean_protocol = re.compile(r'^\[[^\]]+\]\s*')
    def _send_message(self, msgs, target, nick=None, tasks=None):
        if msgs is None:
            return
        if not isinstance(msgs, types.ListType):
            msgs = str(msgs).strip()
            msgs = [(True, m) for m in msgs.split('\n')]
        nb_m = len(msgs)
        if nb_m == 2 and msgs[0][0] == msgs[1][0] and self.re_clean_protocol.match(msgs[0][1]) and self.re_clean_protocol.match(msgs[1][1]) and self.re_clean_protocol.sub('', msgs[0][1]) == self.re_clean_protocol.sub('', msgs[1][1]):
            msgs = [(msgs[0][0], "[identica/twitter] %s" % self.re_clean_protocol.sub('', msgs[0][1]))]
        uniq = {}
        for res, msg in msgs:
            if not res:
                self._show_error(msg, target, admins=True)
            elif msg in uniq or (uniq and nb_m == 2 and msg.endswith("account is set for this channel.")):
                continue
            else:
                uniq[msg] = None
            talk = False
            if nick and target != nick:
                msg = '%s: %s' % (nick, msg)
                talk = True
            if tasks is not None:
                msg += " [Task #%s]" % tasks
            self.msg(target, msg, talk)

    def _show_error(self, failure, target, nick=None, admins=False):
        if not admins:
            loggerr(failure, target)
        if not nick and not admins:
            return
        msg = "Woooups, something is wrong..."
        adminmsg = "%s \n%s" % (msg, failure.getErrorMessage())
        if config.DEBUG:
            msg = adminmsg
        if config.ADMINS and (nick or admins):
            for m in adminmsg.split('\n'):
                for user in config.ADMINS:
                    self.msg(user, m)
        if nick:
            for m in msg.split('\n'):
                self.msg(target, "%s: %s" % (nick,m ))

  # -----------------
  # Default commands

    def command_help(self, rest, channel=None, nick=None):
        """help [<command>] : Prints general help or help for specific <command>."""
        rest = rest.lstrip(config.COMMAND_CHARACTER)
        conf = chanconf(channel)
        commands = [c for c in [c.replace('command_', '') for c in dir(IRCBot) if c.startswith('command_') and c != "command_more"] if self._can_user_do(nick, channel, c, conf)]
        def_msg = 'My commands are:  '+config.COMMAND_CHARACTER+(' ;  '+config.COMMAND_CHARACTER).join(commands)+'\nType "'+config.COMMAND_CHARACTER+'help <command>" to get more details.'
        if rest is None or rest == '':
            return def_msg
        elif rest in commands:
            doc = clean_doc(self._get_command_doc(rest))
            if not chan_has_identica(channel, conf):
                doc = clean_identica(doc)
            return config.COMMAND_CHARACTER + doc
        return '%s%s is not a valid command. %s' % (config.COMMAND_CHARACTER, rest, def_msg)

    def command_test(self, *args):
        """test : Simple test to check whether I'm present."""
        return 'Hello! Type "%shelp" to list my commands.' % config.COMMAND_CHARACTER

    def command_source(self, *args):
        """source : Gives the link to my sourcecode."""
        return 'My sourcecode is under free GPL 3.0 licence and available at the following address: %s' % self.sourceURL

  # ------------------
  # LogQuery commands

    re_extract_digit = re.compile(r'\s+(\d+)\s+')
    def _extract_digit(self, string):
        nb = safeint(string.strip())
        if nb:
            return nb, ''
        string = " %s " % string
        nb = 1
        res = self.re_extract_digit.search(string)
        if res:
            nb = safeint(res.group(1))
            string = self.re_extract_digit.sub(r' ', string, 1)
        return nb, string.strip()

    def command_lastfrom(self, rest, channel=None, nick=None):
        """lastfrom <nick> [<N>] : Alias for "last --from", prints the last or <N> (max 5) last message(s) from user <nick> (options from "last" except --from can apply)."""
        nb, fromnick = self._extract_digit(rest)
        return self.command_last("%s --from %s" % (nb, fromnick), channel, nick)

    def command_lastwith(self, rest, channel=None, nick=None):
        """lastwith <word> [<N>] : Alias for "last --with", prints the last or <N> (max 5) last message(s) matching <word> (options from "last" can apply)."""
        nb, word = self._extract_digit(rest)
        return self.command_last("%s --with %s" % (nb, word), channel, nick)

    re_lastcommand = re.compile(r'^%s(last|more)' % config.COMMAND_CHARACTER, re.I)
    re_optionsfromwith = re.compile(r'\s*--(from|with)\s*(\d*)\s*', re.I)
    re_optionskip = re.compile(r'\s*--skip\s*(\d*)\s*', re.I)
    def command_lastmore(self, rest, channel=None, nick=None):
        """lastmore [<N>] : Prints 1 or <N> more result(s) (max 5) from previous "last" "lastwith" "lastfrom" or "lastcount" command (options from "last" except --skip can apply; --from and --with will reset --skip to 0)."""
        master = get_master_chan(self.nickname)
        if channel == self.nickname and master != self.nickname:
            truechannel = master
        else:
            truechannel = channel
        if not rest:
            nb = self.lastqueries[truechannel]['n']
        else:
            nb, rest = self._extract_digit(rest)
        tmprest = rest
        st = self.lastqueries[truechannel]['skip']
        last = self.db['logs'].find({'channel': channel, 'message': self.re_lastcommand, 'user': nick.lower()}, fields=['message'], sort=[('timestamp', pymongo.DESCENDING)], skip=1)
        for m in last:
            command, _, text = m['message'].encode('utf-8').lstrip(config.COMMAND_CHARACTER).partition(' ')
            if command == "lastseen":
                continue
            text = self.re_optionskip.sub(' ', text)
            _, text = self._extract_digit(text)
            tmprest = "%s %s" % (text, tmprest)
            if not command.endswith('more'):
                function = self._find_command_function(command)
                if not self.re_optionsfromwith.search(rest):
                    tmprest = "%s --skip %s" % (tmprest, st)
                if command != "lastcount":
                    tmprest = "%s %s" % (nb, tmprest)
                if function:
                    return function(tmprest, channel, nick)
        return "No %slast like command found in my history log." % config.COMMAND_CHARACTER

    def command_more(self, rest, channel=None, nick=None):
        """more : Alias for "lastmore"."""
        return self.command_lastmore(rest, channel, nick)

    re_matchcommands = re.compile(r'-(-(from|with|skip|chan)|[fwsc])', re.I)
    def command_last(self, rest, channel=None, nick=None, reverse=False):
        """last [<N>] [--from <nick>] [--with <text>] [--chan <chan>] [--skip <nb>] [--filtered|--nofilter] : Prints the last or <N> (max 5) last message(s) from current or main channel if <chan> is not given, optionnally starting back <nb> results earlier and filtered by user <nick> and by <word>. --nofilter includes tweets that were not displayed because of filters, --filtered searches only through these."""
        # For private queries, give priority to master chan if set in for the use of !last commands
        nb = 0
        def_nb = 1
        master = get_master_chan(self.nickname)
        if channel == self.nickname and master != self.nickname:
            channel = master
            def_nb = 10
        re_nick = re.compile(r'^\[[^\[]*'+nick, re.I)
        query = {'channel': channel, '$and': [{'filtered': {'$ne': True}}, {'message': {'$not': self.re_lastcommand}}, {'message': {'$not': re_nick}}], '$or': [{'user': {'$ne': self.nickname.lower()}}, {'message': {'$not': re.compile(r'^('+self.nickname+' —— )?('+nick+': \D|[^\s:]+: ('+config.COMMAND_CHARACTER+'|\[\d))')}}]}
        st = 0
        current = ""
        clean_my_nick = False
        news = False
        rest = cleanblanks(handle_quotes(rest))
        for arg in rest.split(' '):
            if current == "f":
                query['user'] = arg.lower()
                current = ""
            elif current == "w":
                if arg == self.str_re_tweets or arg == self.str_re_news:
                    clean_my_nick = True
                arg = clean_regexp(arg)
                re_arg = re.compile("%s" % arg, re.I)
                query['$and'].append({'message': re_arg})
                current = ""
            elif current == "s":
                st = max(st, safeint(arg))
                current = ""
            elif current == "c":
                chan = '#'+arg.lower().lstrip('#')
                if chan.lower() in self.factory.channels:
                    query['channel'] = re.compile(r'^%s$' % chan, re.I)
                else:
                    return "I do not follow this channel."
                current = ""
            elif arg.isdigit():
                maxnb = 5 if def_nb == 1 else def_nb
                nb = max(nb, min(safeint(arg), maxnb))
            elif arg == "--nofilter" or arg == "--filtered":
                query['$and'].remove({'filtered': {'$ne': True}})
                if arg == "--filtered":
                    query['$and'].append({'filtered': True})
            elif self.re_matchcommands.match(arg):
                current = arg.lstrip('-')[0]
        if not nb:
            nb = def_nb
        self.lastqueries[channel] = {'n': nb, 'skip': st+nb}
        if config.DEBUG:
            loggvar("Requesting last %s %s" % (rest, query), channel, "!last")
        matches = list(self.db['logs'].find(query, sort=[('timestamp', pymongo.DESCENDING)], fields=['timestamp', 'screenname', 'message'], limit=nb, skip=st))
        if len(matches) == 0:
            more = " more" if st > 1 else ""
            return "No"+more+" match found in my history log."
        if reverse:
            matches.reverse()
        if clean_my_nick:
            for i, m in enumerate(matches):
                matches[i] = m.replace("%s — " % self.nickname, '')
        return "\n".join(['[%s] %s — %s' % (shortdate(l['timestamp']), l['screenname'].encode('utf-8'), l['message'].encode('utf-8')) for l in matches])

    def command_lastseen(self, rest, channel=None, nick=None):
        """lastseen <nickname> : Prints the last time <nickname> was seen logging in and out."""
        user, _, msg = rest.partition(' ')
        if user == '':
            return "Please ask for a specific nickname."
        re_user = re.compile(r'^\[[^\[]*'+user, re.I)
        query = {'user': user.lower(), 'message': re_user}
        if channel != self.nickname:
            query['channel'] = channel
        res = list(self.db['logs'].find(query, fields=['timestamp', 'message'], sort=[('timestamp', pymongo.DESCENDING)], limit=2))
        if res:
            res.reverse()
            return " —— ".join(["%s %s" % (shortdate(m['timestamp']), m['message'].encode('utf-8')[1:-1]) for m in res])
        return self.command_lastfrom(user, channel, nick)

  # ---------------
  # Count commands

    def command_count(self, rest, *args):
        """count <text> : Prints the character length of <text> (spaces will be trimmed, urls will be shortened to 20 chars)."""
        return threads.deferToThread(lambda x: str(countchars(x))+" characters (max 140)", rest)

    def command_lastcount(self, rest, channel=None, nick=None):
        """lastcount : Prints the latest "count" command and its result (options from "last" except <N> can apply)."""
        res = self.re_optionskip.search(rest)
        if res:
            st = safeint(res.group(1)) * 2
            rest = self.re_optionskip.sub(' --skip %s ' % st, rest)
        return self.command_last("2 --with ^"+config.COMMAND_CHARACTER+"count|\S+:\s\d+\scharacters %s" % rest, channel, nick, True)

  # -------------------------------------
  # Twitter / Identi.ca sending commands

    re_force = re.compile(r'\s*--force\s*')
    re_nolimit = re.compile(r'\s*--nolimit\s*')
    def _match_reg(self, text, regexp):
        if regexp.search(text):
            return regexp.sub(' ', text).strip(), True
        return text, False

    def _send_via_protocol(self, siteprotocol, command, channel, nick, **kwargs):
        conf = chanconf(channel)
        if not chan_has_protocol(channel, siteprotocol, conf):
            return "No %s account is set for this channel." % siteprotocol
        if 'text' in kwargs:
            kwargs['text'], nolimit = self._match_reg(kwargs['text'], self.re_nolimit)
            kwargs['text'], force = self._match_reg(kwargs['text'], self.re_force)
            try:
                ct = countchars(kwargs['text'])
            except:
                ct = 100
            if ct < 30 and not nolimit:
                return "Do you really want to send such a short message? (%s chars) add --nolimit to override" % ct
            elif ct > 140 and siteprotocol == "twitter" and not nolimit:
                return "[%s] Sorry, but that's too long (%s characters) add --nolimit to override" % (siteprotocol, ct)
        if command in ['microblog', 'retweet']:
            kwargs['channel'] = channel
        if "TWITTER" in conf:
            conn = Microblog("twitter", conf)
            if 'text' in kwargs and not force and command != "directmsg":
                bl, self.twitter_users, msg = conn.test_microblog_users(kwargs['text'], self.twitter_users)
                if not bl:
                    return "[%s] %s" % (siteprotocol, msg)
        if siteprotocol == "identica":
            conn = Microblog(siteprotocol, conf)
        command = getattr(conn, command, None)
        return command(**kwargs)

    def command_identica(self, text, channel=None, nick=None):
        """identica <text> [--nolimit] : Posts <text> as a status on Identi.ca (--nolimit overrides the minimum 30 characters rule)./IDENTICA"""
        channel = self.getMasterChan(channel)
        return threads.deferToThread(self._send_via_protocol, 'identica', 'microblog', channel, nick, text=text)

    def command_twitteronly(self, text, channel=None, nick=None):
        """twitteronly <text> [--nolimit] [--force] : Posts <text> as a status on Twitter (--nolimit overrides the minimum 30 characters rule / --force overrides the restriction to mentions users I couldn't find on Twitter)./TWITTER/IDENTICA"""
        channel = self.getMasterChan(channel)
        return threads.deferToThread(self._send_via_protocol, 'twitter', 'microblog', channel, nick, text=text)

    re_answer = re.compile('^\d{14}')
    def command_twitter(self, text, channel=None, nick=None):
        """twitter <text> [--nolimit] [--force] : Posts <text> as a status on Identi.ca and on Twitter (--nolimit overrides the minimum 30 characters rule / --force overrides the restriction to mentions users I couldn't find on Twitter)./TWITTER"""
        if self.re_answer.match(text.strip()):
            return("Mmmm... Didn't you mean !%s instead?" % ("answer" if len(text) > 30 else "rt"))
        channel = self.getMasterChan(channel)
        dl = []
        dl.append(defer.maybeDeferred(self._send_via_protocol, 'twitter', 'microblog', channel, nick, text=text))
        if chan_has_identica(channel):
            dl.append(defer.maybeDeferred(self._send_via_protocol, 'identica', 'microblog', channel, nick, text=text))
        return defer.DeferredList(dl, consumeErrors=True)

    def command_answer(self, rest, channel=None, nick=None, check=True):
        """answer <tweet_id> <@author text> [--nolimit] [--force] : Posts <text> as a status on Identi.ca and as a response to <tweet_id> on Twitter. <text> must include the @author of the tweet answered to except when answering myself. (--nolimit overrides the minimum 30 characters rule / --force overrides the restriction to mentions users I couldn't find on Twitter)./TWITTER"""
        channel = self.getMasterChan(channel)
        tweet_id, text = self._extract_digit(rest)
        if tweet_id < 2 or text == "":
            return "Please input a correct tweet_id and message."
        if check:
            conf = chanconf(channel)
            conn = Microblog('twitter', conf)
            tweet = conn.show_status(tweet_id)
            if tweet and 'user' in tweet and 'screen_name' in tweet['user'] and 'text' in tweet:
                author = tweet['user']['screen_name'].lower()
                if author != conf['TWITTER']['USER'].lower() and "@%s" % author not in text.decode('utf-8').lower():
                    return "Don't forget to quote @%s when answering his tweets ;)" % tweet['user']['screen_name']
            else:
                return "[twitter] Cannot find tweet %s on Twitter." % tweet_id
        dl = []
        dl.append(defer.maybeDeferred(self._send_via_protocol, 'twitter', 'microblog', channel, nick, text=text, tweet_id=tweet_id))
        if chan_has_identica(channel):
            dl.append(defer.maybeDeferred(self._send_via_protocol, 'identica', 'microblog', channel, nick, text=text))
        return defer.DeferredList(dl, consumeErrors=True)

    def command_answerlast(self, rest, channel=None, nick=None):
        """answerlast <text> [--nolimit] [--force] : Send <text> as a tweet in answer to the last tweet sent to Twitter from the channel./TWITTER"""
        lasttweetid = self.db['lasttweets'].find_one({'channel': channel})
        if not lasttweetid:
            return "Sorry, no last tweet id found for this chan."
        return self.command_answer("%s %s" % (str(lasttweetid["tweet_id"]), rest), channel, nick, check=False)

    def command_dm(self, rest, channel=None, nick=None):
        """dm <user> <text> [--nolimit] : Posts <text> as a direct message to <user> on Twitter (--nolimit overrides the minimum 30 characters rule)./TWITTER"""
        channel = self.getMasterChan(channel)
        user, _, text = rest.partition(' ')
        user = user.lstrip('@').lower()
        if user == "" or text == "":
            return "Please input a user name and a message."
        return threads.deferToThread(self._send_via_protocol, 'twitter', 'directmsg', channel, nick, user=user, text=text)

    def command_rmtweet(self, tweet_id, channel=None, nick=None):
        """rmtweet <tweet_id> : Deletes <tweet_id> from Twitter./TWITTER"""
        channel = self.getMasterChan(channel)
        tweet_id = safeint(tweet_id)
        if not tweet_id:
            return "Please input a correct tweet_id."
        return threads.deferToThread(self._send_via_protocol, 'twitter', 'delete', channel, nick, tweet_id=tweet_id)

    def command_rmlasttweet(self, tweet_id, channel=None, nick=None):
        """rmlasttweet : Deletes last tweet sent to Twitter from the channel./TWITTER"""
        lasttweetid = self.db['lasttweets'].find_one({'channel': channel})
        if not lasttweetid:
            return "Sorry, no last tweet id found for this chan."
        return self.command_rmtweet(str(lasttweetid['tweet_id']), channel, nick)

    def _rt_on_identica(self, tweet_id, conf, channel, nick):
        conn = Microblog('twitter', conf)
        res = conn.show_status(tweet_id)
        if res and 'user' in res and 'screen_name' in res['user'] and 'text' in res:
            tweet = "♻ @%s: %s" % (res['user']['screen_name'].encode('utf-8'), res['text'].encode('utf-8'))
            if countchars(tweet) > 140:
                tweet = "%s…" % tweet[:139]
            return self._send_via_protocol('identica', 'microblog', channel, nick, text=tweet)
        return "[identica] Cannot find tweet %s on Twitter." % tweet_id

    def command_rt(self, tweet_id, channel=None, nick=None):
        """rt <tweet_id> : Retweets <tweet_id> on Twitter and posts a ♻ status on Identi.ca./TWITTER"""
        channel = self.getMasterChan(channel)
        tweet_id = safeint(tweet_id)
        if not tweet_id:
            return "Please input a correct tweet_id."
        dl = []
        dl.append(defer.maybeDeferred(self._send_via_protocol, 'twitter', 'retweet', channel, nick, tweet_id=tweet_id))
        conf = chanconf(channel)
        if chan_has_identica(channel, conf):
            dl.append(defer.maybeDeferred(self._rt_on_identica, tweet_id, conf, channel, nick))
        return defer.DeferredList(dl, consumeErrors=True)

    def command_stats(self, rest, channel=None, nick=None):
        """stats : Prints stats on the Twitter account set for the channel./TWITTER"""
        channel = self.getMasterChan(channel)
        conf = chanconf(channel)
        if conf and "TWITTER" in conf and "USER" in conf["TWITTER"]:
            stats = Stats(self.db, conf["TWITTER"]["USER"].lower())
            return stats.print_last()
        return "No Twitter account set for this channel."

  # ----------------------------
  # Twitter monitoring commands
    def _restart_stream(self, channel):
        if "stream" in self.feeders[channel] and self.feeders[channel]["stream"].status == "running":
            oauth2_token = self.feeders[channel]["stream"].twitter_token or None
            self.feeders[channel]["stream"].end()
            self.feeders[channel]['stream'] = FeederFactory(self, channel, 'stream', 20, twitter_token=oauth2_token)
            self.feeders[channel]["stream"].start()

    re_url = re.compile(r'\s*(https?://\S+)\s*', re.I)
    def _parse_follow_command(self, query):
        if not self.re_url.search(query):
            database = 'tweets'
            url = query
            name = 'TWEETS: %s' % query
        else:
            query = remove_ext_quotes(query)
            database = 'news'
            url = self.re_url.search(query).group(1)
            name = self.re_url.sub('', query).strip().lower()
        return database, url, name

    def command_follow(self, query, channel=None, nick=None):
        """follow <name url|text|@user> : Asks me to follow and display elements from a RSS named <name> at <url>, or tweets matching <text> or from <@user>./AUTH"""
        channel = self.getMasterChan(channel)
        database, query, name = self._parse_follow_command(query)
        if query == "":
            return "Please specify what you want to follow (%shelp follow for more info)." % config.COMMAND_CHARACTER
        if len(query) > 300:
            return "Please limit your follow queries to a maximum of 300 characters"
        if database == "news" and name == "":
            return "Please provide a name for this url feed."
        self.db['feeds'].update({'database': database, 'channel': channel, 'name': name}, {'database': database, 'channel': channel, 'name': name, 'query': query, 'user': nick, 'timestamp': datetime.today()}, upsert=True)
        if database == "news":
            query = "%s <%s>" % (name, query)
        if database == "tweets":
            self._restart_stream(channel)
        return '"%s" query added to %s database for %s' % (query, database, channel)

    re_clean_query = re.compile(r'([()+|])')
    def command_unfollow(self, query, channel=None, *args):
        """unfollow <name|text|@user> : Asks me to stop following and displaying elements from a RSS named <name>, or tweets matching <text> or from <@user>./AUTH"""
        channel = self.getMasterChan(channel)
        query = query.lstrip('«').rstrip('»')
        database, query, name = self._parse_follow_command(query)
        re_query = re.compile(r'^%s$' % self.re_clean_query.sub(r'\\\1', query), re.I)
        res = self.db['feeds'].remove({'channel': channel, '$or': [{'name': re_query}, {'query': re_query}]}, safe=True)
        if not res or not res['n']:
            return "I could not find such query in my database"
        if database == "tweets":
            self._restart_stream(channel)
        return '"%s" query removed from feeds database for %s'  % (query, channel)

    def command_list(self, database, channel=None, *args):
        """list [tweets|news|filters] : Displays the list of filters or news or tweets queries followed for current channel."""
        channel = self.getMasterChan(channel)
        database = database.strip()
        if database != "tweets" and database != "news" and database != "filters":
            return 'Please enter either "%slist tweets", "%slist news" or "%slist filters".' % (config.COMMAND_CHARACTER, config.COMMAND_CHARACTER, config.COMMAND_CHARACTER)
        if database == "filters":
            feeds = assembleResults(self.filters[channel])
        else:
            feeds = getFeeds(channel, database, self.db, url_format=False)
        if database == 'tweets':
            res = "\n".join([f.replace(')OR(', '').replace(r')$', '').replace('^(', '').replace('from:', '@') for f in feeds])
        else:
            res = "\n".join(feeds)
        if res:
            return res
        return "No query set for %s." % database

    def command_newsurl(self, name, channel=None, *args):
       """newsurl <name> : Displays the url of a RSS feed saved as <name> for current channel."""
       channel = self.getMasterChan(channel)
       res = self.db['feeds'].find_one({'database': 'news', 'channel': channel, 'name': name.lower().strip()}, fields=['query', 'name'])
       if res:
            return "«%s» : %s" % (res['name'].encode('utf-8'), res['query'].encode('utf-8'))
       return "No news feed named « %s » for this channel" % name

    str_re_tweets = ' — http://twitter\.com/'
    def command_lasttweets(self, tweet, channel=None, nick=None):
        """lasttweets <word> [<N>] : Prints the last or <N> last tweets matching <word> (options from "last" can apply)."""
        return self.command_lastwith("'%s' %s" % (self.str_re_tweets, tweet), channel, nick)

    str_re_news = '^\[News — '
    def command_lastnews(self, tweet, channel=None, nick=None):
        """lastnews <word> [<N>] : Prints the last or <N> last news matching <word> (options from "last" can apply)."""
        return self.command_lastwith("'%s' %s" % (self.str_re_news, tweet), channel, nick)

    def command_filter(self, keyword, channel=None, nick=None):
        """filter <word> : Filters the display of tweets or news containing <word>./AUTH"""
        channel = self.getMasterChan(channel)
        keyword = keyword.lower().strip()
        if keyword == "":
            return "Please specify what you want to follow (%shelp follow for more info)." % config.COMMAND_CHARACTER
        self.db['filters'].update({'channel': channel, 'keyword': keyword}, {'channel': channel, 'keyword': keyword, 'user': nick, 'timestamp': datetime.today()}, upsert=True)
        self.filters[channel].append(keyword)
        return '"%s" filter added for tweets displays on %s' % (keyword, channel)

    def command_unfilter(self, keyword, channel=None, nick=None):
        """unfilter <word> : Removes a tweets display filter for <word>./AUTH"""
        channel = self.getMasterChan(channel)
        keyword = keyword.lower().strip()
        res = self.db['filters'].remove({'channel': channel, 'keyword': keyword}, safe=True)
        if not res or not res['n']:
            return "I could not find such filter in my database"
        self.filters[channel].remove(keyword)
        return '"%s" filter removed for tweets display on %s'  % (keyword, channel)


  # ------------------
  # Other commands...

    @defer.inlineCallbacks
    def command_ping(self, rest, channel=None, nick=None):
        """ping [<text>] : Pings all ops and at most 50 more users on the chan saying <text> except for users set with noping./AUTH"""
        names = yield self._names(channel)
        ops = [name.strip('@') for name in names if name.startswith('@')]
        names = [name for name in names if not name.startswith('@')]
        skip = [user['lower'].encode('utf-8') for user in self.db['noping_users'].find({'channel': channel}, fields=['lower'])]
        skip.append(nick.lower())
        skip.append(self.nickname.lower())
        left = [name for name in names if name.lower() not in skip]
        ops = [name for name in ops if name.lower() not in skip]
        if not len(left + ops):
            defer.returnValue("There's no one to ping here :(")
        random.shuffle(left)
        if len(left) > 50:
            left = left[:49]
        if rest.strip() == "":
            rest = "Ping!"
        defer.returnValue("%s %s" % (" ".join(ops + left), rest))

    re_stop = re.compile(r'\s*--stop\s*', re.I)
    re_list = re.compile(r'\s*--list\s*', re.I)
    split_list_users = lambda _, l: [x.lower() for x in l.split(" ")]
    def command_noping(self, rest, channel=None, nick=None):
        """noping <user1> [<user2> [<userN>...]] [--stop] [--list] : Deactivates pings from ping command for <users 1 to N> listed. With --stop, reactivates pings for those users. With --list just gives the list of deactivated users."""
        if self.re_list.search(rest):
            skip = [user['user'].encode('utf-8') for user in self.db['noping_users'].find({'channel': channel}, fields=['user'])]
            text = "are"
            if len(skip) < 2:
                text = "is"
            return "%s %s actually registered for noping." % (" ".join(skip), text)
        if self.re_stop.search(rest):
            no = ""
            again = "again"
            rest = self.re_stop.sub(' ', rest).replace('  ', ' ')
            users = rest.split(" ")
            self.db['noping_users'].remove({'channel': channel, 'lower': {'$in': [x.lower() for x in users]}})
        else:
            no = "not "
            again = "anymore"
            users = rest.split(" ")
            for user in users:
                self.db['noping_users'].update({'channel': channel, 'lower': user.lower()}, {'channel': channel, 'user': user, 'lower': user.lower(), 'timestamp': datetime.today()}, upsert=True)
        return "All right, %s will %sbe pinged %s." % (" ".join(users).strip(), no, again)

    def _set_silence(self, channel, minutes):
        self.silent[channel] = datetime.today() + timedelta(minutes=minutes)

    def command_fuckoff(self, minutes, channel=None, nick=None):
        """fuckoff [<N>] : Tells me to shut up for the next <N> minutes (defaults to 5)./AUTH"""
        channel = self.getMasterChan(channel)
        if not minutes:
            minutes = 5
        else:
            when, _ = self._extract_digit(minutes)
            minutes = max(1, when)
        reactor.callFromThread(reactor.callLater, 1, self._set_silence, channel, minutes)
        return "All right, I'll be back in %s minutes or if you run %scomeback." % (minutes, config.COMMAND_CHARACTER)

    def command_comeback(self, rest, channel=None, nick=None):
        """comeback : Tells me to start talking again after use of "fuckoff"./AUTH"""
        channel = self.getMasterChan(channel)
        if self.silent[channel] < datetime.today():
            return "I wasn't away but OK :)"
        self.silent[channel] = datetime.today()
        return "It's good to be back!"

    re_url_pad = re.compile(r'https?://.*pad', re.I)
    def command_setpad(self, rest, channel=None, nick=None):
        """setpad <url> : Defines <url> of the current etherpad./AUTH"""
        channel = self.getMasterChan(channel)
        url = rest.strip()
        if self.re_url_pad.match(url):
            self.db['feeds'].update({'database': 'pad', 'channel': channel}, {'database': 'pad', 'channel': channel, 'query': url, 'user': nick, 'timestamp': datetime.today()}, upsert=True)
            return "Current pad is now set to %s" % rest
        return "This is not a valid pad url."

    def command_pad(self, rest, channel=None, *args):
        """pad : Prints the url of the current etherpad."""
        channel = self.getMasterChan(channel)
        res = self.db['feeds'].find_one({'database': 'pad', 'channel': channel}, fields=['query'])
        if res:
            return "Current pad is available at: %s" % res['query']
        return "No pad is currently set for this channel."

    re_clean_twitter_task = re.compile(r'^%s(identica|(twitt|answ)er(only)?)\s*(\d{14}\d*\s*)?' % config.COMMAND_CHARACTER, re.I)
    def command_runlater(self, rest, channel=None, nick=None):
        """saylater <minutes> [--chan <channel>] <command [arguments]> : Schedules <command> in <minutes> for current channel or optional <channel>."""
        now = time.time()
        when, task = self._extract_digit(rest)
        when = max(0, when) * 60
        then = shortdate(datetime.fromtimestamp(now + when))
        if task.startswith("--chan "):
            tmpchan = task[7:task.find(' ', 7)]
            tmpchan2 = '#'+tmpchan.lower().lstrip('#')
            if tmpchan2 in self.factory.channels:
                channel = tmpchan2
            else:
                return "I do not follow this channel."
            task = task.replace("--chan %s " % tmpchan, "")
        else:
            channel = self.getMasterChan(channel)
        target = nick if channel == self.nickname else channel
        rank = len(self.tasks)
        if task.startswith(config.COMMAND_CHARACTER):
            if self.re_clean_twitter_task.match(task):
                count = countchars(self.re_clean_twitter_task.sub('', task))
                if count > 140:
                    return("I can already tell you this won't work, it's too long (%s characters)" % count)
            taskid = reactor.callLater(when, self.privmsg, nick, channel, task, tasks=rank)
        else:
            taskid = reactor.callLater(when, self._send_message, task, target)
        loggvar("Task #%s planned at %s by %s: %s" % (rank, then, nick, task), channel, "tasks")
        self.tasks.append({'rank': rank, 'channel': channel, 'author': nick, 'command': task, 'created': shortdate(datetime.fromtimestamp(now)), 'scheduled': then, 'scheduled_ts': now + when, 'id': taskid})
        return "Task #%s scheduled at %s : %s" % (rank, then, task)

    def command_tasks(self, rest, channel=None, *args):
        """tasks : Prints the list of coming tasks scheduled./AUTH"""
        channel = self.getMasterChan(channel)
        now = time.time()
        res = "\n".join(["#%s [%s]: %s" % (task['rank'], task['scheduled'], task['command']) for task in self.tasks if task['channel'] == channel and task['scheduled_ts'] > now and 'canceled' not in task])
        if res == "":
            return "No task scheduled."
        return res

    def command_cancel(self, rest, channel=None, *args):
        """cancel <task_id> : Cancels the scheduled task <task_id>./AUTH"""
        channel = self.getMasterChan(channel)
        task_id = safeint(rest.lstrip('#'))
        try:
            task = self.tasks[task_id]
            if task['channel'] != channel:
                return "Task #%s is not scheduled for this channel." % task_id
            task['id'].cancel()
            self.tasks[task_id]['canceled'] = True
            return "#%s [%s] CANCELED: %s" % (task_id, task['scheduled'], task['command'])
        except:
            return "The task #%s does not exist yet or is already canceled." % task_id

    def command_title(self, url, *args):
        """title <url> : Prints the title of the webpage at <url>."""
        d = getPage(url)
        d.addCallback(self._parse_pagetitle, url)
        d.addErrback(lambda _: "I cannot access the webpage at %s" % url)
        return d

    def _parse_pagetitle(self, page_contents, url):
        pagetree = lxml.html.fromstring(page_contents)
        title = u' '.join(pagetree.xpath('//title/text()')).strip()
        title = title.encode('utf-8')
        return '%s -- "%s"' % (url, title)

    def command_chans(self, rest, channel=None, *args):
        """chans : Prints the list of all the channels I'm in."""
        chans = [chan for chan in self.factory.channels if chan.lower() != channel.lower()]
        if not len(chans):
            return "I'm only hanging out here."
        return "I'm currently hanging out in %s. Come visit!" % " ; ".join(chans)

# Auto-reconnecting Factory
class IRCBotFactory(protocol.ReconnectingClientFactory):
    protocol = IRCBot
    channels = ["#" + c.lower() for c in config.CHANNELS.keys()]
    if not hasattr(config, "SOLITARY") or str(config.SOLITARY).lower() == "false":
        channels.append("#gazouilleur")


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

