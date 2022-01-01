#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gazouilleur.lib.tests
from gazouilleur import config

import sys, os.path, types, re, exceptions
import random, time, imghdr
from datetime import datetime
import lxml.html
from OpenSSL import SSL
from twisted.internet import reactor, protocol, threads, ssl, error as twerror
from twisted.internet.defer import maybeDeferred, DeferredList, inlineCallbacks, returnValue as returnD
from twisted.web import client
from twisted.application import internet, service
from twisted.python import log
from gazouilleur.lib.ircclient_with_names import NamesIRCClient
from gazouilleur.lib.log import *
from txmongo import MongoConnection
from gazouilleur.lib.mongo import sortasc, sortdesc, ensure_indexes
from gazouilleur.lib.utils import *
from gazouilleur.lib.filelogger import FileLogger
from gazouilleur.lib.microblog import Microblog, clean_oauth_error, format_tweet
from gazouilleur.lib.feeds import FeederFactory
from gazouilleur.lib.stats import Stats
client.HTTPClientFactory.noisy = False
import urllib3
urllib3.disable_warnings()

THREADS = 15*len(config.CHANNELS)
reactor.suggestThreadPoolSize(THREADS)

class IRCBot(NamesIRCClient):

    sourceURL = 'https://github.com/RouxRC/gazouilleur'
    lineRate = 0.75
    saving_task = False
    saved_tasks = 0
    saving_tasks = 0
    tasks = []
    nicks = {}
    silent = {}
    filters = {}
    cache_urls = {}
    lastqueries = {}
    twitter = {"users": {}}

    def __init__(self):
        #NickServ identification handled automatically by twisted
        NamesIRCClient.__init__(self)
        self.nickname = config.BOTNAME
        self.username = config.BOTNAME
        self.password = config.BOTPASS
        try:
            self.sasl = config.SASL
        except AttributeError:
            self.sasl = False
        self.db = MongoConnection(config.MONGODB['HOST'], config.MONGODB['PORT'], pool_size=int(THREADS/3))[config.MONGODB['DATABASE']]
        self.breathe = datetime.today()
        self.get_twitter_conf()
        self.logger =  {}
        self.feeders = {}
        self.colorizer = {"private": chan_color_conf()}
        self.users = {}
        for extra in config.EXTRA_COMMANDS:
            setattr(self, "command_%s" % extra['command'], self.__command_get(extra))
            setattr(self, 'command_set%s' % extra['command'], self.__command_set(extra))

    def get_twitter_conf(self):
        for c in filter(lambda x: "TWITTER" in config.CHANNELS[x], config.CHANNELS):
            try:
                self.twitter["url_length"], self.twitter['max_img_size'] = Microblog("twitter", config.CHANNELS[c]).get_twitter_conf()
                break
            except:
                pass
        if "url_length" not in self.twitter:
            loggerr("Could not get Twitter's configuration, setting shortened urls length to default value.", action="twitter")
            self.twitter["url_length"] = 23
        loggvar("Set Twitter shortened urls length for %scount to %s characters." % (COMMAND_CHAR_DEF, self.twitter["url_length"]), action="twitter")


    # Double logger (mongo / files)
    @inlineCallbacks
    def log(self, message, user=None, channel=config.BOTNAME, filtered=False):
        if channel == "*" or channel == self.nickname or channel.lower() not in self.logger:
            channel = config.BOTNAME
        lowchan = channel.lower()
        if user:
            nick, _, host = user.partition('!')
            if channel not in self.nicks:
                self.nicks[lowchan] = {}
            if nick not in self.nicks[lowchan] or self.nicks[lowchan][nick] != host:
                self.nicks[lowchan][nick] = host
            else:
                user = nick
            host = self.nicks[lowchan][nick]
            yield self.db['logs'].insert({'timestamp': datetime.today(), 'channel': lowchan, 'user': nick.lower(), 'screenname': nick, 'host': host, 'message': message, 'filtered': filtered})
            if nick+" changed nickname to " in message:
                oldnick = message[1:-1].replace(nick+" changed nickname to ", '')
                yield self.db['logs'].insert({'timestamp': datetime.today(), 'channel': lowchan, 'user': oldnick.lower(), 'screenname': oldnick, 'host': host, 'message': message})
            message = "%s: %s" % (user, message)
        if not (message.startswith('%s: PING ' % self.nickname) and lowchan == self.nickname.lower()) and lowchan in self.logger:
            self.logger[lowchan].log(message, filtered)
        if user:
            returnD((nick, user))

  # -------------------
  # Connexion loggers

    @inlineCallbacks
    def connectionMade(self):
        yield self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        loggirc('Connection made')
        yield ensure_indexes(self.db)
        lowname = config.BOTNAME.lower()
        self.logger[lowname] = FileLogger()
        yield self.log("[connected at %s]" % time.asctime(time.localtime(time.time())))
        NamesIRCClient.connectionMade(self)

    @inlineCallbacks
    def connectionLost(self, reason):
        yield self.log("[disconnected at %s]" % time.asctime(time.localtime(time.time())))
        [task['id'].cancel() for task in self.tasks if task['id'].active()]
        for channel in self.factory.channels:
            self.left(channel)
        lowname = config.BOTNAME.lower()
        loggirc2('Connection lost because: %s.' % reason)
        if lowname in self.logger:
            self.logger[lowname].close()
        NamesIRCClient.connectionLost(self, reason)

    @inlineCallbacks
    def signedOn(self):
        loggirc("Signed on as %s." % self.nickname)
        for channel in self.factory.channels:
            self.colorizer[channel] = chan_color_conf(channel)
            conf = chanconf(channel)
            self.join(channel, conf["PASSWORD"] if conf and "PASSWORD" in conf else None)
        yield self._refresh_tasks_from_db()

    @inlineCallbacks
    def _get_chan_known_users(self, channel):
        re_joined = re.compile(r'^\[.* joined\]$')
        past_users = yield self.db['logs'].aggregate([{'$match': {'channel': channel.lower(), 'message': re_joined}}, {'$group': {'_id': '$user'}}])
        cur_users = yield self._names(channel)
        returnD(set([u['_id'].lower() for u in past_users] + [u.lower().lstrip('@') for u in cur_users]))

    @inlineCallbacks
    def joined(self, channel):
        NamesIRCClient.joined(self, channel)
        conf = chanconf(channel)
        if conf:
            conf["oauth2"] = None
        lowchan = channel.lower()
        self.logger[lowchan] = FileLogger(lowchan)
        loggirc("Joined.", channel)
        yield self.log("[joined at %s]" % time.asctime(time.localtime(time.time())), None, channel)
        if lowchan == "#gazouilleur":
            returnD(None)
        self.lastqueries[lowchan] = {'n': 1, 'skip': 0}
        filters = yield self.db['filters'].find({'channel': lowchan}, fields=['keyword'])
        self.filters[lowchan] = [keyword['keyword'].encode('utf-8') for keyword in filters]
        self.silent[lowchan] = datetime.today()
        self.feeders[lowchan] = {}
        # Get list of known users on the chan if welcome message activated
        self.users[lowchan] = set()
        if "WELCOME" in conf and conf["WELCOME"]:
            self.users[lowchan] = yield self._get_chan_known_users(channel)
        # Follow RSS Feeds matching url queries set for this channel with !follow
        if display_feed(conf, 'news'):
            self.feeders[lowchan]['news'] = FeederFactory(self, channel, 'news', 299, pagetimeout=35)
        # Monitor webpages set for this channel with !monitor
        if display_feed(conf, 'pages'):
            self.feeders[lowchan]['pages'] = FeederFactory(self, channel, 'pages', 301, timeout=900, pagetimeout=95)
        twuser = get_chan_twitter_user(channel, conf)
        if twuser:
        # Get OAuth2 tokens for twitter search extra limitrate
            try:
                conf["oauth2"] = Microblog("twitter", conf, get_token=True).get_oauth2_token()
                loggvar("Got OAuth2 token for %s on Twitter." % twuser, channel, "twitter")
            except Exception as e:
                err = clean_oauth_error(e)
                loggerr("Could not get an OAuth2 token from Twitter for user @%s: %s" % (twuser, err), channel, "twitter")
        # Follow Searched Tweets matching queries set for this channel with !follow
            if display_feed(conf, 'twitter_search'):
                self.feeders[lowchan]['twitter_search'] = FeederFactory(self, channel, 'search', 90 if conf["oauth2"] else 180, timeout=600, twitter_token=conf["oauth2"])
        # Follow Searched Tweets matching queries set for this channel with !follow via Twitter's streaming API
            if display_feed(conf, 'stream'):
                self.feeders[lowchan]['stream'] = FeederFactory(self, channel, 'stream', 5, timeout=90, twitter_token=conf["oauth2"])
        # Follow Stats for Twitter USER
            if chan_has_twitter(channel, conf):
                if display_feed(conf, 'stats'):
                    self.feeders[lowchan]['stats'] = FeederFactory(self, channel, 'stats', 600)
        # Follow Tweets sent by Twitter USER
                if display_feed(conf, 'mytweets_T'):
                    self.feeders[lowchan]['mytweets_T'] = FeederFactory(self, channel, 'mytweets', 20 if conf["oauth2"] else 30, twitter_token=conf["oauth2"])
            # Deprecated
            # Follow Tweets sent by and mentionning Twitter USER via IceRocket.com
            #   self.feeders[lowchan]['mytweets'] = FeederFactory(self, channel, 'tweets', 289, pagetimeout=20, feeds=[getIcerocketFeedUrl('%s+OR+@%s' % (twuser, twuser))], tweets_search_page='icerocket')
            # ... or via IceRocket.com old RSS feeds
            #   self.feeders[lowchan]['mytweets'] = FeederFactory(self, channel, 'tweets', 89, pagetimeout=20, feeds=[getIcerocketFeedUrl('%s+OR+@%s' % (twuser, twuser), rss=True)])
            # ... or via Topsy.com
            #   self.feeders[lowchan]['mytweets'] = FeederFactory(self, channel, 'tweets', 289, pagetimeout=20, feeds=[getTopsyFeedUrl('%s+OR+@%s' % (twuser, twuser))], tweets_search_page='topsy')
            # Follow DMs sent to Twitter USER
                if display_feed(conf, 'dms'):
                    self.feeders[lowchan]['dms'] = FeederFactory(self, channel, 'dms', 90)
        # Follow ReTweets of tweets sent by Twitter USER
                if display_feed(conf, 'retweets'):
                    self.feeders[lowchan]['retweets'] = FeederFactory(self, channel, 'retweets', 360)
        # Follow Mentions of Twitter USER in tweets
            if display_feed(conf, 'mentions'):
                self.feeders[lowchan]['mentions'] = FeederFactory(self, channel, 'mentions', 90)
        else:
        # Follow Searched Tweets matching queries set for this channel with !follow via IceRocket.com since no Twitter account is set
            if display_feed(conf, 'tweets'):
                self.feeders[lowchan]['tweets'] = FeederFactory(self, channel, 'tweets', 277, pagetimeout=30, tweets_search_page='icerocket')
        # ... or via Topsy.com
        #   self.feeders[lowchan]['tweets'] = FeederFactory(self, channel, 'tweets', 277, pagetimeout=25, tweets_search_page='icerocket')
        n = self.factory.channels.index(lowchan) + 1
        for i, f in enumerate(self.feeders[lowchan].keys()):
            threads.deferToThread(reactor.callLater, 3*(i+1)*n, self.feeders[lowchan][f].start)
        returnD(True)

    @inlineCallbacks
    def left(self, channel, silent=False):
        if not silent:
            yield self.log("[left at %s]" % time.asctime(time.localtime(time.time())), None, channel)
        lowchan = channel.lower()
        if lowchan in self.feeders:
            for f in self.feeders[lowchan].keys():
                self.feeders[lowchan][f].end()
        if lowchan in self.logger:
            self.logger[lowchan].close()
        if not silent:
            loggirc2("Left.", channel)

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

    @inlineCallbacks
    def noticed(self, user, channel, message):
        loggirc("SERVER NOTICE [%s]: %s" % (user, message), channel)
        if 'is not a registered nickname' in message and 'NickServ' in user:
            self._reclaimNick()
        elif 'has been regained' in message and 'NickServ' in user:
            for chan in self.factory.channels:
                yield self.left(chan, silent=True)
                yield self.joined(chan)


  # ------------------------
  # Users connexions logger

    @inlineCallbacks
    def userJoined(self, user, channel):
        lowchan = channel.lower()
        lowuser = user.lower()
        lowuser1 = lowuser.rstrip('_')
        conf = chanconf(lowchan)
        if conf and "WELCOME" in conf and conf["WELCOME"] and self.users[lowchan] and lowuser not in self.users[lowchan] and lowuser1 not in self.users[lowchan]:
            self.users[lowchan].add(lowuser)
            msgs = conf["WELCOME"].split("\n")
            self._send_message(msgs.pop(0), channel, user)
            for m in msgs:
                self._send_message(m, channel)
        yield self.log("[%s joined]" % user, user, channel)

    @inlineCallbacks
    def userLeft(self, user, channel, reason=None):
        msg = "[%s left" % user
        if reason:
            msg += " (%s)" % reason
        msg += "]"
        yield self.log(msg, user, channel)

    @inlineCallbacks
    def _get_user_channels(self, nick):
        res = []
        for c in self.factory.channels:
            last_log = yield self.db['logs'].find({'channel': c, 'user': nick.lower(), 'message': re.compile(r'^\[[^\[]*'+nick+'[\s\]]', re.I)}, fields=['message'], limit=1, filter=sortdesc('timestamp'))
            if last_log and not last_log[0]['message'].encode('utf-8').endswith(' left]'):
                res.append(c)
        returnD(res)

    @inlineCallbacks
    def userQuit(self, user, quitMessage):
        nick, _, _ = user.partition('!')
        chans = yield self._get_user_channels(nick)
        for c in chans:
            self.userLeft(nick, c, quitMessage)

    @inlineCallbacks
    def userRenamed(self, oldnick, newnick):
        chans = yield self._get_user_channels(oldnick)
        for c in chans:
            if c != "#gazouilleur":
                self.users[c.lower()].add(newnick.lower())
                yield self.log("[%s changed nickname to %s]" % (oldnick, newnick), oldnick, c)

    def getMasterChan(self, channel):
        if channel == self.nickname:
            channel = get_master_chan()
        return channel.lower()

  # -------------------
  # Command controller

    # Identify function corresponding to a parsed command
    def _find_command_function(self, command):
        return getattr(self, 'command_' + command.lower(), None)

    def _get_command_name(self, command):
        if not callable(command):
            return command
        return command.__name__.replace('command_', '')

    def _get_command_doc(self, command):
        if not callable(command):
            command = self._find_command_function(command)
        return command.__doc__

    def _can_user_do(self, nick, channel, command, conf=None):
        return has_user_rights_in_doc(nick, channel, self._get_command_name(command), self._get_command_doc(command))

    def _get_target(self, channel, nick):
        return nick if channel == self.nickname else channel

    re_catch_command = re.compile(r'^\s*%s[:,\s]*%s' % (config.BOTNAME, COMMAND_CHAR_REG), re.I)
    @inlineCallbacks
    def privmsg(self, user, channel, message, tasks=None):
        try:
            message = message.decode('utf-8')
        except UnicodeDecodeError:
            try:
                message = message.decode('iso-8859-1')
            except UnicodeDecodeError:
                message = message.decode('cp1252')
        message = cleanblanks(message)
        message = self.re_catch_command.sub(COMMAND_CHAR_DEF, message)
        nick, user = yield self.log(message, user, channel)
        d = None
        if channel == "#gazouilleur" and not message.startswith("%schans" % COMMAND_CHAR_DEF):
            returnD(None)
        if not startsWithCommandChar(message):
            if self.nickname.lower() in message.lower() and chan_is_verbose(channel):
                d = maybeDeferred(self.command_test)
            else:
                returnD(None)
        message = message.encode('utf-8')
        if config.DEBUG:
            loggvar("COMMAND: %s: %s" % (user, message), channel)
        command, _, rest = message.lstrip(COMMAND_CHAR_STR).partition(' ')
        if not command:
            returnD(None)
        func = self._find_command_function(command)
        if func is None and d is None:
            if chan_is_verbose(channel):
                d = maybeDeferred(self.command_help, command, channel, nick, discreet=True)
            else:
                returnD(None)
        target = self._get_target(channel, nick)
        if d is None:
            if self._can_user_do(nick, channel, func):
                d = maybeDeferred(func, rest, channel, nick)
            else:
                if chan_is_verbose(channel):
                    self._send_message("Sorry, you don't have the rights to use this command in this channel.", target, nick)
                returnD(None)
        d.addCallback(self._send_message, target, nick, tasks=tasks)
        d.addErrback(self._show_error, target, nick)
        returnD(None)

    # Hack the endpoint method sending messages to block messages as soon as possible when filter or fuckoff mode is on
    re_extract_chan = re.compile(r'PRIVMSG (#\S+) :')
    re_tweets = re.compile(r' — https?://twitter.com/[^/\s]*/statuse?s?/[0-9]*(/(photo|video)/1)?$', re.I)
    def _sendLine(self, chan="default"):
        if self._queue[chan]:
            line, original = self._queue[chan].pop(0)
            msg = line
            skip = False
            if self.re_extract_chan.match(line) != "default":
                msg = self.re_extract_chan.sub('', line)
                try:
                    msg_utf = msg.decode('utf-8')
                    orig_utf = original.decode('utf-8')
                except UnicodeDecodeError as e:
                    msg_utf = msg
                    orig_utf = original
                    loggerr("Encoding error on %s: %s" % (msg, e), chan)
                orig_low = orig_utf.lower()
                twuser = get_chan_twitter_user(chan).lower()
                if "[DM] " in orig_utf or (twuser and twuser in orig_low and not(chan in self.filters and "@%s" % twuser in self.filters[chan])):
                    pass
                elif chan in self.silent and self.silent[chan] > datetime.today() and self.re_tweets.search(original):
                    skip = True
                    reason = "fuckoff until %s" % self.silent[chan]
                elif chan in self.filters and self.re_tweets.search(original):
                    for keyword in self.filters[chan]:
                        k = keyword.decode('utf-8')
                        if (not k.startswith('@') and k in orig_low) or (k.startswith('@') and orig_low.startswith(k[1:]+': ')):
                            skip = True
                            reason = "filter on «%s»" % keyword
                            break
            else:
                msg_utf = line.decode('utf-8')
            if line.startswith('PRIVMSG '):
                self.log(msg_utf, self.nickname, chan, filtered=skip)
            if skip:
                if config.DEBUG:
                    try:
                        loggvar("FILTERED: %s [%s]" % (str(msg), reason), chan)
                    except:
                        print colr("ERROR encoding filtered msg", 'red'), msg, reason
                        loggvar("FILTERED: %s [%s]" % (msg, reason), chan)
                self._queueEmptying[chan] = reactor.callLater(0.05, self._sendLine, chan)
            else:
                self._reallySendLine(line)
                self._queueEmptying[chan] = reactor.callLater(self.lineRate, self._sendLine, chan)
        else:
            self._queueEmptying[chan] = None

    def _reallySendLine(self, line):
        if line.startswith('PRIVMSG '):
            target = "private"
            if line[8] == "#":
                target = line[8:line.find(":")].lower().strip()
            line = self.colorizer[target].colorize(line)
        return NamesIRCClient._reallySendLine(self, line)

    def msg(self, target, msg):
        NamesIRCClient.msg(self, target, msg, 400)

    re_clean_protocol = re.compile(r'^\[[^\]]+\]\s*')
    def _send_message(self, msgs, target, nick=None, tasks=None):
        if msgs is None:
            return
        if not isinstance(msgs, types.ListType):
            try:
                msgs = msgs.encode('utf-8')
            except:
                msgs = str(msgs)
            msgs = [(True, m) for m in msgs.strip().split('\n')]
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
            if nick and target != nick:
                msg = '%s: %s' % (nick, msg)
            if tasks is not None:
                msg += " [Task #%s]" % tasks
            self.msg(target, msg)

    def _show_error(self, failure, target, nick=None, admins=False):
        if not admins:
            loggerr(failure, target)
        if not nick and not admins:
            return
        msg = "Woooups, something is wrong…"
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


   # Default commands
   # ----------------
   ## Available to anyone
   ## Exclude regexp : '(help|test|chans|source)'

    link_commands = ' or read https://github.com/RouxRC/gazouilleur/blob/master/LIST_COMMANDS.md'
    txt_list_comds = '" to list my commands%s' % link_commands
    def command_help(self, rest, channel=None, nick=None, discreet=False):
        """help [<command>] : Prints general help or help for specific <command>."""
        rest = rest.lstrip(COMMAND_CHAR_STR).lower()
        conf = chanconf(channel)
        commands = [c for c in [c.replace('command_', '') for c in dir(self) if c.startswith('command_')] if self._can_user_do(nick, channel, c, conf)]
        def_msg = 'Type "%shelp' % COMMAND_CHAR_DEF
        if not discreet:
            def_msg = 'My commands are:  %s%s\n%s <command>" to get more details%s' % (COMMAND_CHAR_DEF, (' ;  %s' % COMMAND_CHAR_DEF).join(commands), def_msg, self.link_commands)
        else:
            def_msg += self.txt_list_comds
        if rest is None or rest == '':
            return def_msg
        elif rest in commands:
            doc = clean_doc(self._get_command_doc(rest))
            if not chan_has_identica(channel, conf):
                doc = clean_identica(doc)
            return COMMAND_CHAR_DEF + doc
        return '%s%s is not a valid command. %s' % (COMMAND_CHAR_DEF, rest, def_msg)

    def command_test(self, *args):
        """test : Simple test to check whether I'm present."""
        return 'Hello! Type "%shelp%s' % (COMMAND_CHAR_DEF, self.txt_list_comds)

    def command_chans(self, rest, channel=None, *args):
        """chans : Prints the list of all the channels I'm in."""
        chans = [chan for chan in self.factory.channels if chan != channel.lower()]
        if not len(chans):
            return "I'm only hanging out here."
        return "I'm currently hanging out in %s. Come visit!" % " ; ".join(chans)

    def command_source(self, *args):
        """source : Gives the link to my sourcecode."""
        return 'My sourcecode is under free GPL 3.0 licence and available at the following address: %s' % self.sourceURL


   # Logs Query commands
   # -------------------
   ## Available to anyone
   ## Exclude regexp : '(last(from|with|seen)?|.*more)'

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

    re_matchcommands = re.compile(r'-(-(from|with|skip|chan)|[fwsc])', re.I)
    @inlineCallbacks
    def command_last(self, rest, channel=None, nick=None, reverse=False):
        """last [<N>] [--from <nick>] [--with <text>] [--chan <chan>|--allchans] [--skip <nb>] [--filtered|--nofilter] : Prints the last or <N> (max 5) last message(s) from current or main channel if <chan> is not given, optionally starting back <nb> results earlier and filtered by user <nick> and by <text>. --nofilter includes tweets that were not displayed because of filters, --filtered searches only through these."""
        # For private queries, give priority to master chan if set in for the use of !last commands
        nb = 0
        def_nb = 1
        master = get_master_chan(self.nickname)
        if channel == self.nickname and master != self.nickname:
            channel = master
            def_nb = 10
        re_nick = re.compile(r'^\[[^\[]*'+nick, re.I)
        query = {'channel': channel.lower(), '$and': [{'filtered': {'$ne': True}}, {'message': {'$not': self.re_lastcommand}}, {'message': {'$not': re_nick}}], '$or': [{'user': {'$ne': self.nickname.lower()}}, {'message': {'$not': re.compile(r'^('+self.nickname+' —— )?('+nick+': \D|[^\s:]+: ('+COMMAND_CHAR_REG+'|\[\d))')}}]}
        st = 0
        current = ""
        allchans = False
        rest = cleanblanks(handle_quotes(rest))
        for arg in rest.split(' '):
            if current == "f":
                query['user'] = arg.lower()
                current = ""
            elif current == "w":
                arg = clean_regexp(arg)
                re_arg = re.compile(r"%s" % arg, re.I)
                query['$and'].append({'message': re_arg})
                current = ""
            elif current == "s":
                st = max(st, safeint(arg))
                current = ""
            elif current == "c":
                chan = '#'+arg.lower().lstrip('#')
                if 'channel' not in query:
                    returnD("Either use --allchans or --chan <channel> but both is just stupid :p")
                if chan in self.factory.channels:
                    query['channel'] = chan
                else:
                    returnD("I do not follow this channel.")
                current = ""
            elif arg.isdigit():
                maxnb = 5 if def_nb == 1 else def_nb
                nb = max(nb, min(safeint(arg), maxnb))
            elif arg == "--nofilter" or arg == "--filtered":
                query['$and'].remove({'filtered': {'$ne': True}})
                if arg == "--filtered":
                    query['$and'].append({'filtered': True})
            elif arg == "--allchans":
                allchans = True
                del query['channel']
            elif self.re_matchcommands.match(arg):
                current = arg.lstrip('-')[0]
        if not nb:
            nb = def_nb
        self.lastqueries[channel.lower()] = {'n': nb, 'skip': st+nb}
        if config.DEBUG:
            loggvar("Requesting last %s %s" % (rest, query), channel, "!last")
        matches = yield self.db['logs'].find(query, filter=sortdesc('timestamp'), fields=['timestamp', 'screenname', 'message', 'channel'], limit=nb, skip=st)
        if len(matches) == 0:
            more = " more" if st > 1 else ""
            returnD("No"+more+" match found in my history log.")
        if reverse:
            matches.reverse()
        returnD("\n".join(['[%s%s] %s — %s' % (shortdate(l['timestamp']), " %s" % l['channel'].encode('utf-8') if allchans else "", l['screenname'].encode('utf-8'), l['message'].encode('utf-8')) for l in matches]))

    def command_lastfrom(self, rest, channel=None, nick=None):
        """lastfrom [<N>] <nick> : Alias for "last --from", prints the last or <N> (max 5) last message(s) from user <nick> (options from "last" except --from can apply)."""
        nb, fromnick = self._extract_digit(rest)
        return self.command_last("%s --from %s" % (nb, fromnick), channel, nick)

    def command_lastwith(self, rest, channel=None, nick=None):
        """lastwith [<N>] <text> : Alias for "last --with", prints the last or <N> (max 5) last message(s) matching <text> (options from "last" can apply)."""
        nb, word = self._extract_digit(rest)
        return self.command_last("%s --with %s" % (nb, word), channel, nick)

    re_lastcommand = re.compile(r'^%s(last|more)' % COMMAND_CHAR_REG, re.I)
    re_optionsfromwith = re.compile(r'\s*--(from|with)\s*(\d*)\s*', re.I)
    re_optionskip = re.compile(r'\s*--skip\s*(\d*)\s*', re.I)
    @inlineCallbacks
    def command_lastmore(self, rest, channel=None, nick=None):
        """lastmore [<N>] : Prints 1 or <N> more result(s) (max 5) from previous "last" "lastwith" "lastfrom" or "lastcount" command (options from "last" except --skip can apply; --from and --with will reset --skip to 0)."""
        channel = channel.lower()
        master = get_master_chan(self.nickname)
        if channel == self.nickname.lower() and master != self.nickname:
            lowchan = master.lower()
        else:
            lowchan = channel
        if not rest:
            nb = self.lastqueries[lowchan]['n']
        else:
            nb, rest = self._extract_digit(rest)
        tmprest = rest
        st = self.lastqueries[lowchan]['skip']
        last = yield self.db['logs'].find({'channel': channel, 'message': self.re_lastcommand, 'user': nick.lower()}, fields=['message'], filter=sortdesc('timestamp'), skip=1)
        for m in last:
            command, _, text = m['message'].encode('utf-8').lstrip(COMMAND_CHAR_STR).partition(' ')
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
                    res = yield function(tmprest, channel, nick)
                    returnD(res)
        returnD("No %slast like command found in my history log." % COMMAND_CHAR_DEF)

    def command_more(self, rest, channel=None, nick=None):
        """more [<N>] : Alias for "lastmore". Prints 1 or <N> more result(s) (max 5) from previous "last" "lastwith" "lastfrom" or "lastcount" command (options from "last" except --skip can apply; --from and --with will reset --skip to 0)."""
        return self.command_lastmore(rest, channel, nick)

    @inlineCallbacks
    def command_lastseen(self, rest, channel=None, nick=None):
        """lastseen <nickname> : Prints the last time <nickname> was seen logging in and out."""
        user, _, msg = rest.partition(' ')
        if user == '':
            returnD("Please ask for a specific nickname.")
        re_user = re.compile(r'^\[[^\[]*'+user, re.I)
        channel = self.getMasterChan(channel)
        query = {'user': user.lower(), 'message': re_user, 'channel': channel}
        res = yield self.db['logs'].find(query, fields=['timestamp', 'message'], filter=sortdesc('timestamp'), limit=2)
        if res:
            res.reverse()
            returnD(" —— ".join(["%s %s %s" % (shortdate(m['timestamp']), m['message'].encode('utf-8')[1:-1], channel) for m in res]))
        res = yield self.command_lastfrom(user, channel, nick)
        returnD(res)


   # Twitter counting commands
   # -------------------------
   ## Available to anyone
   ## Exclude regexp : '.*count'

    def _check_answered_accounts(self, channel, tweet_id, text):
        conf = chanconf(channel)
        conn = Microblog('twitter', conf)
        tweet = conn.show_status(tweet_id)
        if not isinstance(tweet, dict) or 'text' not in tweet:
            return tweet

        tocheck = [tweet['user']['screen_name']] + [u['screen_name'] for u in tweet.get('entities', {}).get('user_mentions', [])]
        warnings = []
        searchable = text.decode('utf-8').lower()
        for account in tocheck:
            if re.compile(r"(^|\W)@%s\b" % account.lower()).search(searchable):
                warnings.append("@%s" % account)
        return warnings

    re_match_dm = re.compile(r'^\s*%sdm\s+' % COMMAND_CHAR_REG, re.I)
    re_match_answer = re.compile(r'^\s*%sanswer(last|\s+(https?://twitter.com/\S+?/)?\d+)\s+' % COMMAND_CHAR_REG, re.I)
    @inlineCallbacks
    def command_count(self, rest, channel=None, nick=None, _return_value=False):
        """count <text> : Prints the character length of <text> (spaces will be trimmed, urls will be shortened to Twitter's t.co length)."""
        limit = " (max 280)" if not self.re_match_dm.match(rest) else ""
        answ = self.re_match_answer.search(rest)
        if answ:
            channel = self.getMasterChan(channel)
            rest = self.re_match_answer.sub('', rest).strip()
            tweet_id = answ.group(1).strip()
            if answ.group(2):
                tweet_id = tweet_id.replace(answ.group(2), '')
            if tweet_id == 'last' and _return_value:
                tweet_id = yield self.db['lasttweets'].find({'channel': channel})
                if not tweet_id:
                    returnD("Sorry, no last tweet id found for this chan.")
                tweet_id = tweet_id[0]["tweet_id"]
            warnings = self._check_answered_accounts(channel, tweet_id, rest)
            rest, force = self._match_reg(rest, self.re_force)
            if warnings and not force and (tweet_id != 'last' or _return_value):
                if type(warnings) != list:
                    returnD(warnings)
                else:
                    returnD("[twitter] Characters for @accounts answered to don't count anymore in tweets, you shouldn't include %s in your tweet, except for names actually part of your message in which case they do count as characters (use --force to allow it)" % " & ".join(warnings))

        res = countchars(rest, self.twitter["url_length"])

        if _return_value:
            returnD(res)
        returnD("%d characters%s" % (res, limit))

    def command_lastcount(self, rest, channel=None, nick=None):
        """lastcount : Prints the latest "count" command and its result (options from "last" except <N> can apply)."""
        res = self.re_optionskip.search(rest)
        if res:
            st = safeint(res.group(1)) * 2
            rest = self.re_optionskip.sub(' --skip %s ' % st, rest)
        return self.command_last("2 --with ^"+COMMAND_CHAR_DEF+"count|\S+:\s\d+\scharacters %s" % rest, channel, nick, True)


   # Twitter & Identi.ca sending commands
   # ------------------------------------
   ## Twitter available when TWITTER's USER, KEY, SECRET, OAUTH_TOKEN and OAUTH_SECRET are provided in gazouilleur/config.py for the chan and FORBID_POST is not given or set to True.
   ## Identi.ca available when IDENTICA's USER is provided in gazouilleur/config.py for the chan.
   ## available to anyone if TWITTER's ALLOW_ALL is set to True, otherwise only to GLOBAL_USERS and chan's USERS
   ## Exclude regexp : '(identica|twit.*|answer.*|rt|like|(rm|last)*tweet(later)?|dm|finduser|stats|(un)?friend|show(thread)?)' (setting FORBID_POST to True already does the job)

    str_re_tweets = ' — https?://twitter\.com/'
    def command_lasttweet(self, options, channel=None, nick=None):
        """lasttweet [<N>] [<options>] : Prints the last or <N> last tweets sent with the channel's account (options from "last" except --from can apply)./TWITTER"""
        chan = self.getMasterChan(channel)
        twuser = get_chan_twitter_user(chan)
        return self.command_lastwith("\"^%s: .*%s%s/statuse?s?/\" --from %s %s" % (twuser, self.str_re_tweets, twuser, options, self.nickname), channel, nick)

    re_force = re.compile(r'\s*--force\s*')
    re_nolimit = re.compile(r'\s*--nolimit\s*')
    def _match_reg(self, text, regexp):
        if regexp.search(text):
            return regexp.sub(' ', text).strip(), True
        return text, False

    def _clean_quotetweet(self, text):
        quote_tweet = None
        quote = re_clean_tweets.search(text)
        if quote:
            quote_tweet = ("https://%s%s" % (quote.group(1), quote.group(2))).lower()
            text = clean_tweets(text)
        return text, quote_tweet

    re_clean_twitter_task = re.compile(r'^(%s(count|identica|(tw(ee|it)t?|answ)(er(last)?|only)*)\s*(\d{14}\d*\s*)?)+' % COMMAND_CHAR_REG, re.I)
    def _send_via_protocol(self, siteprotocol, command, channel, nick, **kwargs):
        channel = self.getMasterChan(channel)
        conf = chanconf(channel)
        if not chan_has_protocol(channel, siteprotocol, conf):
            return "No %s account is set for this channel." % siteprotocol
        if command in ['microblog', 'retweet']:
            kwargs['channel'] = channel
        conn = Microblog(siteprotocol, conf)
        if 'text' in kwargs:
            kwargs['text'], nolimit = self._match_reg(kwargs['text'], self.re_nolimit)
            kwargs['text'], force = self._match_reg(kwargs['text'], self.re_force)
            kwargs['text'] = self.re_clean_twitter_task.sub('', kwargs['text'])
            try:
                kwargs['length'] = countchars(kwargs['text'], self.twitter["url_length"])
            except:
                kwargs['length'] = 100
            if kwargs['length'] < 30 and not nolimit:
                return "Do you really want to send such a short message? (%s chars) add --nolimit to override" % kwargs['length']
            if kwargs['length'] > 280 and siteprotocol == "twitter" and command != "directmsg" and not nolimit:
                return "[%s] Sorry, but that's too long (%s characters) add --nolimit to override" % (siteprotocol, kwargs['length'])
            if siteprotocol == "twitter" and command != "directmsg":
                if not kwargs.get("imgs", ""):
                    kwargs['text'], kwargs['quote_tweet'] = self._clean_quotetweet(kwargs['text'])
                if not force:
                    bl, self.twitter['users'], msg = conn.test_microblog_users(kwargs['text'], self.twitter['users'])
                    if not bl:
                        return "[%s] %s" % (siteprotocol, msg)
                else:
                    kwargs["force"] = True
        command = getattr(conn, command, None)
        return command(**kwargs)

    def command_identica(self, text, channel=None, nick=None):
        """identica <text> [--nolimit] : Posts <text> as a status on Identi.ca (--nolimit overrides the minimum 30 characters rule)./IDENTICA"""
        return threads.deferToThread(self._send_via_protocol, 'identica', 'microblog', channel, nick, text=text)

    tweet_url = r"https?://\S*twitter.com/[^/]+/statuse?s?/(\d+)(?:/\S*)?\s+"
    re_twitter_url = re.compile(r"^%s" % tweet_url)
    re_answer = re.compile('^(%sanswer|\d{14}|%s)' % (COMMAND_CHAR_REG, tweet_url))
    @inlineCallbacks
    def command_twitteronly(self, text, channel=None, nick=None):
        """twitteronly <text> [--nolimit] [--force] [img:<url>] : Posts <text> as a status on Twitter (see twitter command's help for other options)./TWITTER/IDENTICA"""
        if self.re_answer.match(text.strip()):
            returnD("Mmmm… Didn't you mean %s%s instead?" % (COMMAND_CHAR_DEF, "answer" if len(text) > 16 else "rt"))
        res = yield self._process_twitpics(text, channel)
        if isinstance(res, str):
            returnD(res)
        returnD(self._send_via_protocol('twitter', 'microblog', channel, nick, text=res[0], imgs=res[1]))

    def command_tweet(self, text, channel=None, nick=None):
        """tweet <text> [--nolimit] [--force] [img:<url>] : Alias for twitter command./TWITTER"""
        return self.command_twitter(text, channel=channel, nick=nick)

    def command_twitter(self, text, channel=None, nick=None):
        """twitter <text> [--nolimit] [--force] [img:<url>] : Posts <text> as a status on Identi.ca and on Twitter. Include up to 4 images with img:<url> at no character cost. --nolimit overrides the minimum 30 characters rule. --force overrides the restriction to mentions users I couldn't find on Twitter or already included in the conversation for answers./TWITTER"""
        if self.re_answer.match(text.strip()):
            return("Mmmm… Didn't you mean %s%s instead?" % (COMMAND_CHAR_DEF, "answer" if len(text) > 16 else "rt"))
        channel = self.getMasterChan(channel)
        dl = []
        dl.append(maybeDeferred(self.command_twitteronly, text, channel, nick))
        if chan_has_identica(channel):
            dl.append(maybeDeferred(self._send_via_protocol, 'identica', 'microblog', channel, nick, text=text.replace('img:', '')))
        return DeferredList(dl, consumeErrors=True)

    re_img = re.compile(r'\s*img:(https?://\S+)\s*', re.I)
    @inlineCallbacks
    def _process_twitpics(self, text, channel=None):
        img_urls = []
        while self.re_img.search(text):
            img_urls.append(self.re_img.search(text).group(1))
            text = self.re_img.sub(' ', text, 1)
        text = text.strip()
        imgs = []
        if img_urls:
            conf = chanconf(channel)
            conn = Microblog("twitter", conf, upload=True)
            res = yield DeferredList([self._dl_and_send_img(url, conn) for url in img_urls], consumeErrors=True)
            for bl, val in res:
                if not bl or isinstance(val, str):
                    returnD("[twitter] %s" % val)
                imgs.append(val[1])
        returnD((text, imgs))

    @inlineCallbacks
    def _dl_and_send_img(self, url, conn):
        imgtype = ""
        data = None
        try:
            data = yield client.getPage(url)
            imgtype = imghdr.what("", data)
            if not imgtype and data.startswith('\xff\xd8'):
                imgtype = "jpeg"
            assert(imgtype in ['png', 'jpeg', 'gif'])
        except Exception as e:
            del(data)
            returnD("Could not find a proper image to send at %s (only jpeg, png & gif accepted)." % url)
        ratio = 100. * len(data) / self.twitter['max_img_size']
        if ratio > 100:
            del(data)
            returnD("The %s image at %s is too big (%d%s max allowed size)." % (imgtype, url, int(ratio), '%'))
        res = yield conn.send_media(data)
        del(data)
        if type(res) is str and ("creation failed" in res or "Broken pipe" in res):
            returnD("Can't send %s image from %s, maybe it's too big?" % (imgtype, url))
        returnD((url, res['media_id_string']))

    @inlineCallbacks
    def command_answer(self, rest, channel=None, nick=None):
        """answer <tweet_id> <text> [--nolimit] [--force] [img:<url>] : Posts <text> as a status on Identi.ca and as a response to <tweet_id> on Twitter. <text> should not include anymore the @author of the tweet answered (see twitter command's help for other options)./TWITTER"""
        channel = self.getMasterChan(channel)
        rest = self.re_twitter_url.sub(r'\1 ', rest)
        tweet_id, text = self._extract_digit(rest)
        if tweet_id < 2 or text == "":
            returnD("Please input a correct tweet_id and message.")
        warnings = self._check_answered_accounts(channel, tweet_id, text)
        rest, force = self._match_reg(rest, self.re_force)
        if warnings and not force:
            if type(warnings) == list:
                returnD("Characters for @accounts answered to don't count anymore in tweets, you shouldn't include %s in your tweet, except for names actually part of your message in which case you can bypass this and consume characters by adding --force" % " & ".join(warnings))
            returnD(warnings)

        res = yield self._process_twitpics(text, channel)
        if isinstance(res, str):
            returnD(res)
        dl = []
        dl.append(maybeDeferred(self._send_via_protocol, 'twitter', 'microblog', channel, nick, text=res[0], tweet_id=tweet_id, imgs=res[1]))
        if chan_has_identica(channel):
            dl.append(maybeDeferred(self._send_via_protocol, 'identica', 'microblog', channel, nick, text=text.replace('img:', '')))
        res = yield DeferredList(dl, consumeErrors=True)
        returnD(res)

    @inlineCallbacks
    def command_answerlast(self, rest, channel=None, nick=None):
        """answerlast <text> [--nolimit] [--force] [img:<url>] : Send <text> as a tweet in answer to the last tweet sent to Twitter from the channel (see twitter command's help for other options)./TWITTER"""
        channel = self.getMasterChan(channel)
        lasttweetid = yield self.db['lasttweets'].find({'channel': channel})
        if not lasttweetid:
            returnD("Sorry, no last tweet id found for this chan.")
        res = yield self.command_answer("%s %s" % (str(lasttweetid[0]["tweet_id"]), rest), channel, nick)
        returnD(res)

    def _rt_on_identica(self, tweet_id, conf, channel, nick):
        conn = Microblog('twitter', conf)
        res = conn.show_status(tweet_id)
        if isinstance(res, dict) and 'user' in res and 'screen_name' in res['user'] and 'text' in res:
            tweet = "♻ @%s: %s" % (res['user']['screen_name'].encode('utf-8'), res['text'].encode('utf-8'))
            return self._send_via_protocol('identica', 'microblog', channel, nick, text=tweet)
        return res.replace("twitter", "identica")

    def command_rt(self, tweet_id, channel=None, nick=None):
        """rt <tweet_id> : Retweets <tweet_id> on Twitter and posts a ♻ status on Identi.ca./TWITTER"""
        channel = self.getMasterChan(channel)
        tweet_id = safeint(tweet_id, twitter=True)
        if not tweet_id:
            return "Please input a correct tweet_id."
        dl = []
        dl.append(maybeDeferred(self._send_via_protocol, 'twitter', 'retweet', channel, nick, tweet_id=tweet_id))
        conf = chanconf(channel)
        if chan_has_identica(channel, conf):
            dl.append(maybeDeferred(self._rt_on_identica, tweet_id, conf, channel, nick))
        return DeferredList(dl, consumeErrors=True)

    def command_like(self, tweet_id, channel=None, nick=None):
        """like <tweet_id> : Likes (ex-favorites) <tweet_id> on Twitter./TWITTER"""
        channel = self.getMasterChan(channel)
        tweet_id = safeint(tweet_id, twitter=True)
        if not tweet_id:
            return "Please input a correct tweet_id."
        return threads.deferToThread(self._send_via_protocol, 'twitter', 'like', channel, nick, tweet_id=tweet_id)

    def command_rmtweet(self, tweet_id, channel=None, nick=None):
        """rmtweet <tweet_id> : Deletes <tweet_id> from Twitter./TWITTER"""
        channel = self.getMasterChan(channel)
        tweet_id = safeint(tweet_id, twitter=True)
        if not tweet_id:
            return "Please input a correct tweet_id."
        return threads.deferToThread(self._send_via_protocol, 'twitter', 'delete', channel, nick, tweet_id=tweet_id)

    @inlineCallbacks
    def command_rmlasttweet(self, tweet_id, channel=None, nick=None):
        """rmlasttweet : Deletes last tweet sent to Twitter from the channel./TWITTER"""
        channel = self.getMasterChan(channel)
        lasttweetid = yield self.db['lasttweets'].find({'channel': channel})
        if not lasttweetid:
            returnD("Sorry, no last tweet id found for this chan.")
        res = yield self.command_rmtweet(str(lasttweetid[0]['tweet_id']), channel, nick)
        returnD(res)

    @inlineCallbacks
    def command_friend(self, user, channel=None, nick=None, unfriend=False):
        """friend <user> : Follows <user> with the chan's Twitter account (use follow to display tweets)./TWITTER"""
        channel = self.getMasterChan(channel)
        user = user.lstrip('@').strip('').lower()
        if not re.match("^%s$" % TWITTER_ACCOUNT, user):
            returnD("Please input a valid Twitter user name.")
        account = yield self._send_via_protocol('twitter', '%sfollow' % ("un" if unfriend else ""), channel, nick, user=user)
        if isinstance(account, str):
            conf = chanconf(channel)
            conn = Microblog('twitter', conf, bearer_token=conf["oauth2"])
            test, _ = conn.lookup_users([user], return_first_result=True)
            if test and test["protected"]:
                account = test
            else:
                returnD(account)
        msg = "Huge success "
        if unfriend:
            if account["following"]:
                msg = "Huge success un"
            else: msg = "We weren't "
        elif account["protected"] and "status" not in account:
            msg = "Protected account: pending confirmation for "
        elif account["notifications"] or account["protected"]:
            msg = "We're already "
        returnD("[twitter] %sfollowing @%s" % (msg, account["screen_name"]))

    def command_unfriend(self, user, channel=None, nick=None):
        """unfriend <user> : Stops following <user> with the chan's Twitter account./TWITTER"""
        return self.command_friend(user, channel, nick, True)

    @inlineCallbacks
    def command_dm(self, rest, channel=None, nick=None):
        """dm <user> <text> [--nolimit] : Posts <text> as a direct message to <user> on Twitter. Will also add myself to <user>'s followers so he can answer further on. (--nolimit overrides the minimum 30 characters rule)./TWITTER"""
        channel = self.getMasterChan(channel)
        user, _, text = rest.partition(' ')
        user = user.lstrip('@').lower()
        if user == "" or text == "":
            returnD("Please input a user name and a message.")
        res = yield self.command_friend(user, channel, nick)
        if "success following" in res:
            yield self._send_message("[twitter] Started following @%s with chan's account" % user, channel, nick)
        elif "Protected account" in res:
            yield self._send_message(res, channel, nick)
        res = yield self._send_via_protocol('twitter', 'directmsg', channel, nick, username=user, text=text)
        returnD(res)

    @inlineCallbacks
    def command_finduser(self, rest, channel=None, nick=None):
        """finduser <query> [<N=3>] : Searches <query>through Twitter User and returns <N> results (defaults 3, max 20)./TWITTER"""
        channel = self.getMasterChan(channel)
        conf = chanconf(channel)
        count, query = self._extract_digit(rest)
        if " %s " % str(count) in " %s " % rest:
            count = min(count, 20)
        else:
            count = 3
        if query == "":
            returnD("Please input a text query.")
        conn = Microblog('twitter', conf)
        names = conn.search_users(query, count)
        if not names:
            returnD("No result found for %s" % query)
        infofirst = yield self.command_show(names[0], channel, nick)
        returnD([(True, ("Are you looking for @%s ?" % " or @".join(names)).encode('utf-8')), (True, infofirst)])

    @inlineCallbacks
    def _format_tweet(self, tweet, light=False):
        user = tweet['user']
        name = user['screen_name'].encode('utf-8')
        text = tweet['text']
        text, self.cache_urls = yield clean_redir_urls(text.replace('\n', ' '), self.cache_urls)
        if "timestampDB" in tweet:
            ts = tweet["timestampDB"]
        else:
            #ts = datetime.strptime(tweet.get('created_at', ''), '%a %b %d %H:%M:%S +0000 %Y') + timedelta(hours=2)
            ts = parse_date(tweet.get('created_at', ''))
        date = ts.strftime('%Y-%m-%d %H:%M:%S').encode('utf-8')
        source = " - %s" % clean_html(tweet['source']).encode('utf-8')
        extra = u" - %s ♻" % tweet['retweet_count'] if 'retweet_count' in tweet and tweet['retweet_count'] else ""
        extra += u" - %s ♥" % tweet['favorite_count'] if 'favorite_count' in tweet and tweet['favorite_count'] else ""
        text = format_tweet({"message": text, "link": u"https://twitter.com/%s/status/%s" % (user['screen_name'], tweet['id_str'])})
        if light:
            returnD("%s: %s (%s%s)" % (name, text, date, extra.encode('utf-8')))
        returnD("%s (%d followers): %s (%s%s%s)" % (name, user['followers_count'], text, date, source, extra.encode('utf-8')))

    @inlineCallbacks
    def _show_status_even_deleted(self, twconn, twid, channel, nick):
        tweet = twconn.show_status(twid)
        if not isinstance(tweet, dict):
            localtweet = yield self.db['tweets'].find_one({'id': long(twid)})
            if localtweet:
                yield self._send_message("[twitter] Warning: tweet %s was deleted, retrieving an archive from my database" % twid, channel, nick)
                tweet = {
                    "id_str": str(twid),
                    "user": {
                        "screen_name": localtweet["screenname"],
                        "followers_count": localtweet["user_followers"]
                    },
                    "text": localtweet["message"],
                    "timestampDB": localtweet["date"],
                    "source": localtweet["source"],
                    "in_reply_to_status_id_str": localtweet["in_reply_to_status_id_str"]
                }
        returnD(tweet)

    @inlineCallbacks
    def command_show(self, rest, channel=None, nick=None):
        """show <tweet_id|@twitter_user> : Displays message and info on tweet with id <tweet_id> or on user <@twitter_user>."""
        channel = self.getMasterChan(channel)
        conf = chanconf(channel)
        if not get_chan_twitter_user(channel, conf):
            returnD('Sorry but no Twitter account is set for this channel.')
        conn = Microblog('twitter', conf, bearer_token=conf["oauth2"])
        tweet_id = safeint(rest, twitter=True)
        if tweet_id:
            tweet = yield self._show_status_even_deleted(conn, tweet_id, channel, nick)
            if not isinstance(tweet, dict):
                returnD(tweet)
            fmtweet = yield self._format_tweet(tweet)
            returnD(fmtweet)
        user, _ = conn.lookup_users([rest], return_first_result=True)
        if not user:
            returnD("Please provide a valid tweet_id or twitter_user.")
        name = user['screen_name'].encode('utf-8')
        verified = " (certified)" if 'verified' in user and user['verified'] else ""
        url = " - %s" % user['url'] if 'url' in user and user['url'] else ""
        description, self.cache_urls = yield clean_redir_urls(user['description'].replace('\n', ' ') + url, self.cache_urls)
        returnD("@%s (%s): %s (%d tweets, %d followers) — https://twitter.com/%s%s" % (name, user['name'].encode('utf-8'), description.encode('utf-8'), user['statuses_count'], user['followers_count'], name, verified))

    @inlineCallbacks
    def command_showthread(self, rest, channel=None, nick=None):
        """showthread <tweet_id> : Displays conversation around tweet with id <tweet_id>."""
        channel = self.getMasterChan(channel)
        conf = chanconf(channel)
        if not get_chan_twitter_user(channel, conf):
            returnD('Sorry but no Twitter account is set for this channel.')
        conn = Microblog('twitter', conf, bearer_token=conf["oauth2"])
        tweet_id = safeint(rest, twitter=True)
        if not tweet_id:
            returnD("Please provide a valid tweet_id.")
        todo = [tweet_id]
        done = []
        tweets = {}
        root = None
        while todo:
            curid = todo.pop(0)
            done.append(curid)
            answers = yield self.db['tweets'].find({'in_reply_to_status_id_str': str(curid)}, fields=['id'])
            for tw in answers:
                if tw['id'] not in done + todo:
                    todo.append(tw['id'])
            tweet = yield self._show_status_even_deleted(conn, curid, channel, nick)
            if not isinstance(tweet, dict):
                continue
            repl = tweet["in_reply_to_status_id_str"]
            if not repl:
                root = curid
            else:
                repl = int(repl)
                if repl not in done + todo:
                    todo.append(repl)
                if repl not in tweets:
                    tweets[repl] = {"repls": []}
                tweets[repl]["repls"].append(curid)
            if not curid in tweets:
                tweets[curid] = {"repls": []}
            tweets[curid]["text"] = yield self._format_tweet(tweet, light=True)
        if not tweets:
            returnD("[twitter] ERROR 404: Cannot find that tweet.")
        if not root:
            root = min(tweets.keys())
            tweets[root]["text"] = "Deleted tweet - https://twitter.com/i/web/status/%s" % root
        returnD("\n".join(self._convtree(tweets, root)))

    def _convtree(self, tree, root):
        if "text" not in tree[root]:
            return []
        conv = [tree[root]['text']]
        tree[root]['repls'].sort()
        for repl in tree[root]['repls']:
            conv += ["-> %s" % t for t in self._convtree(tree, repl)]
        return conv

    def command_stats(self, rest, channel=None, nick=None):
        """stats : Prints stats on the Twitter account set for the channel./TWITTER"""
        channel = self.getMasterChan(channel)
        twuser = get_chan_twitter_user(channel).lower()
        stats = Stats(twuser)
        return stats.print_last()


   # Twitter, RSS Feeds & Webpages monitoring commands
   # -------------------------------------------------
   ## (Un)Follow, (Un)Filter and Monitor available only to GLOBAL_USERS and chan's USERS
   ## Others available to anyone
   ## Exclude regexp : '(u?n?f(ollow|ilter)|u?n?monitor|list|newsurl|last(tweet|news)|digest)'

    @inlineCallbacks
    def _restart_feeds(self, channel):
        conf = chanconf(channel)
        lowchan = channel.lower()
        feeds = [('stream', 'stream', 5, 90), ('twitter_search', 'search', 90, 600)]
        for feed, database, delay, timeout in feeds:
            if feed in self.feeders[lowchan] and self.feeders[lowchan][feed].status == "running":
                yield self.feeders[lowchan][feed].end()
                self.feeders[lowchan][feed] = FeederFactory(self, channel, database, delay * (1 if conf["oauth2"] else 2), timeout=timeout, twitter_token=conf["oauth2"])
                self.feeders[lowchan][feed].start()

    re_url = re.compile(r'\s*(https?://\S+)\s*', re.I)
    @inlineCallbacks
    def command_follow(self, query, channel=None, nick=None, webpages=False):
        """follow <name rssUrl|text|@user> : Asks me to follow and display elements from a RSS named <name> at <rssUrl>, or tweets matching <text> or from <@user>./AUTH"""
        channel = self.getMasterChan(channel)
        url = self.re_url.search(query)
        if url and url.group(1):
            database = 'news' if not webpages else 'pages'
            name = remove_ext_quotes(query.replace(url.group(1), '').strip().lower())
            query = url.group(1)
        elif webpages:
            returnD("Please specify a url for the page %s you want to monitor (%shelp monitor for more info)." % (query, COMMAND_CHAR_DEF))
        else:
            database = 'tweets'
            name = 'TWEETS: %s' % query
        if query == "":
            returnD("Please specify what you want to follow (%shelp follow for more info)." % COMMAND_CHAR_DEF)
        if len(query) > 300:
            returnD("Please limit your follow queries to a maximum of 300 characters")
        if database != "tweets" and name == "":
            returnD("Please provide a name for this url feed.")
        yield self.db['feeds'].update({'database': database, 'channel': channel, 'name': name}, {'database': database, 'channel': channel, 'name': name, 'query': query, 'user': nick, 'timestamp': datetime.today()}, upsert=True)
        if database == "tweets":
            reactor.callLater(0.5, self._restart_feeds, channel)
        else:
            query = "%s <%s>" % (name, query)
        returnD('«%s» query added to %s database for %s' % (query, database, channel))

    re_clean_query = re.compile(r'([()+|$])')
    regexp_feedquery = lambda self, x: re.compile(r'^%s$' % self.re_clean_query.sub(r'\\\1', x), re.I)
    @inlineCallbacks
    def command_unfollow(self, query, channel=None, nick=None, webpages=False):
        """unfollow <name|text|@user> : Asks me to stop following and displaying elements from a RSS named <name>, or tweets matching <text> or from <@user>./AUTH"""
        channel = self.getMasterChan(channel)
        query = query.strip("«»")
        database = 'news' if not webpages else 'pages'
        res = yield self.db['feeds'].remove({'channel': channel, 'name': self.regexp_feedquery(remove_ext_quotes(query)), 'database': database}, safe=True)
        if not ((res and res['n']) or webpages):
            database = 'tweets'
            res = yield self.db['feeds'].remove({'channel': channel, 'query': self.regexp_feedquery(query), 'database': database}, safe=True)
        if not res or not res['n']:
            returnD("I could not find such query in my database")
        if database == "tweets":
            reactor.callLater(0.5, self._restart_feeds, channel)
        returnD('«%s» query removed from %s database for %s' % (query, database, channel))

    def command_monitor(self, query, channel=None, nick=None):
        """monitor <name> <url> : Asks me to regularily check and tell if the webpage at <url> and identified as <name> changes./AUTH"""
        return self.command_follow(query, channel, nick, webpages=True)

    def command_unmonitor(self, query, channel=None, *args):
        """unmonitor <name> : Asks me to stop monitoring changes on the webpage named <name>./AUTH"""
        return self.command_unfollow(query, channel, webpages=True)

    @inlineCallbacks
    def command_filter(self, keyword, channel=None, nick=None):
        """filter <word|@user> : Filters the display of tweets or news containing <word> or sent by user <@user>, except for tweets from or quoting the chan's account./AUTH"""
        channel = self.getMasterChan(channel)
        keyword = keyword.lower().strip()
        if keyword == "":
            returnD("Please specify what you want to follow (%shelp follow for more info)." % COMMAND_CHAR_DEF)
        yield self.db['filters'].update({'channel': channel, 'keyword': keyword}, {'channel': channel, 'keyword': keyword, 'user': nick, 'timestamp': datetime.today()}, upsert=True)
        self.filters[channel.lower()].append(keyword)
        returnD('«%s» filter added for tweets displays on %s' % (keyword, channel))

    @inlineCallbacks
    def command_unfilter(self, keyword, channel=None, nick=None):
        """unfilter <word|@user> : Removes a tweets display filter for <word> or <@user>./AUTH"""
        channel = self.getMasterChan(channel)
        keyword = keyword.lower().strip()
        res = yield self.db['filters'].remove({'channel': channel, 'keyword': keyword}, safe=True)
        if not res or not res['n']:
            returnD("I could not find such filter in my database")
        self.filters[channel.lower()].remove(keyword)
        returnD('«%s» filter removed for tweets display on %s'  % (keyword, channel))

    @inlineCallbacks
    def command_list(self, database, channel=None, *args):
        """list [--chan <channel>] <tweets|news|filters|pages> : Displays the list of filters or pages monitored or news or tweets queries followed for current channel or optional <channel>."""
        try:
            database, channel = self._get_chan_from_command(database, channel)
        except Exception as e:
            returnD(str(e))
        database = database.strip()
        if database not in ["tweets", "news", "filters", "pages"]:
            returnD('Please enter either «%slist tweets», «%slist news», «%slist pages» or «%slist filters».' % (COMMAND_CHAR_DEF, COMMAND_CHAR_DEF, COMMAND_CHAR_DEF, COMMAND_CHAR_DEF))
        if database == "filters":
            feeds = assembleResults(self.filters[channel.lower()])
        else:
            feeds = yield getFeeds(self.db, channel, database, url_format=False)
        if database == 'tweets':
            res = "\n".join([f.replace(')OR(', '').replace(r')$', '').replace('^(', '').replace('from:', '@') for f in feeds])
        else:
            res = "\n".join(feeds)
        if res:
            returnD(res)
        returnD("No query set for %s." % database)

    @inlineCallbacks
    def command_newsurl(self, name, channel=None, *args):
        """newsurl <name> : Displays the url of a RSS feed or a monitored page saved as <name> for current channel."""
        channel = self.getMasterChan(channel)
        res = yield self.db['feeds'].find({'database': {"$in": ['news', 'pages']}, 'channel': channel, 'name': name.lower().strip()}, fields=['query', 'name', 'database'])
        if res:
            returnD(u"\n".join([u"«%s» (%s) : %s" % (r['name'], r['database'], r['query']) for r in res]).encode('utf-8'))
        returnD("No news feed named «%s» for this channel" % name)

    @inlineCallbacks
    def command_tweetswith(self, query, *args):
        """tweetswith <match> : Prints the total number of tweets seen matching <match> and the first one seen."""
        res = "No match found in my history of tweets seen."
        re_arg = re.compile(r"%s" % clean_regexp(query), re.I)
        total = yield self.db['tweets'].aggregate([{'$match': {'message': re_arg}}, {'$group': {'_id': '$id'}}, {'$group': {'_id': 1, 'count': {'$sum' : 1}}}])
        n_tot = total[0]['count'] if total else 0
        if n_tot:
            re_rts = re.compile(r"(([MLR]T|%s|♺)\s*)+@" % QUOTE_CHARS.encode('utf-8'), re.I)
            rts = yield self.db['tweets'].aggregate([{'$match': {'message': re_arg}}, {'$match': {'message': re_rts}}, {'$group': {'_id': '$id'}}, {'$group': {'_id': 1, 'count': {'$sum' : 1}}}])
            plural = "s" if rts and rts[0]['count'] > 1 else ""
            n_rts = " (including %d RT%s)" % (rts[0]['count'], plural) if rts else ""
            first = yield self.db['tweets'].find({'message': re_arg}, filter=sortasc('timestamp'), limit=1)
            first = first[0]
            name = first['screenname'].encode('utf-8')
            date = first['timestamp'].strftime('%Y-%m-%d %H:%M:%S').encode('utf-8')
            plural = "s" if n_tot > 1 else ""
            res = [(True, "%d tweet%s seen matching « %s »%s since the first one seen on %s:" % (n_tot, plural, query, n_rts, date)), (True, "%s: %s — https://twitter.com/%s/status/%d" % (name, first['message'].encode('utf-8'), name, first['id']))]
        returnD(res)

    def command_lasttweets(self, options, channel=None, nick=None):
        """lasttweets [<N>] [<options>] : Prints the last or <N> last tweets displayed on the chan (options from "last" except --from can apply)."""
        return self.command_lastwith("\"%s\" --from %s %s" % (self.str_re_tweets, options, self.nickname), channel, nick)

    str_re_news = '^[.* — https?://\S+$'
    def command_lastnews(self, options, channel=None, nick=None):
        """lastnews [<N>] [<options>] : Prints the last or <N> last news displayed on the chan (options from "last" except --from can apply)."""
        return self.command_lastwith("\"%s\" --from %s %s" % (self.str_re_news, options, self.nickname), channel, nick)

    def command_digest(self, hours, channel=None, nick=None):
        """digest [<H>|week|month] [--chan <channel>]: publishes a webpage with a digest of all unique links seen in news & tweets over the last week, month or <H> hours (defaults to 24) for current channel or optional <channel>./STATS"""
        try:
            hours, channel = self._get_chan_from_command(hours, channel)
        except Exception as e:
            return(str(e))
        hours = hours.strip().lower()
        if not hours or hours in ["d", "day"]:
            hours = 24
        elif hours in ["w", "week"]:
            hours = 24*7
        elif hours in ["m", "month"]:
            hours = 24*30
        hours = safeint(str(hours).strip())
        if not(hours):
            return('Please give in either "week", "month" or a number of hours.')
        twuser = get_chan_twitter_user(channel).lower()
        stats = Stats(twuser)
        return stats.digest(hours, channel)

   # Ping commands
   # -------------
   ## Available only to GLOBAL_USERS and chan's USERS except for NoPing to anyone
   ## Exclude regexp : '.*ping.*'

    re_comment = re.compile(r'^\[')
    @inlineCallbacks
    def command_ping(self, rest, channel=None, nick=None, onlyteam=False, pingall=False):
        """ping [<text>] : Pings all ops, admins, last 18h speakers and at most 5 more random users on the chan saying <text> except for users set with noping./AUTH"""
        channel = self.getMasterChan(channel)
        names = yield self._names(channel)
        noping = yield self.db['noping_users'].find({'channel': channel}, fields=['lower'])
        skip = [user['lower'].encode('utf-8') for user in noping] + [nick.lower(), self.nickname.lower()]
        left = [(name, name.strip('@').lower().rstrip('_1')) for name in names if name.strip('@').lower().rstrip('_1') not in skip]
        users = [name.strip('@') for name, _ in left if name.startswith('@')]
        lowerops = [name.lower() for name in users]
        others = [name for name, lower in left if lower not in lowerops]
        conf = chanconf(channel)
        chanadmins = list(config.GLOBAL_USERS)
        if conf:
            chanadmins += conf['USERS']
        for admin in chanadmins:
            lower = admin.lower()
            for user in [u.strip('@') for u, l in left if l == lower]:
                if user not in users and user.lower() not in lowerops:
                    users.append(user)
                    if user in others:
                        others.remove(user)
        random.shuffle(users)
        if not onlyteam:
            if pingall:
                limit = 50
            else:
                lowerothers = [name.lower() for name in others]
                recent_logs = yield self.db['logs'].find({'channel': channel, 'timestamp': {'$gte': datetime.today() - timedelta(hours=18)}, 'message': {'$not': self.re_comment}}, fields=['screenname'])
                recents = []
                recents = set([user['screenname'] for user in recent_logs if user['screenname'].lower() in lowerothers])
                lowerrecents = [name.lower() for name in recents]
                users += recents
                others = [name for name in others if name.lower() not in lowerrecents]
                limit = 5
            random.shuffle(others)
            if len(others) > limit:
                others = others[:limit]
            users += others
        if not len(users):
            returnD("There's no one to ping here :(")
        if rest.strip() == "":
            rest = "Ping!"
        else:
            rest = rest.decode('utf-8')
        rest += " %s" % " ".join(users)
        returnD(rest.encode('utf-8'))

    def command_pingall(self, rest, channel=None, nick=None):
        """pingall [<text>] : Pings all ops, admins and at most 50 more random users on the chan by saying <text> except for users set with noping./AUTH"""
        return self.command_ping(rest, channel, nick, pingall=True)

    def command_pingteam(self, rest, channel=None, nick=None):
        """pingteam [<text>] : Pings all ops and admins on the chan by saying <text> except for users set with noping./AUTH"""
        return self.command_ping(rest, channel, nick, onlyteam=True)

    re_stop = re.compile(r'\s*--stop\s*', re.I)
    re_list = re.compile(r'\s*--list\s*', re.I)
    split_list_users = lambda _, l: [x.lower() for x in l.split(" ")]
    @inlineCallbacks
    def command_noping(self, rest, channel=None, nick=None):
        """noping <user1> [<user2> [<userN>…]] [--stop] [--list] : Deactivates pings from ping command for <users 1 to N> listed. With --stop, reactivates pings for those users. With --list just gives the list of deactivated users."""
        channel = self.getMasterChan(channel)
        if not rest:
            rest = nick
        if self.re_list.search(rest):
            noping = yield self.db['noping_users'].find({'channel': channel}, fields=['user'])
            skip = [user['user'].encode('utf-8') for user in noping]
            text = "are"
            if not skip:
                skip.append("No one")
            if len(skip) < 2:
                text = "is"
            returnD("%s %s actually registered as noping." % (" ".join(skip), text))
        if self.re_stop.search(rest):
            no = ""
            again = "again"
            rest = self.re_stop.sub(' ', rest).replace('  ', ' ')
            users = rest.split(" ")
            yield self.db['noping_users'].remove({'channel': channel, 'lower': {'$in': [x.lower() for x in users]}})
        else:
            no = "not "
            again = "anymore"
            users = rest.split(" ")
            for user in users:
                yield self.db['noping_users'].update({'channel': channel, 'lower': user.lower()}, {'channel': channel, 'user': user, 'lower': user.lower(), 'timestamp': datetime.today()}, upsert=True)
        returnD("All right, %s will %sbe pinged %s." % (" ".join(users).strip(), no, again))


   # Tasks commands
   # --------------
   ## RunLater available to anyone
   ## Cancel & Tasks available only to GLOBAL_USERS and chan's USERS
   ## Exclude regexp : '(runlater|tasks|cancel)'

    re_chan_in_command = re.compile(r'\s*--chan\s+#?(\S+)\s*', re.I)
    def _get_chan_from_command(self, task, channel):
        search = self.re_chan_in_command.search(task)
        if search:
            optchan = "#%s" % search.group(1).lower().lstrip('#')
            task = self.re_chan_in_command.sub('', task)
            if optchan in self.factory.channels:
                channel = optchan.encode('utf-8')
            else:
                raise Exception("I do not follow this channel.")
        else:
            channel = self.getMasterChan(channel)
        return task, channel

    @inlineCallbacks
    def command_runlater(self, rest, channel=None, nick=None):
        """runlater <minutes> [--chan <channel>] <command [arguments]> : Schedules <command> in <minutes> for current channel or optional <channel>."""
        now = time.time()
        when, task = self._extract_digit(rest)
        task = task.decode('utf-8')
        if not task:
            returnD("Please tell me what you want me to do!")
        if when > 250000:
            returnD("Do you really want to do that in more than 6 months? Looks like something wrong to me...")
        when = max(0, when) * 60
        then = shortdate(datetime.fromtimestamp(now + when))
        try:
            task, channel = self._get_chan_from_command(task, channel)
        except Exception as e:
            returnD(str(e))
        target = self._get_target(channel, nick)
        task = cleanblanks(task)
        task = self.re_catch_command.sub(COMMAND_CHAR_DEF, task)
        task = task.encode('utf-8')
        if self.saving_task:
            self.saving_tasks += 1
        else:
            self.saving_tasks = 0
            self.saved_tasks = 0
        task_id = self.saving_tasks + 1
        while task_id != self.saved_tasks + 1:
            yield deferredSleep(0.5)
        self.saving_task = True
        rank = len(self.tasks)
        if "--nolimit" in task:
            task = self.re_nolimit.sub('', task) + " --nolimit"
        if startsWithCommandChar(task):
            command, _, rest = task.lstrip(COMMAND_CHAR_STR).partition(' ')
            func = self._find_command_function(command)
            if func is None:
                returnD(self._stop_saving_task("I can already tell you that %s%s is not a valid command." % (COMMAND_CHAR_DEF, command)))
            if not self._can_user_do(nick, channel, func):
                returnD(self._stop_saving_task("I can already tell you that you don't have the rights to use %s%s in this channel." % (COMMAND_CHAR_DEF, command)))
            if self.re_clean_twitter_task.match(task):
                count = yield self.command_count(task, channel, nick, _return_value=True)
                if type(count) != int:
                    returnD(self._stop_saving_task("I can already tell you this won't work: %s" % count))
                elif (count > 280 or count < 30) and "--nolimit" not in task:
                    returnD(self._stop_saving_task("I can already tell you this won't work, it's too %s (%s characters). Add --nolimit to override" % (("short" if count < 30 else "long"), count)))
            taskid = reactor.callLater(when, self.privmsg, nick, channel, task, tasks=rank)
        else:
            taskid = reactor.callLater(when, self._send_message, task, target)
        loggvar("Task #%s planned at %s by %s: %s" % (rank, then, nick, task), channel, "tasks")
        task_obj = {'rank': rank, 'channel': channel.lower(), 'author': nick, 'command': task, 'created': shortdate(datetime.fromtimestamp(now)), 'scheduled': then, 'scheduled_ts': now + when, 'target': target}
        yield self.db['tasks'].insert(task_obj)
        task_obj['id'] = taskid
        self.tasks.append(task_obj)
        returnD(self._stop_saving_task("Task #%s scheduled at %s : %s" % (rank, then, task)))

    re_tweetlater = re.compile(r'^\s*(\d+\s+)?(.*)$')
    def command_tweetlater(self, rest, channel=None, nick=None):
        """tweetlater <minutes> <text> [--nolimit] [--force] [img:<url>] : Alias for runlater twitter (options from "twitter" apply). Use runlater for rt and answer./TWITTER"""
        return self.command_runlater(self.re_tweetlater.sub(lambda x: (x.group(1) if x.group(1) else "") + "!twitter %s" % x.group(2), rest), channel, nick)

    def _stop_saving_task(self, text):
        self.saving_task = False
        self.saved_tasks += 1
        return text

    @inlineCallbacks
    def _refresh_tasks_from_db(self):
        now = time.time()
        tasks = yield self.db['tasks'].find({'scheduled_ts': {'$gte': now - 30}, 'channel': {'$in': self.factory.channels}}, filter=sortasc('scheduled_ts'))
        for task in filter(lambda x: "canceled" not in x, tasks):
            for x in filter(lambda y: isinstance(task[y], unicode), task):
                task[x] = task[x].encode('utf-8')
            task['rank'] = len(self.tasks)
            when = max(11, task['scheduled_ts'] + 60 - now)
            then = shortdate(datetime.fromtimestamp(now + when))
            yield self.db['tasks'].update({"_id": task['_id']}, {"$set": {"rank": task['rank']}})
            reactor.callLater(10, self._send_message, "Task #%s from %s rescheduled after restart at %s : %s" % (task['rank'], task['author'], then, task['command']), task['channel'])
            if startsWithCommandChar(task['command']):
                taskid = reactor.callLater(when, self.privmsg, task['author'], task['channel'], task['command'], tasks=task['rank'])
            else:
                taskid = reactor.callLater(when, self._send_message, task['command'], task['target'])
            task['id'] = taskid
            self.tasks.append(task)
            loggvar("Task #%s from %s re-planned at %s: %s" % (task['rank'], task['author'], then, task['command']), task['channel'], "tasks")

    def command_tasks(self, rest, channel=None, *args):
        """tasks [--chan <channel>] : Prints the list of coming tasks scheduled for current channel or optional <channel>./AUTH"""
        try:
            rest, channel = self._get_chan_from_command(rest, channel)
        except Exception as e:
           return str(e)
        now = time.time()
        res = "\n".join(["#%s [%s]: %s" % (task['rank'], task['scheduled'], task['command']) for task in self.tasks if task['channel'] == channel.lower() and task['scheduled_ts'] > now and 'canceled' not in task])
        if res == "":
            return "No task scheduled."
        return res

    @inlineCallbacks
    def command_cancel(self, rest, channel=None, *args):
        """cancel [--chan <channel>] <task_id> : Cancels the scheduled task <task_id> for current channel or optional <channel>./AUTH"""
        try:
            rest, channel = self._get_chan_from_command(rest, channel)
        except Exception as e:
           returnD(str(e))
        task_id = safeint(rest.lstrip('#'))
        try:
            task = self.tasks[task_id]
            if task['channel'] != channel.lower():
                returnD("Task #%s is not scheduled for this channel." % task_id)
            task['id'].cancel()
            yield self.db['tasks'].update({"channel": channel, "rank": task_id, "created": task["created"]}, {"$set": {"canceled": True}}, multi=True)
            self.tasks[task_id]['canceled'] = True
            returnD("#%s [%s] CANCELED: %s" % (task_id, task['scheduled'], task['command']))
        except exceptions.IndexError:
            returnD("The task #%s does not exist yet." % task_id)
        except twerror.AlreadyCancelled:
            returnD("The task #%s was already canceled." % task_id)
        except twerror.AlreadyCalled:
            returnD("The task #%s already ran." % task_id)
        except Exception as e:
            loggerr("%s %s" % (type(e), e), channel, "tasks")
            returnD("Could not retrieve any task with id #%s." % task_id)


   # Other commands...
   # -----------------
   ## Pad & Title available to anyone
   ## FuckOff/ComeBack & SetPad available only to GLOBAL_USERS and chan's USERS
   ## Exclude regexp : '(fuckoff|comeback|.*pad|title|dice)'

    def command_fuckoff(self, minutes, channel=None, nick=None):
        """fuckoff [<N>] : Tells me to shut up for the next <N> minutes (defaults to 5)./AUTH"""
        channel = self.getMasterChan(channel)
        if not minutes:
            minutes = 5
        else:
            when, _ = self._extract_digit(minutes)
            minutes = max(1, when)
        self.silent[channel.lower()] = datetime.today() + timedelta(minutes=minutes)
        return "All right, I'll be back in %s minutes or if you run %scomeback." % (minutes, COMMAND_CHAR_DEF)

    def command_comeback(self, rest, channel=None, nick=None):
        """comeback : Tells me to start talking again after use of "fuckoff"./AUTH"""
        channel = self.getMasterChan(channel).lower()
        if self.silent[channel] < datetime.today():
            return "I wasn't away but OK :)"
        self.silent[channel] = datetime.today()
        return "It's good to be back!"

    def __command_set(self, extra):
        @inlineCallbacks
        def _command_set(value, channel=None, nick=None):
            channel = self.getMasterChan(channel)
            value = value.strip()
            if value and extra.get("validation", None):
                if not re.match(extra["validation"], value, re.I):
                    returnD(extra['fail'])
            yield self.db['feeds'].update({'database': 'command_%s' % extra['command'], 'channel': channel}, {'database': 'command_%s' % extra['command'], 'channel': channel, 'query': value, 'user': nick, 'timestamp': datetime.today()}, upsert=True)
            returnD("Current %s is now set to %s" % (extra['command'], value))
        _command_set.__doc__ = """%s <value> : %s""" % (extra['command'], extra['helpset'])
        return _command_set

    def __command_get(self, extra):
        @inlineCallbacks
        def _command_get(rest, channel=None, *args):
            channel = self.getMasterChan(channel)
            res = yield self.db['feeds'].find({'database': 'command_%s' % extra['command'], 'channel': channel}, fields=['query'])
            if res and res[0]['query']:
                returnD(extra['return'] % res[0]['query'])
            returnD(extra['none'])
        _command_get.__doc__ = """%s : %s""" % (extra['command'], extra['help'])
        return _command_get

    def command_title(self, url, *args):
        """title <url> : Prints the title of the webpage at <url>."""
        d = client.getPage(url)
        d.addCallback(self._parse_pagetitle, url)
        d.addErrback(lambda _: "I cannot access the webpage at %s" % url)
        return d

    def _parse_pagetitle(self, page_contents, url):
        pagetree = lxml.html.fromstring(page_contents)
        title = u' '.join(pagetree.xpath('//title/text()')).strip()
        title = title.encode('utf-8')
        return '%s -- "%s"' % (url, title)

    def command_dice(self, rest, *args):
        """dice [<N>] : Let me toss heads or tails, or give a random number between 1 and <N> if given."""
        maxval = safeint(rest)
        if not maxval:
            return "Heads!" if random.randint(0, 1) else "Tails!"
        return random.randint(1, maxval)


   # Admin commands
   # --------------
   ## AddAuth available only to GLOBAL_USERS and  chan's USERS
   ## Restart available only to GLOBAL_USERS
   ## Exclude regexp : '(addauth|restart)'

    def command_addauth(self, rest, channel=None, nick=None):
        """addauth <user> : Gives auth rights to <user> until next reboot./AUTH"""
        channel = self.getMasterChan(channel)
        conf = chanconf(channel)
        conf["USERS"].append(rest.decode('utf-8'))
        return "%s now has auth rights for %s" % (rest, channel)

    def command_restart(self, rest, channel=None, nick=None):
        """restart : Tries to reboot me./ADMIN"""
        target = self._get_target(channel, nick)
        self._send_message("Trying to reboot…", target, nick)
        try:
            import subprocess
            reactor.callLater(1, self.quit, "admin reboot from chan by %s" % nick)
            reactor.callLater(3, subprocess.call, ["bin/gazouilleur restart --quiet"] ,shell=True)
        except Exception as e:
            return str(e)


# Auto-reconnecting Factory
class IRCBotFactory(protocol.ReconnectingClientFactory):
    protocol = IRCBot
    channels = ["#" + c.lower() for c in config.CHANNELS.keys()]
    if not hasattr(config, "SOLITARY") or str(config.SOLITARY).lower() == "false":
        channels.append("#gazouilleur")


ssl_options = ssl.optionsForClientTLS(hostname=config.HOST.decode("utf-8"))
#class ClientTLSContext(ssl.ClientContextFactory):
#    isClient = 1
#    def getContext(self):
#        return SSL.Context(SSL.TLSv1_METHOD)

# Run as 'python gazouilleur/bot.py' ...
if __name__ == '__main__':
    from setproctitle import setproctitle
    setproctitle('gazouilleur (%s)' % config.BOTNAME)

    if is_ssl(config):
        reactor.connectSSL(config.HOST, config.PORT, IRCBotFactory(), ssl_options)
        #reactor.connectSSL(config.HOST, config.PORT, IRCBotFactory(), ssl.ClientContextFactory())
    else:
        reactor.connectTCP(config.HOST, config.PORT, IRCBotFactory())
    log.startLogging(sys.stdout)
    reactor.run()
# ... or in the background when called with 'twistd -y gazouilleur/bot.py'
elif __name__ == '__builtin__':
    application = service.Application('Gazouilleur IRC Bot')
    if "-l" not in sys.argv:
        filelog = log.FileLogObserver(open(os.path.relpath('log/run.log'), 'a'))
        filelog.timeFormat = "%Y-%m-%d %H:%M:%S"
        application.setComponent(log.ILogObserver, filelog.emit)
    if is_ssl(config):
        ircService = internet.SSLClient(config.HOST, config.PORT, IRCBotFactory(), ssl_options)
        #ircService = internet.SSLClient(config.HOST, config.PORT, IRCBotFactory(), ClientTLSContext())
    else:
        ircService = internet.TCPClient(config.HOST, config.PORT, IRCBotFactory())
    ircService.setServiceParent(application)
