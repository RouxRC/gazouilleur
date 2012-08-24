#!/bin/python
# -*- coding: utf-8 -*-
# adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os, sys, time
from datetime import datetime, timedelta
import feedparser, pymongo, urllib2
from twisted.internet import reactor, protocol, defer, task
from twisted.python import failure
from httpget import conditionalGetPage
try:
    import cStringIO as _StringIO
except ImportError:
    import StringIO as _StringIO
from utils import *
sys.path.append('..')
from config import DEBUG, MONGODB
from microblog import Sender

re_tweet_url = re.compile(r'twitter.com/([^/]+)/statuse?s?/(\d+)$', re.I)

class FeederProtocol():
    def __init__(self, factory):
        self.fact = factory
        self.db = self.fact.db

    def _handle_error(self, traceback, msg, url):
        self.fact.ircclient._show_error(failure.Failure("%s %s : %s" % (msg, url, traceback)), self.fact.channel)

    def in_cache(self, url):
        already_got = self.fact.cache.get(url, None)
        if already_got:
            elapsed_time = time.time() - already_got
            if elapsed_time < self.fact.delay:
                return True
        return False

    def get_page(self, nodata, url):
        return conditionalGetPage(self.fact.cache_dir, url, timeout=self.fact.timeout)

    def get_data_from_page(self, page, url):
        try:
            feed = feedparser.parse(_StringIO.StringIO(page+''))
        except TypeError:
            feed = feedparser.parse(_StringIO.StringIO(str(page)))
        self.fact.cache[url] = time.time()
        return feed

    def process_elements(self, feed, url):
        if not feed.entries:
            return None
        sourcename = url
        if feed.feed and 'title' in feed.feed:
            sourcename = feed.feed['title']
        ids = []
        news = []
        for i in feed.entries:
            date = i.get('published_parsed', '')
            if date:
                date = datetime.fromtimestamp(time.mktime(i.get('published_parsed', '')))
                if datetime.today() - date > timedelta(hours=24):
                    break
            link, self.fact.cache_urls = clean_redir_urls(i.get('link', ''), self.fact.cache_urls)
            sourcename = unescape_html(sourcename)
            title = unescape_html(i.get('title', '').replace('\n', ' '))
            ids.append(link)
            news.append({'_id': "%s:%s" % (self.fact.channel, link), 'channel': self.fact.channel, 'message': title, 'link': link, 'date': date, 'timestamp': datetime.today(), 'source': url, 'sourcename': sourcename})
        existing = [n['_id'] for n in self.db['news'].find({'channel': self.fact.channel, 'link': {'$in': ids}}, fields=['_id'], sort=[('id', pymongo.DESCENDING)])]
        new = [n for n in news if n['_id'] not in existing]
        if new:
            new.reverse()
            try:
                self.db['news'].insert(new, continue_on_error=True, safe=True)
            except pymongo.errors.OperationFailure as e:
                self._handle_error(e, "recording news batch", url)
            self.fact.ircclient._send_message([(True, "[News — %s] %s — %s" % (n['sourcename'].encode('utf-8'), n['message'].encode('utf-8'), n['link'].encode('utf-8'))) for n in new], self.fact.channel)
        return None

    def process_tweets(self, feed, url):
        if not feed.entries:
            return None
        ids = []
        hashs = []
        tweets = []
        fresh = True
        for i in feed.entries:
            date = datetime.fromtimestamp(time.mktime(i.get('published_parsed', ''))-4*60*60)
            if datetime.today() - date > timedelta(hours=12):
                fresh = False
                break
            tweet, self.fact.cache_urls = clean_redir_urls(i.get('title', '').replace('\n', ' '), self.fact.cache_urls)
            link = i.get('link', '')
            res = re_tweet_url.search(link)
            if res:
                user = res.group(1)
                tid = long(res.group(2))
                ids.append(tid)
                tweets.append({'_id': "%s:%s" % (self.fact.channel, tid), 'channel': self.fact.channel, 'id': tid, 'user': user.lower(), 'screenname': user, 'message': tweet, 'uniq_rt_hash': uniq_rt_hash(tweet), 'link': link, 'date': date, 'timestamp': datetime.today(), 'source': url})
        existing = [t['_id'] for t in self.db['tweets'].find({'channel': self.fact.channel, 'id': {'$in': ids}}, fields=['_id'], sort=[('id', pymongo.DESCENDING)])]
        news = [t for t in tweets if t['_id'] not in existing]
        if news:
            news.reverse()
            if fresh and len(news) > len(feed.entries) / 2 and url[-1:] <= "3":
                reactor.callLater(10, self.start, [next_page(url)])
            text = []
            if not self.fact.displayRT:
                hashs = [t['uniq_rt_hash'] for t in news if t['uniq_rt_hash'] not in hashs]
                existing = [t['uniq_rt_hash'] for t in self.db['tweets'].find({'channel': self.fact.channel, 'uniq_rt_hash': {'$in': hashs}}, fields=['uniq_rt_hash'], sort=[('id', pymongo.DESCENDING)])]
                for t in news:
                    if t['uniq_rt_hash'] not in existing:
                        existing.append(t['uniq_rt_hash'])
                        text.append(self.displayTweet(t))
            else:
                text = [self.displayTweet(t) for t in news]
            try:
                self.db['tweets'].insert(news, continue_on_error=True, safe=True)
            except Exception as e:
                self._handle_error(e, "recording tweets batch", url)
            self.fact.ircclient._send_message(text, self.fact.channel)
        return None

    def displayTweet(self, t):
        return (True, "%s: %s — %s" % (t['screenname'].encode('utf-8'), t['message'].encode('utf-8'), t['link'].encode('utf-8')))

    def start(self, urls=None):
        d = defer.succeed('')
        for url in urls:
            if DEBUG:
                print "[%s/%s] Query %s" % (self.fact.channel, self.fact.database, url)
            if not self.in_cache(url):
                d.addCallback(self.get_page, url)
                d.addErrback(self._handle_error, "downloading", url)
                d.addCallback(self.get_data_from_page, url)
                d.addErrback(self._handle_error, "parsing", url)
                if self.fact.database == "tweets":
                    d.addCallback(self.process_tweets, url)
                else:
                    d.addCallback(self.process_elements, url)
                d.addErrback(self._handle_error, "working on", url)
        return d

    def processDMs(self, listdms, user):
        if not listdms:
            return None
        ids = []
        dms = []
        for i in listdms:
            date = datetime.fromtimestamp(time.mktime(time.strptime(i.get('created_at', ''), '%a %b %d %H:%M:%S +0000 %Y'))+2*60*60)
            if datetime.today() - date > timedelta(hours=12):
                break
            tid = long(i.get('id', ''))
            if tid:
                ids.append(tid)
                sender = i.get('sender_screen_name', '')
                dm, self.fact.cache_urls = clean_redir_urls(i.get('text', '').replace('\n', ' '), self.fact.cache_urls)
                dms.append({'_id': "%s:%s" % (self.fact.channel, tid), 'channel': self.fact.channel, 'id': tid, 'user': user.lower(), 'sender': sender.lower(), 'screenname': sender, 'message': dm, 'date': date, 'timestamp': datetime.today()})
        existing = [t['_id'] for t in self.db['dms'].find({'channel': self.fact.channel, 'id': {'$in': ids}}, fields=['_id'], sort=[('id', pymongo.DESCENDING)])]
        news = [t for t in dms if t['_id'] not in existing]
        if news:
            news.reverse()
            try:
                self.db['dms'].insert(news, continue_on_error=True, safe=True)
            except pymongo.errors.OperationFailure as e:
                self._handle_error(e, "recording DMs batch", url)
            self.fact.ircclient._send_message([(True, "[DM] @%s: %s — https://twitter.com/%s" % (n['screenname'].encode('utf-8'), n['message'].encode('utf-8'), n['screenname'].encode('utf-8'))) for n in news], self.fact.channel)
        return None

    def startdms(self, conf):
        d = defer.succeed(Sender('twitter', conf))
        if DEBUG:
            print "[%s/dms] Query @%s's dms" % (self.fact.channel, conf['TWITTER']['USER'])
        d.addCallback(Sender.get_directmsgs)
        d.addErrback(self._handle_error, "gettings DMs from", conf['TWITTER']['USER'])
        d.addCallback(self.processDMs, conf['TWITTER']['USER'])
        d.addErrback(self._handle_error, "working on DMs from", conf['TWITTER']['USER'])
        return d

class FeederFactory(protocol.ClientFactory):

    def __init__(self, ircclient, channel, database="news", delay=90, simul_conns=10, timeout=20, feeds=None, displayRT=False):
        self.ircclient = ircclient
        self.channel = channel
        self.database = database
        self.delay = delay
        self.simul_conns = simul_conns
        self.timeout = timeout
        self.feeds = feeds
        self.displayRT = displayRT
        self.db = pymongo.Connection(MONGODB['HOST'], MONGODB['PORT'])[MONGODB['DATABASE']]
        self.protocol = FeederProtocol(self)
        self.cache_dir = os.path.join('cache', channel)
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.cache = {}
        self.cache_urls = {}

    def start(self):
        if DEBUG:
            print "Start %s feeder for %s every %ssec by %s connections %s" % (self.database, self.channel, self.delay, self.simul_conns, self.feeds)
        if self.database == "dms":
            conf = chanconf(self.channel)
            self.runner = task.LoopingCall(self.protocol.startdms, conf)
        else:
            self.runner = task.LoopingCall(self.run)
        self.runner.start(self.delay + 2)

    def end(self):
        if self.runner:
            self.runner.stop()

    def run(self):
        urls = self.feeds
        if not urls:
            urls = getFeeds(self.channel, self.database, self.db)
        # Divide into groups all the feeds to download
        if len(urls) > self.simul_conns:
            url_groups = [[] for x in xrange(self.simul_conns)]
            for i, url in enumerate(urls):
                url_groups[i % self.simul_conns].append(url)
        else:
            url_groups = [[url] for url in urls]
        ct = 0
        for group in url_groups:
            if self.database == "tweets":
                ct += 1
                reactor.callLater(ct, self.protocol.start, group)
            else:
                self.protocol.start(group)
        return defer.succeed(True)

