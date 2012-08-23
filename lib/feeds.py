#!/bin/python
# -*- coding: utf-8 -*-
# adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os, sys, time
from datetime import datetime, timedelta
import feedparser, pymongo
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

re_tweet_url = re.compile(r'twitter.com/([^/]+)/statuse?s?/(\d+)$', re.I)

class FeederProtocol():
    def __init__(self, factory):
        self.fact = factory
        self.db = self.fact.db

    def _handle_error(self, traceback, extra_args):
        self.fact.ircclient._show_error(traceback, self.fact.channel)

    def in_cache(self, url):
        already_got = self.fact.cache.get(url, None)
        if already_got:
            elapsed_time = time.time() - already_got
            if elapsed_time < self.fact.delay:
                return True
        return False

    @defer.inlineCallbacks
    def get_data_from_page(self, nodata, url):
        page = yield conditionalGetPage(self.fact.cache_dir, url, timeout=self.fact.timeout)
        try:
            feed = feedparser.parse(_StringIO.StringIO(page+''))
        except TypeError:
            feed = feedparser.parse(_StringIO.StringIO(str(page)))
        self.fact.cache[url] = time.time()
        defer.returnValue(feed)

    def process_elements(self, feed, url):
        items = feed.get('items', None)
    # TODO
        elements = []
        print items
        for i in items:
            print i
        return None

    def process_tweets(self, feed, url):
        items = feed.get('items', None)
        if not items:
            return None
        ids = []
        hashs = []
        tweets = []
        fresh = True
        for i in items:
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
                rt_hash = uniq_rt_hash(tweet)
                if rt_hash not in hashs:
                    hashs.append(rt_hash)
                ids.append(tid)
                tweets.append({'_id': "%s:%s" % (self.fact.channel, tid), 'channel': self.fact.channel, 'id': tid, 'user': user.lower(), 'screenname': user, 'message': tweet, 'uniq_rt_hash': rt_hash, 'link': link, 'date': date, 'timestamp': datetime.today(), 'source': url})
        existing = [t['_id'] for t in self.db['tweets'].find({'channel': self.fact.channel, 'id': {'$in': ids}}, fields=['_id'], sort=[('id', pymongo.DESCENDING)])]
        news = [t for t in tweets if t['_id'] not in existing]
        if news:
            news.reverse()
            if fresh and len(news) > len(items) / 2 :
                reactor.callLater(10, self.start, [next_page(url)])
            text = []
            if not self.fact.displayRT:
                existing = [t['uniq_rt_hash'] for t in self.db['tweets'].find({'channel': self.fact.channel, 'uniq_rt_hash': {'$in': hashs}}, fields=['uniq_rt_hash'], sort=[('id', pymongo.DESCENDING)])]
                for t in news:
                    if t['uniq_rt_hash'] not in existing:
                        existing.append(t['uniq_rt_hash'])
                        text.append(self.displayTweet(t))
            else:
                text = [self.displayTweet(t) for t in news]
            try:
                self.db['tweets'].insert(news, continue_on_error=True, safe=True)
            except pymongo.errors.OperationFailure as e:
                self.fact.ircclient._show_error("ERROR saving batch in DB: %s" % e)
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
                d.addCallback(self.get_data_from_page, url)
                d.addErrback(self._handle_error, (url, 'parsing'))
                if self.fact.database == "tweets":
                    d.addCallback(self.process_tweets, url)
                else:
                    d.addCallback(self.process_elements, url)
                d.addErrback(self._handle_error, (url, 'working on page'))
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


rss_feeds = ['http://www.icerocket.com/search?tab=twitter&q=gazouilleur&rss=1',
          'http://www.icerocket.com/search?tab=twitter&q=regardscitoyens&rss=1',
          'http://www.icerocket.com/search?tab=twitter&q=deputes&rss=1&p=2',
          'http://www.regardscitoyens.org/feed/']

if __name__ == "__main__":
    FeederFactory(None, "#rc-test", "new", 20, 3, 15, rss_feeds).start()
    reactor.run()

