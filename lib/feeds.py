#!/bin/python
# -*- coding: utf-8 -*-
# adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os, sys, time, urllib
from datetime import datetime, timedelta
import feedparser, pymongo
from twisted.internet import reactor, protocol, defer, task, threads
from twisted.python import failure
from twisted.web import error
from httpget import conditionalGetPage
try:
    import cStringIO as _StringIO
except ImportError:
    import StringIO as _StringIO
from utils import getIcerocketFeedUrl, next_page, re_tweet_url
sys.path.append('..')
from config import DEBUG, MONGODB

class FeederProtocol():
    def __init__(self, factory):
        self.fact = factory
        self.with_errors = 0
        self.error_list = []
        self.db = self.fact.db
        
    def _handle_error(self, traceback, extra_args):
        self.with_errors += 1
        self.error_list.append(extra_args)
        print traceback, extra_args
        print "="*20
        print "Trying to go on..."
# TODO dm admins
 
    def in_cache(self, url):
        already_got = self.fact.cache.get(url, None)
        if already_got:
            elapsed_time = time.time() - already_got[0]
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
        self.fact.cache[url] = (time.time(), feed)
        return feed
    
    def process_elements(self, feed, url):
        items = feed.get('items', None)
        for i in items:
            print i
        return None

    def process_tweets(self, feed, url):
        items = feed.get('items', None)
        if not items:
            return None
        ids = []
        tweets = {}
        fresh = True
        for i in items:
            date = datetime.fromtimestamp(time.mktime(i.get('published_parsed', ''))-3*60*60)
            if datetime.today() - date > timedelta(hours=24):
                fresh = False
                break
            tweet = i.get('title', '').replace('\n', ' ')
            link = i.get('link', '')
            res = re_tweet_url.search(link)
            if res:
                user = res.group(1)
                tid = long(res.group(2))
                ids.append(tid)
                #TODO ADD hash for RTs
                tweets[tid] = {'channel': self.fact.channel, '_id': tid, 'user': user.lower(), 'screenname': user, 'message': tweet, 'link': link, 'date': date, 'timestamp': datetime.today()}
        last = self.db['tweets'].find_one({'channel': self.fact.channel, '_id': {'$in': ids}}, fields=['_id'], sort=[('_id', pymongo.DESCENDING)])
        ids.reverse()
        news = []
        if last:
            news = [tweets[tid] for tid in ids if tid > last['_id']]
        elif tweets:
            if fresh:
                reactor.callLater(10, self.start, [next_page(url)])
            news = [tweets[tid] for tid in ids]
        if news:
            self.db['tweets'].insert(news)
            text = [(True, "%s: %s — %s" % (t['screenname'].encode('utf-8'), t['message'].encode('utf-8'), t['link'].encode('utf-8'))) for t in news]
            self.fact.ircclient._send_message(text, self.fact.channel)
        return None
        
    def start(self, urls=None):
        d = defer.succeed('')
        for url in urls:
            if not self.in_cache(url):
                d.addCallback(self.get_page, url)
                d.addErrback(self._handle_error, (url, 'getting'))
                d.addCallback(self.get_data_from_page, url)
                d.addErrback(self._handle_error, (url, 'parsing'))
                if self.fact.database == "tweets":
                    d.addCallback(self.process_tweets, url)
                else:
                    d.addCallback(self.process_elements, url)
                d.addErrback(self._handle_error, (url, 'working on page'))
        return d 
 
class FeederFactory(protocol.ClientFactory):

    def __init__(self, ircclient, channel, database="news", delay=90, simul_conns=10, timeout=20, feeds=None):
        if DEBUG:
            print "Start %s feeder for %s every %ssec by %s connections %s" % (database, channel , delay, simul_conns, feeds)
        self.ircclient = ircclient
        self.channel = channel
        self.database = database
        self.delay = delay
        self.simul_conns = simul_conns
        self.timeout = timeout
        self.feeds = feeds
        self.db = pymongo.Connection(MONGODB['HOST'], MONGODB['PORT'])[MONGODB['DATABASE']]
        self.protocol = FeederProtocol(self)
        self.cache_dir = os.path.join('cache', channel)
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.cache = {}

    def start(self):
        self.runner = task.LoopingCall(self.run)
        self.runner.start(self.delay + 2)

    def end(self):
        if self.runner:
            self.runner.stop()
 
    def run(self):
        urls = self.feeds
        if not urls:
            urls = self.get_feeds(self.channel, self.database)
        if DEBUG and len(urls):
            print "Query %s" % urls
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

    def get_feeds(self, channel=None, database="news"):
        urls = []
        feeds = self.db["feeds"].find({'database': database, 'channel': channel}, fields=['query'], sort=[('timestamp', pymongo.ASCENDING)])
        if database == "tweets":
            # create combined queries on Icerocket from search words retrieved in db
            query = ""
            for feed in feeds:
                arg = feed['query'].replace('@', 'from:')
                arg = "()OR" % urllib.quote(arg, '')
                if len(query+arg) < 200:
                    query += arg
                else:
                    urls.append(getIcerocketFeedUrl(query[:-2]))
                    query = ""
            if query != "":
                urls.append(getIcerocketFeedUrl(query))
        elif database == "news":
            urls = [feed['query'] for feed in feeds]
        return urls


rss_feeds = ['http://www.icerocket.com/search?tab=twitter&q=gazouilleur&rss=1', 
          'http://www.icerocket.com/search?tab=twitter&q=regardscitoyens&rss=1',
          'http://www.icerocket.com/search?tab=twitter&q=deputes&rss=1&p=2',
          'http://www.regardscitoyens.org/feed/']

if __name__ == "__main__":
    FeederFactory(None, "#rc-test", "new", 20, 3, 15, rss_feeds).start()
    reactor.run()

