#!/bin/python
# -*- coding: utf-8 -*-
# adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os, sys, time, urllib
import feedparser, pymongo
from twisted.internet import reactor, protocol, defer, task, threads
from twisted.python import failure
from twisted.web import error
from httpget import conditionalGetPage
try:
    import cStringIO as _StringIO
except ImportError:
    import StringIO as _StringIO
from utils import getIcerocketFeedUrl
sys.path.append('..')
from config import DEBUG, MONGODB
 
# This dict structure will be the following:
# { 'URL': (TIMESTAMP, value) }
cache = {}
 
class FeederProtocol():
    def __init__(self, factory):
        self.factory = factory
        self.with_errors = 0
        self.error_list = []
        self.db = self.factory.db
        
    def _handle_error(self, traceback, extra_args):
        self.with_errors += 1
        self.error_list.append(extra_args)
        print traceback, extra_args
        print "="*20
        print "Trying to go on..."
# TODO dm admins
        
    def get_data_from_page_in_cache(self, url):
        already_got = cache.get(url, None)
        if already_got:
            elapsed_time = time.time() - already_got[0]
            if elapsed_time < self.factory.delay:
                return already_got[1]
        return None
 
    def get_page(self, nodata, url):
        return conditionalGetPage(self.factory.cache_dir, url, timeout=self.factory.timeout)

    def get_data_from_page(self, page, url):
        try:
            feed = feedparser.parse(_StringIO.StringIO(page+''))
        except TypeError:
            feed = feedparser.parse(_StringIO.StringIO(str(page)))
        cache[url] = (time.time(), feed)
        return feed
    
    def work_on_page(self, parsed_feed, url):
        chan = parsed_feed.get('channel', None)
        if chan:
            if DEBUG:
                print "Got", chan.get('title', '')
            #print chan.get('link', '')
            #print chan.get('tagline', '')
            #print chan.get('description', '')
        items = parsed_feed.get('items', None)
#        if items:
#            for item in items:
#                print '\tTitle: ', item.get('title', '')
#                print '\tDate: ', item.get('date', '')
#                print '\tLink: ', item.get('link', '')
#                print '\tDescription: ', item.get('description', '')
#                print '\tSummary: ', item.get('summary', '')
#                print "-"*20
        return parsed_feed
        
    def start(self, urls=None):
        d = defer.succeed("")
        for url in urls:
            feed = self.get_data_from_page_in_cache(url)
            if not feed:
                d.addCallback(self.get_page, url)
                d.addErrback(self._handle_error, (url, 'getting'))
                d.addCallback(self.get_data_from_page, url)
                d.addErrback(self._handle_error, (url, 'parsing'))
            else:
                d.addCallback(lambda x: feed)
            d.addCallback(self.work_on_page, url)
            d.addErrback(self._handle_error, (url, 'working on page'))
        return d 
 
class FeederFactory(protocol.ClientFactory):

    def __init__(self, channel, database="news", delay=90, simul_conns=10, timeout=20, feeds=None):
        if DEBUG:
            print "Start %s feeder for %s every %ssec by %s connections %s" % (database, channel , delay, simul_conns, feeds)
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
            url_groups = [url for url in urls]
        for group in url_groups:
            self.protocol.start(group)
        return defer.succeed(True)

    def get_feeds(self, channel=None, database="news"):
        urls = []
        feeds = self.db["feeds"].find({'database': database, 'channel': channel}, fields=['query'], sort=[('timestamp', pymongo.ASCENDING)])
        if database == "tweets":
            # create combined queries on Icerocket from search words created in db
            query = ""
            for feed in feeds:
                arg = "()OR" % urllib.quote(feed['query'], '')
                if len(query+arg) < 200:
                    query += arg
                else:
                    urls.append(getIcerocketFeedUrl(query))
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
    FeederFactory("#rc-test", "new", 20, 3, 15, rss_feeds).start()
    reactor.run()

