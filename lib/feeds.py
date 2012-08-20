#!/bin/python
# -*- coding: utf-8 -*-
# adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os, sys, time, feedparser
from twisted.internet import reactor, protocol, defer, task
from twisted.python import failure
from twisted.web import error
from httpget import conditionalGetPage
try:
    import cStringIO as _StringIO
except ImportError:
    import StringIO as _StringIO
 
rss_feeds = ['http://www.icerocket.com/search?tab=twitter&q=gazouilleur&rss=1', 
          'http://www.icerocket.com/search?tab=twitter&q=regardscitoyens&rss=1',
          'http://www.icerocket.com/search?tab=twitter&q=deputes&rss=1&p=2',
          'http://www.regardscitoyens.org/feed/'
        ]
 
# This dict structure will be the following:
# { 'URL': (TIMESTAMP, value) }
cache = {}
 
class FeederProtocol():
    def __init__(self, factory):
        self.factory = factory
        self.with_errors = 0
        self.error_list = []
        
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
        print "got", url
        chan = parsed_feed.get('channel', None)
        if chan:
            print chan.get('title', '')
            #print chan.get('link', '')
            #print chan.get('tagline', '')
            #print chan.get('description', '')
        items = parsed_feed.get('items', None)
        if items:
            print len(items)
#            for item in items:
#                print '\tTitle: ', item.get('title', '')
#                print '\tDate: ', item.get('date', '')
#                print '\tLink: ', item.get('link', '')
#                print '\tDescription: ', item.get('description', '')
#                print '\tSummary: ', item.get('summary', '')
#                print "-"*20
        print "="*40
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

    def __init__(self, channel, delay=90, simul_conns=20, timeout=10):
    #    self.protocol.factory = self
        self.channel = channel
        self.delay = delay
        self.simul_conns = simul_conns
        self.timeout = timeout
        self.protocol = FeederProtocol(self)
        self.cache_dir = os.path.join('cache', channel)
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        loop = task.LoopingCall(self.start).start(self.delay)
        #self.start()
 
    def start(self):
        self.get_feeds(self. channel)
        self.nb_feeds = len(self.urls)
        # Divide into groups all the feeds to download
        if len(self.urls) > self.simul_conns:
            url_groups = [[] for x in xrange(self.simul_conns)]
            for i, url in enumerate(self.urls):
                url_groups[i % self.simul_conns].append(url)
        else:
            url_groups = [[url] for url in self.urls]
        for group in url_groups:
            self.protocol.start(group)
 
    def get_feeds(self, channel=None):
        if not channel:
            self.urls = rss_feeds
        self.urls = rss_feeds
#TODO get chan feeds from DB
        
if __name__=="__main__":
    f = FeederFactory("#rc")
    reactor.run()

