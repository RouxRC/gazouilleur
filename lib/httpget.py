#!/bin/python
# -*- coding: utf-8 -*-
# adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os.path as path
import md5
from twisted.internet import reactor, defer
from twisted.web import client
from twisted.web.client import HTTPPageGetter, HTTPClientFactory
 
class ConditionalHTTPPageGetter(HTTPPageGetter):
    
    def handleStatus_200(self):
        if self.headers.has_key('last-modified'):
            self.factory.lastModified(self.headers['last-modified'][0])
    
    def handleStatus_304(self):
        self.factory.notModified()
        self.transport.loseConnection()

#TODO change filecache to mongo 

class ConditionalHTTPClientFactory(HTTPClientFactory):
    
    protocol = ConditionalHTTPPageGetter
    noisy = False
 
    def __init__(self, cacheDir, url, method='GET', postdata=None, headers={}, agent="Gazouilleur with Twisted ConditionalPageGetter", timeout=0, cookies=None, followRedirect=1):
        self.cachefile = path.join(cacheDir, self.getHashForUrl(url))
        self.last_modified = None
        if path.exists(self.cachefile):
            with open(self.cachefile) as cache:
                self.last_modified = cache.readline().strip()
                headers['If-Modified-Since'] = self.last_modified
        HTTPClientFactory.__init__(self, url, method=method, postdata=postdata, headers=headers, agent=agent, timeout=timeout, cookies=cookies, followRedirect=followRedirect)

    def getHashForUrl(self, url):
        hash = md5.new(url)
        return hash.hexdigest()
        
    def lastModified(self, modtime):
        with open(self.cachefile, 'w') as f:
            f.write(modtime)
    
    def notModified(self):
        if self.waiting:
            self.waiting = 0
 
def conditionalGetPage(cacheDir, url, contextFactory=None, *args, **kwargs):
    scheme, host, port, _ = client._parse(url)
    factory = ConditionalHTTPClientFactory(cacheDir, url, *args, **kwargs)
    if scheme == 'https':
        from twisted.internet import ssl
        if contextFactory is None:
            contextFactory = ssl.ClientContextFactory()
        reactor.connectSSL(host, port, factory, contextFactory)
    else:
        reactor.connectTCP(host, port, factory)
    return factory.deferred

