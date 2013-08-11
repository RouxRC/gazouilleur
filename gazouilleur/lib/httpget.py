#!/usr/bin/env python
# -*- coding: utf-8 -*-
# adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os.path as path
from twisted.internet import reactor, defer
try:
    from twisted.web.client import _parse as parse_url
except:
    from urlparse import urlparse
    def parse_url(url):
        o = urlparse(url)
        port = o.port
        if not port:
            port = 443 if o.scheme.endswith("s") else 80
        return o.scheme, o.netloc, port, None
from twisted.web.client import HTTPPageGetter, HTTPClientFactory
from gazouilleur.lib.utils import get_hash
 
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
        self.cachefile = path.join(cacheDir, get_hash(url))
        self.last_modified = None
        if path.exists(self.cachefile):
            with open(self.cachefile) as cache:
                self.last_modified = cache.readline().strip()
                headers['If-Modified-Since'] = self.last_modified
        HTTPClientFactory.__init__(self, url, method=method, postdata=postdata, headers=headers, agent=agent, timeout=timeout, cookies=cookies, followRedirect=followRedirect)

    #Fix Twisted GetPage crash on google P3P CP= headers
    def gotHeaders(self, headers):
        if headers.has_key('P3P') and header['P3P'].startswith('CP='):
            del(headers['P3P'])

    def lastModified(self, modtime):
        with open(self.cachefile, 'w') as f:
            f.write(modtime)
    
    def notModified(self):
        if self.waiting:
            self.waiting = 0
 
def conditionalGetPage(cacheDir, url, contextFactory=None, *args, **kwargs):
    scheme, host, port, _ = parse_url(url)
    factory = ConditionalHTTPClientFactory(cacheDir, url, *args, **kwargs)
    if scheme == 'https':
        from twisted.internet import ssl
        if contextFactory is None:
            contextFactory = ssl.ClientContextFactory()
        reactor.connectSSL(host, port, factory, contextFactory)
    else:
        reactor.connectTCP(host, port, factory)
    return factory.deferred

