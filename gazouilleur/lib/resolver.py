#!/usr/bin/env python
# -*- coding: utf-8 -*-

from twisted.internet import reactor
from twisted.web import client
from twisted.web.client import Agent, RedirectAgent
client._HTTP11ClientFactory.noisy = False

class ResolverAgent(RedirectAgent):

    def __init__(self, uri, connectTimeout=15, redirectLimit=20):
        self.lastURI = uri
        RedirectAgent.__init__(self, Agent(reactor, connectTimeout=connectTimeout), redirectLimit=redirectLimit)

    def resolve(self):
        return self.request('HEAD', self.lastURI)

    def _handleRedirect(self, response, method, uri, headers, redirectCount):
        if redirectCount >= self._redirectLimit:
            # Infinite redirection detected, keep lastURI
            return response
        locationHeaders = response.headers.getRawHeaders('location', [])
        if not locationHeaders:
            err = error.RedirectWithNoLocation(
                response.code, 'No location header field', uri)
            raise ResponseFailed([failure.Failure(err)], response)
        try:
            host = self.lastURI[:(self.lastURI+"/").index('/', 8)]
        except:
            host = "http:/"
        self.lastURI = locationHeaders[0].lstrip('/')
        if not self.lastURI.startswith('http'):
            self.lastURI = "%s/%s" % (host, self.lastURI)
        deferred = self._agent.request(method, self.lastURI, headers)
        return deferred.addCallback(self._handleResponse, method, uri, headers, redirectCount + 1)

