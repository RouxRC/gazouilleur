#!/bin/python
# -*- coding: utf-8 -*-

import sys
from twitter import *
from utils import *
sys.path.append('..')
import config

class Sender():

    def __init__(self, site, conf):
        self.site = site.lower()
        if self.site == "identica":
            self.conf = conf['IDENTICA']
            self.domain = "identi.ca"
            self.api_version = "api"
            self.auth = UserPassAuth(self.conf['USER'], self.conf['PASS'])
        elif self.site == "twitter":
            self.conf = conf['TWITTER']
            self.domain = "api.twitter.com"
            self.api_version = "1"
            self.auth = OAuth(self.conf['OAUTH_TOKEN'], self.conf['OAUTH_SECRET'], self.conf['KEY'], self.conf['SECRET'])
        self.conn = Twitter(domain=self.domain, api_version=self.api_version, auth=self.auth)

    def _send_query(self, function, args, tryout=0, previous_exception=None, print_result=False):
        if tryout > 2: 
            return previous_exception
        try:
            if not print_result:
                args['trim_user'] = 'true'
            args['source'] = config.BOTNAME
            res = function(**args)
            if print_result:
                return res
            elif config.DEBUG:
                print "[%s] %s %s" % (self.site, res['text'].encode('utf-8'), args)
            return "[%s] Huge success!" % self.site
        except TwitterHTTPError as e:
            exception = "[%s] %s" % (self.site, sending_error(e))
            if config.DEBUG and exception != previous_exception:
                print "%s: http://%s/%s.%s %s" % (exception, self.domain, e.uri, e.format, args)
            return self._send_query(function, args, tryout+1, exception)

    def microblog(self, text="", tweet_id=None):
        function = getattr(self.conn.statuses, 'update', None)
        args = {'status': text}
        if tweet_id:
            args['in_reply_to_status_id'] = tweet_id
        return self._send_query(function, args)

    def delete(self, tweet_id):
        function = getattr(self.conn.statuses, 'destroy', None)
        args = {'id': tweet_id}
        return self._send_query(function, args)

    def retweet(self, tweet_id):
        function = getattr(self.conn.statuses, 'retweet', None)
        args = {'id': tweet_id}
        return self._send_query(function, args)

    def show_status(self, tweet_id):
        function = getattr(self.conn.statuses, 'show', None)
        args = {'id': tweet_id}
        return self._send_query(function, args, print_result=True)

    def directmsg(self, user, text):
        function = getattr(self.conn.direct_messages, 'new', None)
        args = {'user': user, 'text': text}
        return self._send_query(function, args)

