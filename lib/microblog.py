#!/bin/python
# -*- coding: utf-8 -*-

import sys
from twitter import *
from utils import *
sys.path.append('..')
import config

class Sender():

    def __init__(self, protocol, conf):
        self.protocol = protocol
        if protocol == "identica":
            self.conf = conf['IDENTICA']
            self.domain = "identi.ca"
            self.api_version = "api"
            self.auth = UserPassAuth(self.conf['USER'], self.conf['PASS'])
        elif protocol == "twitter":
            self.conf = conf['TWITTER']
            self.domain = "api.twitter.com"
            self.api_version = "1"
            self.auth = OAuth(self.conf['OAUTH_TOKEN'], self.conf['OAUTH_SECRET'], self.conf['KEY'], self.conf['SECRET'])
        else:
            raise Exception
        self.auth_users = config.GLOBAL_USERS + conf['USERS']
        self.conn = Twitter(domain=self.domain, api_version=self.api_version, auth=self.auth)


    def _send_query(self, function, args, tryout=0, previous_exception=None):
        if tryout > 2:
            return Exception(previous_exception)
        try:
            res = function(**args)
            if config.DEBUG:
                print res
            return "[%s] Huge success!" % self.protocol
        except Exception as e:
            exception = "[%s] %s" % (self.domain, sending_error(e))
            if config.DEBUG:
                print e
            return self._send_query(function, args, tryout+1, exception)

    def microblog(self, tweet=""):
        function = getattr(self.conn.statuses, 'update', None)
        args = {'status': tweet}
        return self._send_query(function, args)

    def retweet(self, tweet_id):
        pass

    def directmsg(self, user, tweet):
        function = getattr(self.conn.direct_messages, 'new', None)
        args = {'user': user, 'text': tweet}
        return self._send_query(function, args)

    def answer(self, tweet_id, tweet):
        pass


#class Follower(TwitterStream):

#    def __init__(self):
#        pass
