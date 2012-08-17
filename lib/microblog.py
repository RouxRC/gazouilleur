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
            args['trim_user'] = 'true'
            args['source'] = config.BOTNAME
            res = function(**args)
            if config.DEBUG:
                print res
            return "[%s] Huge success!" % self.protocol
        except Exception as e:
            exception = "[%s] %s" % (self.domain, sending_error(e))
            if config.DEBUG:
                print e
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

    def directmsg(self, user, text):
        function = getattr(self.conn.direct_messages, 'new', None)
        args = {'screen_name': user, 'text': text}
        return self._send_query(function, args)


#class Follower(TwitterStream):

#    def __init__(self):
#        pass
