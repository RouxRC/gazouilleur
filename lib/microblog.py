#!/bin/python
# -*- coding: utf-8 -*-

import sys
from datetime import datetime
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
            if 'USER' in self.conf:
                self.user = self.conf['USER']
            self.domain = "api.twitter.com"
            self.api_version = "1"
            self.auth = OAuth(self.conf['OAUTH_TOKEN'], self.conf['OAUTH_SECRET'], self.conf['KEY'], self.conf['SECRET'])
        self.conn = Twitter(domain=self.domain, api_version=self.api_version, auth=self.auth)

    def _send_query(self, function, args={}, tryout=0, previous_exception=None, return_result=False):
        if tryout > 2:
            return previous_exception
        try:
            if not return_result:
                args['trim_user'] = 'true'
            args['source'] = config.BOTNAME
            res = function(**args)
            if return_result:
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
        args = {'status': text}
        if tweet_id:
            args['in_reply_to_status_id'] = tweet_id
        return self._send_query(self.conn.statuses.update, args)

    def delete(self, tweet_id):
        return self._send_query(self.conn.statuses.destroy, {'id': tweet_id})

    def retweet(self, tweet_id):
        return self._send_query(self.conn.statuses.retweet, {'id': tweet_id})

    def show_status(self, tweet_id):
        return self._send_query(self.conn.statuses.show, {'id': tweet_id}, return_result=True)

    def directmsg(self, user, text):
        return self._send_query(self.conn.direct_messages.new, {'user': user, 'text': text})

    def get_dms(self, **kwargs):
        return self._send_query(self.conn.direct_messages, return_result=True)

    def get_stats(self, db=None):
        timestamp = timestamp_hour(datetime.today())
        last = db['stats'].find_one({'user': self.user.lower()}, sort=[('timestamp', pymongo.DESCENDING)])
        if last and timestamp == last['timestamp']:
            res = None
        else:
            res = self._send_query(self.conn.account.totals, return_result=True)
        return res, last, timestamp
