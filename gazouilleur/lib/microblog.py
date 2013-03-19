#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
from datetime import datetime
from twitter import *
from gazouilleur import config
from gazouilleur.lib.utils import *

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
            self.api_version = config.TWITTER_API_VERSION
            self.auth = OAuth(self.conf['OAUTH_TOKEN'], self.conf['OAUTH_SECRET'], self.conf['KEY'], self.conf['SECRET'])
        self.conn = Twitter(domain=self.domain, api_version=self.api_version, auth=self.auth)

    def _send_query(self, function, args={}, tryout=0, previous_exception=None, return_result=False):
        if tryout > 2:
            return previous_exception
        try:
            if not return_result:
                args['trim_user'] = 'true'
            args['source'] = config.BOTNAME
            socket.setdefaulttimeout(35)
            res = function(**args)
            if return_result:
                return res
            elif config.DEBUG:
                print "[%s] %s %s" % (self.site, res['text'].encode('utf-8'), args)
            return "[%s] Huge success!" % self.site
        except Exception as e:
            exception = "[%s] %s" % (self.site, sending_error(e))
            if config.DEBUG and exception != previous_exception:
                print "%s: http://%s/%s.%s %s" % (exception, self.domain, e.uri, e.format, args)
            return self._send_query(function, args, tryout+1, exception, return_result)

    def microblog(self, text="", tweet_id=None):
        if self.site == "twitter":
            text = text.replace('~', '&#126;')
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

    def get_mytweets(self, **kwargs):
        return self._send_query(self.conn.statuses.user_timeline, {'screen_name': self.user, 'count': 75, 'include_rts': 'true'}, return_result=True)

    def get_mentions(self, **kwargs):
        return self._send_query(self.conn.statuses.mentions_timeline, {'count': 200, 'include_entities': 'false'}, return_result=True)

    def get_retweets(self, retweets_processed={}, **kwargs):
        tweets = self._send_query(self.conn.statuses.retweets_of_me, {'count': 50, 'trim_user': 'true', 'include_entities': 'false', 'include_user_entities': 'false'}, return_result=True)
        done = 0
        retweets = []
        for tweet in tweets:
            if tweet['id_str'] not in retweets_processed or tweet['retweet_count'] > retweets_processed[tweet['id_str']]:
                retweets += self.get_retweets_by_id(tweet['id'])
                done += 1
            retweets_processed[tweet['id_str']] = tweet['retweet_count']
            if done >= config.TWITTER_API_LIMIT:
                break
        return retweets, retweets_processed

    def get_retweets_by_id(self, tweet_id, **kwargs):
        return self._send_query(self.conn.statuses.retweets, {'id': tweet_id, 'count': 100}, return_result=True)

    def directmsg(self, user, text):
        text = text.replace('~', '&#126;')
        return self._send_query(self.conn.direct_messages.new, {'user': user, 'text': text})

    def get_dms(self, **kwargs):
        return self._send_query(self.conn.direct_messages, return_result=True)

    def get_stats(self, db=None, **kwargs):
        timestamp = timestamp_hour(datetime.today())
        db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        last = db['stats'].find_one({'user': self.user.lower()}, sort=[('timestamp', pymongo.DESCENDING)])
        if last and timestamp == last['timestamp']:
            res = None
        elif self.api_version == 1:
            res = self._send_query(self.conn.account.totals, return_result=True)
        else:
            res = self._send_query(self.conn.users.show, {'screen_name': self.user}, return_result=True)
        return res, last, timestamp
