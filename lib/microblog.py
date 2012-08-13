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
            self.auth = OAuth(self.conf['TOKEN'], self.conf['TOKEN_SECRET'], self.conf['SECRET'], self.conf['KEY'])
        else:
            raise Exception
        self.auth_users = config.GLOBAL_USERS + conf['USERS']
        self.conn = Twitter(domain=self.domain, api_version=self.api_version, auth=self.auth)

#TODO ADD TEST USER

    def microblog(self, tweet, nolimit=False):
        ct = countchars(tweet)
        if ct < 30 and not nolimit:
            return "Do you really want to send such a short message? (%s chars) add --nolimit to override" % ct
        elif ct > 140:
            return "Too long (%s characters)" % ct
        try:
            res = self.conn.statuses.update(status=tweet)
#TODO TRY AGAIN ?
            return "Huge success on %s ! (%s characters)" % (self.protocol, ct)
        except Exception as e:
            return Exception("[%s] %s" % (self.domain, sending_error(e)))

    def retweet(self, tweet_id):
        pass

    def directmsg(self, user, tweet):
        #t.direct_messages.new(user=user, text=text)
        pass

    def answer(self, tweet_id, tweet):
        pass


#class Follower(TwitterStream):

#    def __init__(self):
#        pass
