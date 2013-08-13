#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
from datetime import datetime
from twitter import *
from pypump import PyPump
from gazouilleur import config
from gazouilleur.lib.utils import *

class Microblog():

    def __init__(self, site, conf):
        self.site = site.lower()
        # Identi.ca service only supported for commands "ping" and "microblog"
        if self.site == "identica":
            self.conf = conf['IDENTICA']
            self.domain = "identi.ca"
            self.api_version = "api"
            # Old Status.net Identi.ca connection:
            #self.auth = UserPassAuth(self.conf['USER'], self.conf['PASS'])
            #self.conn = Twitter(domain=self.domain, api_version=self.api_version, auth=self.auth)
            # New Pump.io Identi.ca connection:
            self.user = "%s@%s" % (self.conf['USER'].lower(), self.domain)
            from gazouilleur.identica_auth_config import identica_auth
            self.conf.update(identica_auth[self.conf['USER'].lower()])
            self.conn = PyPump(self.user, key=self.conf['key'], secret=self.conf['secret'], token=self.conf['token'], token_secret=self.conf['token_secret'])
        elif self.site == "twitter":
            self.conf = conf['TWITTER']
            if 'USER' in self.conf:
                self.user = self.conf['USER']
            self.domain = "api.twitter.com"
            self.api_version = config.TWITTER_API_VERSION
            self.auth = OAuth(self.conf['OAUTH_TOKEN'], self.conf['OAUTH_SECRET'], self.conf['KEY'], self.conf['SECRET'])
            self.conn = Twitter(domain=self.domain, api_version=self.api_version, auth=self.auth)

    def _send_query(self, function, args={}, tryout=0, previous_exception=None, return_result=False, channel=None):
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
            if self.site == 'twitter' and channel and 'id_str' in res:
                save_lasttweet_id(channel, res['id_str'])
            return "[%s] Huge success!" % self.site
        except Exception as e:
            exc_str = str(e)
            pos = exc_str.find('status 40')+7
            if pos != 6:
                code = int(exc_str[pos:pos+3])
                if code == 404:
                    err = "[%s] ERROR: Not Found: %s." % (self.site, code)
                elif code == 501:
                    err = "[%s] WARNING: Not responding: %s." % (self.site, code)
                else:
                    err = "[%s] WARNING: Forbidden: %s. Take a breather, check your commands, verify the config or adapt TWITTER_API_LIMIT." % (self.site, code)
                if config.DEBUG:
                    print err
                return err
            exception = "[%s] %s" % (self.site, sending_error(e))
            if config.DEBUG and exception != previous_exception:
                try:
                    print "%s: http://%s/%s.%s %s" % (exception, self.domain, e.uri, e.format, args)
                except:
                    print exception, e, args
            return self._send_query(function, args, tryout+1, exception, return_result)

    def ping(self):
        socket.setdefaulttimeout(35)
        try:
            if self.site == "identica":
                return str(self.conn.Person(self.user)) == self.user
            return self.conn.account.verify_credentials(include_entities='false', skip_status='true') is not None and check_twitter_results(self.get_dms())
        except Exception as e:
            return False

    def microblog(self, text="", tweet_id=None, channel=None):
        if self.site == "identica":
            try:
                note = self.conn.Note(text)
                note.to = (self.conn.Public, self.conn.Followers, self.conn.Following)
                note.send()
                return "[identica] Huge success!"
            except Exception as e:
                exception = "[identica] %s" % sending_error(e)
                if config.DEBUG:
                    print exception, e
                return exception 
        text = text.replace('~', '&#126;')
        args = {'status': text}
        if tweet_id:
            args['in_reply_to_status_id'] = tweet_id
        return self._send_query(self.conn.statuses.update, args, channel=channel)

    def delete(self, tweet_id):
        return self._send_query(self.conn.statuses.destroy, {'id': tweet_id})

    def retweet(self, tweet_id, channel=None):
        return self._send_query(self.conn.statuses.retweet, {'id': tweet_id}, channel=channel)

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
        check_twitter_results(tweets)
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

def check_twitter_results(data):
    text = data
    if not isinstance(text, str):
        try:
            text = text[0]
        except:
            pass
    if text and isinstance(text, str) and ("WARNING" in text or "ERROR" in text):
        raise(Exception(text))
    return data

