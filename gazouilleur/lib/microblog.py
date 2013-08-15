#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import json
from datetime import datetime
from twitter import *
from pypump import PyPump
from gazouilleur import config
from gazouilleur.lib.utils import *

class Microblog():

    def __init__(self, site, conf, bearer_token=None, get_token=False):
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
            if get_token:
                self.api_version = None
                self.format = ""
                self.auth = OAuth2(self.conf['KEY'], self.conf['SECRET'])
            else:
                self.api_version = config.TWITTER_API_VERSION
                self.format = "json"
                if bearer_token:
                    self.auth = OAuth2(bearer_token=bearer_token)
                else:
                    self.auth = OAuth(self.conf['OAUTH_TOKEN'], self.conf['OAUTH_SECRET'], self.conf['KEY'], self.conf['SECRET'])
            self.conn = Twitter(domain=self.domain, api_version=self.api_version, auth=self.auth, format=self.format)

    def get_oauth2_token(self):
        res = self.conn.oauth2.token(grant_type="client_credentials")
        obj = json.loads(res)
        if "token_type" not in obj or obj["token_type"] != "bearer" or "access_token" not in obj:
            raise Exception("Wrong token type given by twitter, weird : %s" % res)
        return obj["access_token"]

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
            exc_str = str(e).lower()
            pos = exc_str.find('status 4') + 7
            if pos != 6:
                code = int(exc_str[pos:pos+3])
                if code == 404:
                    err = "[%s] ERROR: Not Found: %s." % (self.site, code)
                elif code == 501:
                    err = "[%s] WARNING: Not responding: %s." % (self.site, code)
                else:
                    err = "[%s] WARNING: Forbidden: %s. Take a breather, check your commands, verify the config or adapt TWITTER_API_LIMIT." % (self.site, code)
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
        return self._send_query(self.conn.statuses.user_timeline, {'screen_name': self.user, 'count': 15, 'include_rts': 'true'}, return_result=True)

    def get_mentions(self, **kwargs):
        return self._send_query(self.conn.statuses.mentions_timeline, {'count': 200, 'include_entities': 'false'}, return_result=True)

    def get_retweets(self, retweets_processed={}, bearer_token=None, **kwargs):
        tweets = self._send_query(self.conn.statuses.retweets_of_me, {'count': 50, 'trim_user': 'true', 'include_entities': 'false', 'include_user_entities': 'false'}, return_result=True)
        done = 0
        retweets = []
        check_twitter_results(tweets)
        if bearer_token:
            helper = Microblog("twitter", {"TWITTER": self.conf}, bearer_token=bearer_token)
            limitfactor = 4
        else:
            helper = self
            limitfactor = 1
        for tweet in tweets:
            if tweet['id_str'] not in retweets_processed or tweet['retweet_count'] > retweets_processed[tweet['id_str']]:
                new_rts = helper.get_retweets_by_id(tweet['id'])
                if "Forbidden: " in new_rts:
                    break
                retweets += new_rts
                done += 1
            retweets_processed[tweet['id_str']] = tweet['retweet_count']
            if done >= limitfactor*config.TWITTER_API_LIMIT:
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
        check_twitter_results(res)
        return res, last, timestamp

    def search(self, query, count=50, max_id=None):
        args = {'q': query, 'count': count, 'include_entities': 'false', 'result_type': 'recent'}
        if max_id:
            args['max_id'] = max_id
        return self._send_query(self.conn.search.tweets, args, return_result=True)

def check_twitter_results(data):
    text = data
    if not isinstance(text, str):
        try:
            text = text[0]
        except:
            pass
    if text and isinstance(text, str) and ("WARNING" in text or "RROR" in text):
        raise(Exception(text))
    return data

def grab_extra_meta(source, result):
    for meta in ["in_reply_to_status_id_str", "in_reply_to_screen_name", "lang", "geo", "coordinates", "source"]:
        if meta in source:
            result[meta] = source [meta]
    for meta in ['name', 'friends_count', 'followers_count', 'statuses_count', 'listed_count']:
        key = "user_%s" % meta.replace('_count', '')
        if key in source:
            result[key] = source[key]
        elif 'user' in source and meta in source['user']:
            result[key] = source['user'][meta]
    return result
    
