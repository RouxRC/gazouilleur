#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib
from socket import setdefaulttimeout
from json import loads as load_json
from datetime import datetime
from twitter import Twitter, TwitterStream, OAuth, OAuth2
from pypump import PyPump
from gazouilleur import config
from gazouilleur.lib.log import *
from gazouilleur.lib.utils import *

class Microblog():

    def __init__(self, site, conf, bearer_token=None, get_token=False, streaming=False):
        self.site = site.lower()
        self.conf = conf[site.upper()]
        # Identi.ca service only supported for commands "ping" and "microblog"
        if self.site == "identica":
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
            self.user = self.conf['USER']
            self.post = 'FORBID_POST' not in conf['TWITTER'] or str(conf['TWITTER']['FORBID_POST']).lower() != "true"
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
            args = {"api_version": self.api_version, "auth": self.auth, "secure": True}
            if streaming:
                self.domain = "stream.twitter.com"
                conn = TwitterStream
                args["block"] = False
            else:
                conn = Twitter
                args['format'] = self.format
            args['domain'] = self.domain
            self.conn = conn(**args)

    def get_oauth2_token(self):
        res = self.conn.oauth2.token(grant_type="client_credentials")
        obj = load_json(res)
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
            setdefaulttimeout(35)
            res = function(**args)
            if return_result:
                return res
            elif config.DEBUG:
                loggvar("%s %s" % (res['text'].encode('utf-8'), args), action=self.site)
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
                    err = "[%s] WARNING: Forbidden: %s. Check your commands (already done? forbidden?) or take a breather and wait a bit, you may have overpassed Twitter's API 15min limits." % (self.site, code)
                return err
            exception = sending_error(e)
            if config.DEBUG and exception != previous_exception:
                loggerr("http://%s/%s/%s.%s %s : %s" % (self.domain, self.api_version, str(function), self.format, args, exception), action=self.site)
            return self._send_query(function, args, tryout+1, exception, return_result)

    def ping(self):
        setdefaulttimeout(35)
        try:
            if self.site == "identica":
                return "%s@%s" % (self.conn.Person(self.user).username, self.domain) == self.user
            creds = self.conn.account.verify_credentials(include_entities='false', skip_status='true')
            dms = not self.post or isinstance(check_twitter_results(self.get_dms()), list)
            if config.DEBUG and not (creds and dms):
                raise Exception("%s\n%s" % (creds, dms))
            return creds is not None and dms
        except Exception as e:
            if config.DEBUG:
                loggerr("Ping failed: %s" % e, action=self.site)
            return False

    def microblog(self, text="", tweet_id=None, channel=None):
        if text.startswith("%scount" % config.COMMAND_CHARACTER):
            text = text.replace("%scount" % config.COMMAND_CHARACTER, "").strip()
        if self.site == "identica":
            try:
                note = self.conn.Note(text)
                note.to = (self.conn.Public, self.conn.Followers, self.conn.Following)
                note.send()
                return "[identica] Huge success!"
            except Exception as e:
                if "[Errno 111] Connection refused" in str(e):
                    err_msg = "https://identi.ca seems down"
                else:
                    err_msg = sending_error(e)
                exception = "[identica] %s" % err_msg
                if config.DEBUG:
                    loggerr("%s %s" % (exception, e), action=self.site)
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
        return self._send_query(self.conn.statuses.user_timeline, {'screen_name': self.user, 'count': 15, 'include_rts': 1}, return_result=True)

    def get_mentions(self, **kwargs):
        return self._send_query(self.conn.statuses.mentions_timeline, {'count': 200, 'include_entities': 'false', 'include_rts': 1}, return_result=True)

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

    def search(self, query, count=15, max_id=None):
        args = {'q': query, 'count': count, 'include_entities': 'false', 'result_type': 'recent'}
        if max_id:
            args['max_id'] = max_id
        return self._send_query(self.conn.search.tweets, args, return_result=True)

    def search_stream(self, follow=[], track=[]):
        if not "stream" in self.domain or not len(follow) + len(track):
            return None
        args = {'filter_level': 'none', 'stall_warnings': 'true'}
        if track:
            args['track'] = ",".join(track)
        if follow:
            args['follow']= ",".join(follow)
        if config.DEBUG:
            loggvar(args, action="stream")
        return self.conn.statuses.filter(**args)

    def search_users(self, query, count=3):
        query = urllib.quote(cleanblanks(query).strip('@').lower().replace(' ', '+'), '')
        users = self._send_query(self.conn.users.search, {'q': query, 'count': count, 'include_entities': 'false'}, return_result=True)
        if "Forbidden" in users or "404" in users:
            return []
        return [u['screen_name'] for u in users]

    def lookup_users(self, list_users, cache_users={}):
        good = {}
        todo = []
        for name in list_users:
            name = name.lower().lstrip('@')
            if name in cache_users:
                good[name] = cache_users[name]
            else:
                todo.append(name)
        users = self._send_query(self.conn.users.lookup, {'screen_name': ','.join(todo), 'include_entities': 'false'}, return_result=True)
        if "Forbidden" in users or "404" in users:
            return good, cache_users
        list_users = [l.decode('utf-8') for l in list_users]
        for u in users:
            name = u['screen_name'].decode('utf-8').lower()
            if name in list_users:
                good[name] = u['id_str']
        cache_users.update(good)
        return good, cache_users

    re_twitter_account = re.compile('(^|\W)@([A-Za-z0-9_]{1,15})')
    def test_microblog_users(self, text, cache_users={}):
        match = self.re_twitter_account.findall(text)
        if not len(match):
            return True, cache_users, "No user quoted"
        check = []
        for _, m in match:
            user = m.lower().lstrip('@')
            if user not in cache_users:
                check.append(user)
        good, cache_users = self.lookup_users(check, cache_users)
        for user in check:
            if user not in good.keys():
                extra = ""
                proposals = self.search_users(user)
                if proposals:
                    extra = " (maybe you meant @%s ?)" % " or @".join([p.encode('utf-8') for p in proposals])
                return False, cache_users, "Sorry but @%s doesn't seem like a real account%s. Please correct your tweet of force by adding --force" % (user, extra)
        return True, cache_users, "All users quoted passed"

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

