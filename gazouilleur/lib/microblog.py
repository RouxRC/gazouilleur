#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from urllib import quote as urlquote
from socket import setdefaulttimeout
from json import loads as load_json
from datetime import datetime
from twisted.internet.defer import inlineCallbacks, returnValue
from twitter import Twitter, TwitterStream, TwitterHTTPError, OAuth, OAuth2
from twitter.api import TwitterListResponse
from pypump import PyPump, Client
from gazouilleur import config
from gazouilleur.lib.mongo import sortdesc, save_lasttweet_id, find_stats, db_foll_coll
from gazouilleur.lib.log import *
from gazouilleur.lib.utils import *

class Microblog(object):

    twitter_api_limit = 15
    twitter_api_version = "1.1"

    def __init__(self, site, conf, bearer_token=None, get_token=False, streaming=False, upload=False):
        self.site = site.lower()
        self.conf = conf[site.upper()]
        # Identi.ca service only supported for commands "ping" and "microblog"
        if self.site == "identica":
            self.domain = "identi.ca"
            # New Pump.io Identi.ca connection:
            self.user = "%s@%s" % (self.conf['USER'].lower(), self.domain)
            from gazouilleur.identica_auth_config import identica_auth
            self.conf.update(identica_auth[self.conf['USER'].lower()])
            iclient = Client(webfinger=self.user, type="native", name="Gazouilleur", key=self.conf['key'], secret=self.conf['secret'])
            self.conn = PyPump(client=iclient, token=self.conf['token'], secret=self.conf['token_secret'], verifier_callback=lambda: "")
        elif self.site == "twitter":
            self.domain = "api.twitter.com"
            self.user = self.conf['USER']
            self.post = 'FORBID_POST' not in conf['TWITTER'] or str(conf['TWITTER']['FORBID_POST']).lower() != "true"
            args = {"api_version": self.twitter_api_version, "secure": True}
            format = "json"
            if get_token:
                format = ""
                args["api_version"] = None
                args["auth"] = OAuth2(self.conf['KEY'], self.conf['SECRET'])
            elif bearer_token:
                args["auth"] = OAuth2(bearer_token=bearer_token)
            else:
                args["auth"] = OAuth(self.conf['OAUTH_TOKEN'], self.conf['OAUTH_SECRET'], self.conf['KEY'], self.conf['SECRET'])
            if streaming:
                self.domain = "stream.twitter.com"
                args['block'] = False
                args['timeout'] = 10
                conn = TwitterStream
            else:
                if upload:
                    self.domain = "upload.twitter.com"
                args['format'] = format
                conn = Twitter
            args['domain'] = self.domain
            self.conn = conn(**args)

    def get_oauth2_token(self):
        res = self.conn.oauth2.token(grant_type="client_credentials")
        obj = load_json(res)
        if "token_type" not in obj or obj["token_type"] != "bearer" or "access_token" not in obj:
            raise Exception("Wrong token type given by twitter, weird : %s" % res)
        return obj["access_token"]

    def _send_query(self, function, args={}, tryout=0, previous_exception=None, return_result=False, extended_tweets=False, channel=None):
        if tryout > 2:
            return previous_exception.encode('utf-8')
        try:
            if not return_result:
                args['trim_user'] = 'true'
            if extended_tweets:
                args['tweet_mode'] = 'extended'
            args['source'] = config.BOTNAME
            setdefaulttimeout(15)
            res = function(**args)
            if return_result:
                if extended_tweets:
                    res = reformat_extended_tweets(res)
                return res
            if config.DEBUG and not 'media[]' in args:
                loggvar("%s %s" % (res['text'].encode('utf-8'), args), action=self.site)
            if self.site == 'twitter' and channel and 'id_str' in res:
                save_lasttweet_id(channel, res['id_str'])
            imgstr = ""
            if "media_ids" in args:
                nimg = args["media_ids"].count(",")
                imgstr = " sending tweet with %s attached" % ("%s images" % (nimg+1) if nimg else "image")
            return "[%s] Huge success%s!" % (self.site, imgstr)
        except Exception as e:
            code, exception = get_error_message(e)
            if code in [None, 32, 183, 187, 400, 403, 404, 429, 500, 503]:
                return "[%s] %s" % (self.site, exception.encode('utf-8'))
            if config.DEBUG and exception != previous_exception:
                loggerr("http://%s/%s.%s %s : %s" % (self.domain, "/".join(function.uriparts), function.format, args, exception), action=self.site)
            return self._send_query(function, args, tryout+1, exception, return_result, extended_tweets, channel)

    def ping(self):
        setdefaulttimeout(35)
        try:
            if self.site == "identica":
                return "%s@%s" % (self.conn.Person(self.user).username, self.domain) == self.user
            creds = self.conn.account.verify_credentials(include_entities='false', skip_status='true')
            dms = True
            if self.post:
                trydms = self.get_dms()
                dms = isinstance(trydms, list) or (isinstance(trydms, str) and "ERROR 429" in trydms)
            if config.DEBUG and not (creds and dms):
                raise Exception("%s\n%s" % (creds, dms))
            return creds is not None and dms
        except Exception as e:
            if config.DEBUG:
                loggerr("Ping failed: %s" % e, action=self.site)
            return False

    def get_twitter_rates(self):
        return self._send_query(self.conn.application.rate_limit_status, return_result=True)

    def get_twitter_conf(self):
        res = self._send_query(self.conn.help.configuration, return_result=True)
        return res.get('short_url_length_https', res.get('short_url_length', 22) + 1), res.get('photo_size_limit', 3145728)

    def send_media(self, imgdata):
        return self._send_query(self.conn.media.upload, {"media": imgdata}, return_result=True)

    def microblog(self, text="", tweet_id=None, imgs=None, quote_tweet=None, channel=None, length=0):
        if text.startswith("%scount" % COMMAND_CHAR_REG):
            text = text.replace("%scount" % COMMAND_CHAR_REG, "").strip()
        if self.site == "identica":
            try:
                note = self.conn.Note(text)
                note.to = (self.conn.Public, self.conn.me.followers, self.conn.me.following)
                setdefaulttimeout(15)
                note.send()
                return "[identica] Huge success!"
            except Exception as e:
                err_msg = re_clean_identica_error.sub('', str(e))
                if "[Errno 111] Connection refused" in err_msg or "ECONNREFUSED" in err_msg:
                    err_msg = "https://identi.ca seems down"
                exception = "[identica] %s" % err_msg
                if config.DEBUG:
                    loggerr(e, action=self.site)
                return exception
        args = {'status': text.replace('\\n', '\n')}
        if tweet_id:
            args['in_reply_to_status_id'] = str(tweet_id)
            args['auto_populate_reply_metadata'] = 'true'
        if quote_tweet:
            args['attachment_url'] = quote_tweet
        if imgs:
            args['media_ids'] = ",".join(imgs)
        return self._send_query(self.conn.statuses.update, args, channel=channel)

    def delete(self, tweet_id):
        return self._send_query(self.conn.statuses.destroy, {'id': tweet_id})

    def retweet(self, tweet_id, channel=None):
        return self._send_query(self.conn.statuses.retweet, {'id': tweet_id}, channel=channel)

    def like(self, tweet_id, channel=None):
        return self._send_query(self.conn.favorites.create, {'_id': tweet_id, 'include_entities': False}, channel=channel)

    def show_status(self, tweet_id):
        return self._send_query(self.conn.statuses.show, {'id': tweet_id}, return_result=True, extended_tweets=True)

    def get_mytweets(self, **kwargs):
        return self._send_query(self.conn.statuses.user_timeline, {'screen_name': self.user, 'count': 15, 'include_rts': 1}, return_result=True, extended_tweets=True)

    def get_mentions(self, **kwargs):
        return self._send_query(self.conn.statuses.mentions_timeline, {'count': 200, 'include_rts': 1}, return_result=True, extended_tweets=True)

    def get_retweets(self, retweets_processed={}, bearer_token=None, **kwargs):
        tweets = self._send_query(self.conn.statuses.retweets_of_me, {'count': 50, 'trim_user': 'true', 'include_user_entities': 'false'}, return_result=True)
        done = 0
        retweets = []
        check_twitter_results(tweets)
        if type(tweets) is str:
            return retweets, retweets_processed
        if bearer_token:
            helper = Microblog("twitter", {"TWITTER": self.conf}, bearer_token=bearer_token)
            limitfactor = 4
        else:
            helper = self
            limitfactor = 1
        for tweet in tweets:
            if tweet['id_str'] not in retweets_processed or tweet['retweet_count'] > retweets_processed[tweet['id_str']]:
                new_rts = helper.get_retweets_by_id(tweet['id'])
                if "ERROR 429" in new_rts:
                    break
                retweets += new_rts
                done += 1
            retweets_processed[tweet['id_str']] = tweet['retweet_count']
            if done >= limitfactor*int(self.twitter_api_limit/3):
                break
        return retweets, retweets_processed

    def get_retweets_by_id(self, tweet_id, **kwargs):
        return self._send_query(self.conn.statuses.retweets, {'id': tweet_id, 'count': 100}, return_result=True, extended_tweets=True)

    def directmsg(self, user, text, length=0):
        return self._send_query(self.conn.direct_messages.new, {'user': user, 'text': text})

    def get_dms(self, **kwargs):
        return self._send_query(self.conn.direct_messages, {'full_text': True}, return_result=True)

    @inlineCallbacks
    def get_stats(self, **kwargs):
        timestamp = timestamp_hour(datetime.today())
        try:
            last = yield find_stats({'user': self.user.lower()}, limit=1, filter=sortdesc('timestamp'))
            last = last[0]
        except:
            last = {}
        if last and last['timestamp'] == timestamp:
            res = None
        else:
            res = self._send_query(self.conn.users.show, {'screen_name': self.user}, return_result=True)
        check_twitter_results(res)
        returnValue((res, last, timestamp))

    def search(self, query, count=15, max_id=None):
        args = {'q': query, 'count': count, 'result_type': 'recent'}
        if max_id:
            args['max_id'] = max_id
        return self._send_query(self.conn.search.tweets, args, return_result=True, extended_tweets=True)

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
        query = urlquote(cleanblanks(query).strip('@').lower().replace(' ', '+'), '')
        users = self._send_query(self.conn.users.search, {'q': query, 'count': count, 'include_entities': 'false'}, return_result=True)
        if isinstance(users, str):
            return []
        return [u['screen_name'] for u in users]

    def lookup_users(self, list_users, cache_users={}, return_first_result=False):
        good = {}
        todo = []
        for name in list_users:
            name = name.lower().lstrip('@')
            if name in cache_users:
                good[name] = cache_users[name]
            else:
                todo.append(name)
        if not todo:
            return good, cache_users
        users = self._send_query(self.conn.users.lookup, {'screen_name': ','.join(todo), 'include_entities': 'false'}, return_result=True)
        if "ERROR 429" in users or "ERROR 404" in users or not isinstance(users, list):
            return good, cache_users
        list_users = [l.decode('utf-8') for l in list_users]
        for u in users:
            if return_first_result:
                return u, cache_users
            name = u['screen_name'].decode('utf-8').lower()
            if name in list_users:
                good[name] = u['id_str']
        cache_users.update(good)
        return good, cache_users

    re_twitter_account = re.compile('(^|\W)@([A-Za-z0-9_]{1,15})')
    re_bad_account = re.compile('(^|\W)(@[A-Za-z0-9_]{1,14}[%s]+[A-Za-z0-9_]*)([^A-Za-z0-9_]|$)' % ACCENTS)
    def test_microblog_users(self, text, cache_users={}):
        force = ". Please correct your tweet of force by adding --force"
        match = self.re_bad_account.search(text)
        if match:
            return False, cache_users, "Sorry but %s does not seem like a valid account%s" % (match.group(2), force)
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
                return False, cache_users, "Sorry but @%s doesn't seem like a real account%s%s" % (user, extra, force)
        return True, cache_users, "All users quoted passed"

    def follow(self, user, **kwargs):
        return self._send_query(self.conn.friendships.create, {'screen_name': user, 'follow': 'true'}, return_result=True)

    def unfollow(self, user, **kwargs):
        return self._send_query(self.conn.friendships.destroy, {'screen_name': user}, return_result=True)

    @inlineCallbacks
    def update_followers(self, db):
      # Get followers list from Twitter
        curfolls = set()
        cursor = -1
        while cursor:
            res = self._send_query(self.conn.followers.ids, {'screen_name': self.user, "cursor": cursor, "count": 5000}, return_result=True)
            if "ERROR 429" in res or "ERROR 404" in res or not isinstance(res, dict):
                loggerr(res)
                returnValue([])
            cursor = res.get("next_cursor", res.get("next_cursor_str", 0))
            curfolls |= set([str(i) for i in res["ids"]])
      # Get known info on followers from DB
        foll_coll = db_foll_coll(self.user)
        oldfolls = yield db[foll_coll].find({"follows_me": True}, fields=[])
        oldfolls = set([f["_id"] for f in oldfolls])
        oldlost = yield db[foll_coll].find({"follows_me": False}, fields=[])
        oldlost = set([f["_id"] for f in oldlost])
        oldtodo = yield db[foll_coll].find({"screen_name": None}, fields=[])
        oldtodo = [f["_id"] for f in oldtodo]
      # Save new found followers
        newids = curfolls - oldfolls
        oldusers = newids & oldlost
        if oldusers:
            yield db[foll_coll].update({"_id": {"$in": list(oldusers)}}, {"$set": {"follows_me": True, "last_update": time.time()}}, multi=True)
        newusers = [{"_id": str(u), "follows_me": True, "last_update": time.time() if len(oldfolls) else 0} for u in list(newids - oldusers)]
        if newusers:
            yield db[foll_coll].insert(newusers)
      # Update old followers lost
        lostids = list(oldfolls - curfolls)
        todolostids = []
        if lostids:
            # only keep for display lost ones with old activity to avoid repeated unfollow weird accounts
            todolostids = yield db[foll_coll].find({"_id": {"$in": lostids}, "last_update": {"$lte": time.time()-604800}}, fields=[])
            todolostids = [f["_id"] for f in todolostids]
            yield db[foll_coll].update({"_id": {"$in": lostids}}, {"$set": {"follows_me": False, "last_update": time.time()}}, multi=True)
      # Collect metas on missing profiles
        todo = todolostids + list(newids) + oldtodo
        lost = []
        for chunk in chunkize(todo, 100):
            users = self._send_query(self.conn.users.lookup, {'user_id': ','.join([str(c) for c in chunk]), 'include_entities': 'false'}, return_result=True)
            if "ERROR 429" in users or "ERROR 404" in users or not isinstance(users, list):
                break
            for user in users:
                if str(user["id"]) in lostids:
                    lost.append(user)
                for f in ["status", "entities"]:
                    if f in user:
                        del(user[f])
                yield db[foll_coll].update({"_id": str(user["id"])}, {"$set": user})
        returnValue(lost)

def check_twitter_results(data):
    text = data
    if not isinstance(text, str):
        try:
            text = text[0]
        except:
            pass
    if text and isinstance(text, str) and ("WARNING" in text or text.startswith("[twitter] ERROR ")):
        raise(Exception(text))
    return data

def reformat_extended_tweets(tweet):
    if type(tweet) in [list, TwitterListResponse]:
        return [reformat_extended_tweets(t) for t in tweet]
    elif "statuses" in tweet:
        tweet["statuses"] = [reformat_extended_tweets(t) for t in tweet["statuses"]]
        return tweet

    if "extended_tweet" in tweet:
        for field in tweet["extended_tweet"]:
            tweet[field] = tweet["extended_tweet"][field]
    tweet['text'] = tweet.get('full_text', tweet.get('text', ''))

    if 'entities' in tweet or 'extended_entities' in tweet:
        for entity in tweet.get('extended_entities', tweet['entities']).get('media', []) + tweet.get('entities', {}).get('urls', []):
            if 'expanded_url' in entity and 'url' in entity and entity['expanded_url']:
                try:
                    cleanurl, _ = clean_url(entity['expanded_url'])
                    tweet["text"] = tweet["text"].replace(entity['url'], cleanurl)
                except Exception as e:
                    loggerr(e)

    tweet["url"] = "https://twitter.com/%s/status/%s" % (tweet['user']['screen_name'], tweet['id_str'])

    if 'retweeted_status' in tweet:
        tweet['retweeted_status'] = reformat_extended_tweets(tweet['retweeted_status'])
        if tweet['retweeted_status']['id_str'] != tweet['id_str']:
            tweet['text'] = "RT @%s: %s" % (tweet['retweeted_status']['user']['screen_name'], tweet['retweeted_status']['text'])

    if "quoted_status" in tweet and tweet["quoted_status"]['id_str'] != tweet['id_str']:
        tweet["quoted_status"] = reformat_extended_tweets(tweet["quoted_status"])
        tweet['text'] = tweet['text'].replace(tweet["quoted_status"]["url"].lower(), u"« @%s: %s »" % (tweet["quoted_status"]["user"]["screen_name"], tweet["quoted_status"]["text"]))

    return tweet

def grab_extra_meta(source, result):
    for meta in ["in_reply_to_status_id_str", "in_reply_to_screen_name", "lang", "geo", "coordinates", "source"]:
        if meta in source:
            result[meta] = source[meta]
    for meta in ['name', 'friends_count', 'followers_count', 'statuses_count', 'listed_count']:
        key = "user_%s" % meta.replace('_count', '')
        if key in source:
            result[key] = source[key]
        elif 'user' in source and meta in source['user']:
            result[key] = source['user'][meta]
    return result

re_clean_identica_error = re.compile(r" \(POST {.*$")

re_twitter_error = re.compile(r' status (\d+) for', re.I)
def get_error_message(e):
    error = str(e).lower()
    if "[errno 32] broken pipe" in error:
        return format_error_message(32)
    if "[errno 111] connection refused" in error or " operation timed out" in error or "reset by peer" in error:
        return format_error_message(111)
    res = re_twitter_error.search(error)
    code = int(res.group(1)) if res else 0
    if code != 500 and str(code).startswith('5') and '"code":' not in error:
        return format_error_message(503)
    message = ""
    if type(e) == TwitterHTTPError and e.response_data:
        if "errors" not in e.response_data:
            return format_error_message(None, str(e.response_data))
        err = e.response_data["errors"][0]
        if err["code"] in [183, 187]:
            code = err["code"]
        elif code == 403 and "statuses/retweet" in error:
            code = 187
        message = err["message"][0].upper() + err["message"][1:] if err["message"] else ""
    elif config.DEBUG:
        loggerr("%s: %s" % (code, error))
    if code == 404 and "direct_messages/new" in error or "friendships" in error:
        code = 403
        message = "No twitter account found with this name"
    return format_error_message(code, message)

twitter_error_codes = {
    32: "Broken pipe",
    111: "Network difficulties, connection refused or timed-out",
    187: "Already done",
    404: "Cannot find that tweet",
    429: "Rate limit exhausted, should be good within the next 15 minutes",
    500: "Twitter internal error",
    503: "Twitter is unavailable at the moment"
}
def format_error_message(code, error=""):
    codestr = " %s" % code if code else ""
    if code in twitter_error_codes:
        error = twitter_error_codes[code]
    if code == 400 and "media ids" in error:
        error += " Maybe you sent too many pictures at once?"
    if not error:
        error = "UNDEFINED"
    return code, "ERROR%s: %s." % (codestr, error.rstrip('.'))

_re_clean_oauth_error = re.compile(r'\s*details:\s*<!DOCTYPE html>.*$', re.I)
def clean_oauth_error(error):
    return _re_clean_oauth_error.sub('', str(error).replace('\n', ''))

