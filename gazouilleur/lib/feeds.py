#!/usr/bin/env python
# -*- coding: utf-8 -*-
# RSS feeder part adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os, time
import pymongo
from random import shuffle, random
from operator import itemgetter
from hashlib import md5
from datetime import datetime, timedelta
from urllib import unquote
from feedparser import parse as parse_feed
from warnings import filterwarnings
filterwarnings(action='ignore', category=DeprecationWarning, module='feedparser', message="To avoid breaking existing software while fixing issue 310")
filterwarnings(action='ignore', category=DeprecationWarning, message="BaseException.message has been deprecated")
from twisted.internet import reactor, protocol, defer
from twisted.internet.task import LoopingCall
from twisted.internet.threads import deferToThreadPool, deferToThread
from twisted.python.threadpool import ThreadPool
from twisted.python import failure
from httpget import conditionalGetPage
from lxml.etree import HTML as html_tree, tostring as html2str
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from gazouilleur import config
from gazouilleur.lib.log import logg
from gazouilleur.lib.utils import *
from gazouilleur.lib.microblog import Microblog, check_twitter_results, grab_extra_meta
from gazouilleur.lib.stats import Stats

re_tweet_url = re.compile(r'twitter.com/([^/]+)/statuse?s?/(\d+)(\D.*)?$', re.I)

class FeederProtocol():
    def __init__(self, factory):
        self.fact = factory
        self.db = self.fact.db
        self.threadpool = ThreadPool(1,25)
        reactor.callFromThread(self.threadpool.start)
        # Allow Ctrl-C to get you out cleanly:
        reactor.addSystemEventTrigger('after', 'shutdown', self.threadpool.stop)

    def log(self, msg, action="", error=False, hint=False):
        self.fact.log(msg, action, error=error, hint=hint)

    def _handle_error(self, traceback, msg, details):
        trace_str = str(traceback)
        try:
            error_message = traceback.getErrorMessage()
        except:
            try:
                error_message = getattr(traceback, 'message')
            except:
                error_message = trace_str
        if not (msg.startswith("downloading") and ("503 " in trace_str or "307 Temporary" in trace_str or "406 Not Acceptable" in trace_str or "was closed cleanly" in trace_str or "User timeout caused" in trace_str)):
            self.log("while %s %s : %s" % (msg, details, error_message.replace('\n', '')), self.fact.database, error=True)
        if trace_str and not (msg.startswith("downloading") or "ERROR 503" in trace_str or "ERROR 111: Network difficulties" in trace_str or '111] Connection refused' in trace_str):
            if (config.DEBUG and "429" not in trace_str) or not msg.startswith("examining"):
                self.log(trace_str, self.fact.database, error=True)
            self.fact.ircclient._show_error(failure.Failure(Exception("%s %s: %s" % (msg, details, error_message))), self.fact.channel, admins=True)
        if ('403 Forbidden' in trace_str or '111: Connection refused' in trace_str) and self.fact.tweets_search_page:
            self.fact.ircclient.breathe = datetime.today() + timedelta(minutes=20)

    def in_cache(self, url):
        if ('icerocket' in url or 'topsy' in url) and datetime.today() < self.fact.ircclient.breathe:
            return True
        already_got = self.fact.cache.get(url, None)
        if already_got:
            elapsed_time = time.time() - already_got
            if elapsed_time < self.fact.delay:
                return True
        return False

    def get_page(self, nodata, url):
        return conditionalGetPage(self.fact.cache_dir, url, timeout=self.fact.timeout)

    re_tweet_infos_icerocket = re.compile(r'&amp;in_reply_to_status_id=(\d+)&amp;in_reply_to=([^"]*)">')
    def _get_tweet_infos(self, text, regexp, reverse=False):
        match = regexp.search(text)
        if match and reverse:
            return match.group(2), match.group(1)
        elif match:
            return match.group(1), match.group(2)
        return '', ''

    def get_data_from_tweets_search_page(self, page, url):
        feed = []
        ids = []
        try:
            tree = html_tree(page)
        except:
            return {"nexturl": '', "tweets": []}
        nexturl = ''
        if 'icerocket' in url:
            nexts = tree.xpath('//a[@id="next"]')
            divs = tree.xpath('//div[@class="media-body"]')
        elif 'topsy' in url:
            nexts = tree.xpath('//div[@class="pager-box-body"]/a')
            divs = tree.xpath('//div[@class="twitter-post-big"] | //div[@class="twitter-post-small"]')
        if len(nexts):
            nexturl = nexts[0].attrib['href']
        if not nexturl.startswith("http"):
            nexturl = url[:url.find('/', 7)+1] + nexturl.lstrip('/')
        for div in divs:
            tweet = {'text': '', 'user': '', 'id_str': ''}
            if 'icerocket' in url:
                ''' Old IceRocket's html parsing
                for line in div:
                    line = html2str(line).replace('\n', ' ').replace('&#183;', ' ').replace('>t.co/', '>https://t.co/')
                    if 'class="author"' in line:
                        tweet['user'], tweet['id_str'] = self._get_tweet_infos(line, self.re_tweet_infos_icerocket, True)
                        break
                    elif 'class=' not in line:
                        tweet['text'] += line
                '''
                tweet['user'], tweet['id_str'] = self._get_tweet_infos(div.xpath('h4/div/a')[0].attrib['href'], re_tweet_url)
                tweet['text'] = html2str(div.xpath('div[@class="message"]')[0])
            elif 'topsy' in url:
                linkstring = html2str(div.xpath('div[@class="actions"]/a')[0]).replace('\n', ' ')
                tweet['user'], tweet['id_str'] = self._get_tweet_infos(linkstring, re_tweet_url)
                tweet['text'] = html2str(div.xpath('div[@class="body"]/span')[0])
            tweet['text'] = cleanblanks(unescape_html(clean_html(tweet['text'].replace('\n', ' ').replace('&#183;', ' ').replace('>t.co/', '>https://t.co/')))).replace('%s: ' % tweet['user'], '')
            if tweet['id_str'] not in ids:
                ids.append(tweet['id_str'])
                feed.append({'created_at': 'now', 'title': tweet['text'], 'link': "http://twitter.com/%s/statuses/%s" % (tweet['user'], tweet['id_str'])})
        return {"nexturl": nexturl, "tweets": feed}

    def get_data_from_page(self, page, url):
        if not page:
            return
        try:
            feed = parse_feed(StringIO(page+''))
        except TypeError:
            feed = parse_feed(StringIO(str(page)))
        self.fact.cache[url] = time.time()
        return feed

    @defer.inlineCallbacks
    def process_elements(self, feed, url):
        if not feed or not feed.entries:
            defer.returnValue(None)
        sourcename = url
        if feed.feed and 'title' in feed.feed:
            sourcename = feed.feed['title']
            sourcename = unescape_html(sourcename)
        ids = []
        news = []
        links = []
        for i in feed.entries:
            date = i.get('published_parsed', i.get('updated_parsed', ''))
            if date:
                date = datetime.fromtimestamp(time.mktime(date))
                if datetime.today() - date > timedelta(hours=config.BACK_HOURS+6):
                    break
            link, self.fact.cache_urls = yield clean_redir_urls(i.get('link', ''), self.fact.cache_urls, self.threadpool)
            if not link.startswith('http'):
                link = "%s/%s" % (url[:url.find('/',8)], link.lstrip('/'))
            if link in links:
                continue
            links.append(link)
            title = unescape_html(i.get('title', '').replace('\n', ' '))
            _id = md5(("%s:%s:%s" % (self.fact.channel, link, title.lower())).encode('utf-8')).hexdigest()
            ids.append(_id)
            news.append({'_id': _id, 'channel': self.fact.channel, 'message': title, 'link': link, 'date': date, 'timestamp': datetime.today(), 'source': url, 'sourcename': sourcename})
        existing = [n['_id'] for n in self.db['news'].find({'channel': self.fact.channel, '_id': {'$in': ids}}, fields=['_id'], sort=[('_id', pymongo.DESCENDING)])]
        new = [n for n in news if n['_id'] not in existing]
        if new:
            new.reverse()
            new = new[:5]
            try:
                self.db['news'].insert(new, continue_on_error=True, safe=True)
            except pymongo.errors.OperationFailure as e:
                self._handle_error(e, "recording news batch", url)
            self.fact.ircclient._send_message([(True, "[News — %s] %s — %s" % (n['sourcename'].encode('utf-8'), n['message'].encode('utf-8'), n['link'].encode('utf-8'))) for n in new], self.fact.channel)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def process_tweets(self, feed, source, query=None, pagecount=0):
        # handle tweets from icerocket or topsy fake rss
        nexturl = ""
        try:
            elements = feed.entries
        except:
        # handle tweets from Twitter API
            if isinstance(feed, list) and len(feed):
                elements = feed
            elif isinstance(feed, dict) and "nexturl" in feed:
                nexturl = feed["nexturl"]
                elements = feed["tweets"]
            else:
                defer.returnValue(None)
        if query:
            source = "%s https://api.twitter.com/api/1.1/search/tweets.json?q=%s" % (source, query)
        ids = []
        hashs = []
        tweets = []
        fresh = True
        for i in elements:
            try:
                time_tweet = time.mktime(i.get('published_parsed', '')) - 4*60*60
            except:
                if i.get('created_at', '') == "now":
                    time_tweet = time.time()
                else:
                    time_tweet = time.mktime(time.strptime(i.get('created_at', ''), '%a %b %d %H:%M:%S +0000 %Y')) + 2*60*60
            date = datetime.fromtimestamp(time_tweet)
            if datetime.today() - date > timedelta(hours=config.BACK_HOURS):
                fresh = False
                break
            tweet, self.fact.cache_urls = yield clean_redir_urls(i.get('title', '').replace('\n', ' '), self.fact.cache_urls, self.threadpool)
            tweet = tweet.replace('&#126;', '~')
            link = i.get('link', '')
            res = re_tweet_url.search(link)
            if res:
                user = res.group(1)
                tid = long(res.group(2))
                ids.append(tid)
                tw = {'_id': "%s:%s" % (self.fact.channel, tid), 'channel': self.fact.channel, 'id': tid, 'user': user.lower(), 'screenname': user, 'message': tweet, 'uniq_rt_hash': uniq_rt_hash(tweet), 'link': link, 'date': date, 'timestamp': datetime.today(), 'source': source}
                tw = grab_extra_meta(i, tw)
                tweets.append(tw)
        existing = [t['_id'] for t in self.db['tweets'].find({'channel': self.fact.channel, 'id': {'$in': ids}}, fields=['_id'], sort=[('id', pymongo.DESCENDING)])]
        news = [t for t in tweets if t['_id'] not in existing]
        if news:
            good = 0
            news.sort(key=itemgetter('id'))
            if fresh and not source.startswith("my") and len(news) > len(elements) / 2:
                if query and nexturl and pagecount < 3*self.fact.back_pages_limit:
                    deferToThreadPool(reactor, self.threadpool, reactor.callLater, 15, self.start_twitter_search, [query], max_id=nexturl, pagecount=pagecount+1)
                elif not query and nexturl and "p=%d" % (self.fact.back_pages_limit+1) not in nexturl and "page=%s" % (2*self.fact.back_pages_limit) not in nexturl:
                    deferToThreadPool(reactor, self.threadpool, reactor.callLater, 41, self.start, nexturl)
                elif not query and not nexturl and int(source[-1:]) <= self.fact.back_pages_limit:
                    deferToThreadPool(reactor, self.threadpool, reactor.callLater, 41, self.start, next_page(source))
            if not self.fact.displayRT:
                hashs = [t['uniq_rt_hash'] for t in news if t['uniq_rt_hash'] not in hashs]
                existing = [t['uniq_rt_hash'] for t in self.db['tweets'].find({'channel': self.fact.channel, 'uniq_rt_hash': {'$in': hashs}}, fields=['uniq_rt_hash'], sort=[('id', pymongo.DESCENDING)])]
                tw_user = ""
                if self.fact.twitter_user:
                    tw_user = self.fact.twitter_user.lower()
                for t in news:
                    if tw_user == t['user'] or t['uniq_rt_hash'] not in existing or (self.fact.displayMyRT and "@%s" % tw_user in t['message'].lower()):
                        existing.append(t['uniq_rt_hash'])
                        if not self.fact.status.startswith("clos"):
                            self.displayTweet(t)
                        good += 1
            else:
                if not self.fact.status.startswith("clos"):
                    [self.displayTweet(t) for t in news]
                good = len(news)
            if config.DEBUG:
                nb_rts_str = ""
                nb_rts = len(news) - good
                if nb_rts:
                    nb_rts_str = " (%s RTs filtered)" % nb_rts
                self.log("Displaying %s tweets%s" % (good, nb_rts_str), self.fact.database, hint=True)
            self.db['tweets'].insert(news, continue_on_error=True, safe=True)
        defer.returnValue(None)

    def displayTweet(self, t):
        msg = "%s: %s — %s" % (t['screenname'].encode('utf-8'), t['message'].encode('utf-8'), t['link'].encode('utf-8'))
        return deferToThreadPool(reactor, self.threadpool, self.fact.ircclient._send_message, msg, self.fact.channel)

    def start(self, url=None):
        d = defer.succeed('')
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        if not self.in_cache(url):
            if config.DEBUG:
                self.log("Query %s" % url, self.fact.database)
            d.addCallback(self.get_page, url)
            d.addErrback(self._handle_error, "downloading", url)
            if self.fact.tweets_search_page:
                d.addCallback(self.get_data_from_tweets_search_page, url)
            else:
                d.addCallback(self.get_data_from_page, url)
            d.addErrback(self._handle_error, "parsing", url)
            if self.fact.database == "tweets":
                d.addCallback(self.process_tweets, url)
            else:
                d.addCallback(self.process_elements, url)
            d.addErrback(self._handle_error, "working on", url)
        return d

    def process_retweets(self, listretweets, *args):
        if not listretweets:
            return None
        retweets, retweets_processed = listretweets
        if retweets:
            self.fact.retweets_processed = retweets_processed
        if config.DEBUG:
            self.log("INFO: RTs processed: %s" % retweets_processed, "retweets", hint=True)
        return self.process_twitter_feed(retweets, "retweets")

    def process_mentions(self, listmentions, *args):
        return self.process_twitter_feed(listmentions, "mentions")

    def process_mytweets(self, listtweets, *args):
        return self.process_twitter_feed(listtweets, "tweets")

    re_max_id = re.compile(r'^.*max_id=(\d+)(&.*)?$', re.I)
    @defer.inlineCallbacks
    def process_twitter_feed(self, listtweets, feedtype, query=None, pagecount=0):
        if not listtweets:
            defer.returnValue(None)
        if query:
            if not isinstance(listtweets, dict):
                defer.returnValue(None)
            nexturl = ""
            if 'max_id_str' in listtweets['search_metadata']:
                nexturl = listtweets['search_metadata']['max_id_str']
            elif 'next_results' in listtweets['search_metadata']:
                nexturl = self.re_max_id.sub(r'\1', listtweets['search_metadata']['next_results'])
            res = {'nexturl':  nexturl}
            listtweets = listtweets['statuses']
        elif not isinstance(listtweets, list):
            defer.returnValue(None)
        feed = []
        for tweet in listtweets:
            if 'entities' in tweet and 'urls' in tweet['entities']:
                for entity in tweet['entities']['urls']:
                  try:
                    if 'expanded_url' in entity and 'url' in entity and entity['expanded_url'] and entity['url'] not in self.fact.cache_urls:
                        self.fact.cache_urls[entity['url']] = clean_url(entity['expanded_url'].encode('utf-8'))
                        _, self.fact.cache_urls = yield clean_redir_urls(self.fact.cache_urls[entity['url']].decode('utf-8'), self.fact.cache_urls, self.threadpool)
                  except Exception as e:
                     self.log(e, error=True)
            if "retweeted_status" in tweet and tweet['retweeted_status']['id_str'] != tweet['id_str']:
                text = "RT @%s: %s" % (tweet['retweeted_status']['user']['screen_name'], tweet['retweeted_status']['text'])
            else:
                text = tweet['text']
            tw = {'created_at': tweet['created_at'], 'title': unescape_html(text), 'link': "http://twitter.com/%s/statuses/%s" % (tweet['user']['screen_name'], tweet['id_str'])}
            tw = grab_extra_meta(tweet, tw)
            feed.append(tw)
        if query:
            res['tweets'] = feed
            processed = yield self.process_tweets(res, 'search', query=query, pagecount=pagecount)
        else:
            processed = yield self.process_tweets(feed, 'my%s' % feedtype)
        defer.returnValue(processed)

    @defer.inlineCallbacks
    def process_dms(self, listdms, user):
        if not listdms:
            defer.returnValue(None)
        ids = []
        dms = []
        for i in listdms:
            try:
                date = datetime.fromtimestamp(time.mktime(time.strptime(i.get('created_at', ''), '%a %b %d %H:%M:%S +0000 %Y'))+2*60*60)
                if datetime.today() - date > timedelta(hours=config.BACK_HOURS):
                    break
            except:
                self.log("processing DM %s: %s" % (i, listdms), "dms", error=True)
                continue
            tid = long(i.get('id', ''))
            if tid:
                ids.append(tid)
                sender = i.get('sender_screen_name', '')
                dm, self.fact.cache_urls = yield clean_redir_urls(i.get('text', '').replace('\n', ' '), self.fact.cache_urls, self.threadpool)
                dms.append({'_id': "%s:%s" % (self.fact.channel, tid), 'channel': self.fact.channel, 'id': tid, 'user': user, 'sender': sender.lower(), 'screenname': sender, 'message': dm, 'date': date, 'timestamp': datetime.today()})
        existing = [t['_id'] for t in self.db['dms'].find({'channel': self.fact.channel, 'id': {'$in': ids}}, fields=['_id'], sort=[('id', pymongo.DESCENDING)])]
        news = [t for t in dms if t['_id'] not in existing]
        if news:
            news.reverse()
            self.db['dms'].insert(news, continue_on_error=True, safe=True)
            self.fact.ircclient._send_message([(True, "[DM] @%s: %s — https://twitter.com/%s" % (n['screenname'].encode('utf-8'), n['message'].encode('utf-8'), n['screenname'].encode('utf-8'))) for n in news], self.fact.channel)
        defer.returnValue(None)

    def process_stats(self, res, user):
        if not res:
            return None
        stats, last, timestamp = res
        if not stats:
            return None
        if not last:
            last = {'tweets': 0, 'followers': 0}
            since = timestamp - timedelta(hours=1)
        else:
            since = last['timestamp']
        if 'lists' not in last:
            last['lists'] = 0
        re_match_rts = re.compile(u'(([MLR]T|%s|♺)\s*)+@?%s' % (QUOTE_CHARS, user), re.I)
        rts = self.db['tweets'].find({'channel': self.fact.channel, 'message': re_match_rts, 'timestamp': {'$gte': since}}, snapshot=True, fields=['_id'])
        nb_rts = rts.count() if rts.count() else 0
        if config.TWITTER_API_VERSION == 1:
            stat = {'user': user, 'timestamp': timestamp, 'tweets': stats.get('updates', last['tweets']), 'followers': stats.get('followers', last['followers']), 'rts_last_hour': nb_rts}
        else:
            stat = {'user': user, 'timestamp': timestamp, 'tweets': stats.get('statuses_count', last['tweets']), 'followers': stats.get('followers_count', last['followers']), 'rts_last_hour': nb_rts, 'lists': stats.get('listed_count', last['lists'])}
        self.db['stats'].insert(stat)
        weekday = timestamp.weekday()
        laststats = Stats(self.db, user)
        if chan_displays_stats(self.fact.channel) and ((timestamp.hour == 13 and weekday < 5) or timestamp.hour == 18):
            self.fact.ircclient._send_message(laststats.print_last(), self.fact.channel)
        last_tweet = self.db['tweets'].find_one({'channel': self.fact.channel, 'user': user}, fields=['date'], sort=[('timestamp', pymongo.DESCENDING)])
        if chan_displays_stats(self.fact.channel) and last_tweet and timestamp - last_tweet['date'] > timedelta(days=3) and (timestamp.hour == 11 or timestamp.hour == 17) and weekday < 5:
            reactor.callFromThread(reactor.callLater, 3, self.fact.ircclient._send_message, "[FYI] No tweet was sent since %s days." % (timestamp - last_tweet['date']).days, self.fact.channel)
        reactor.callFromThread(reactor.callLater, 1, laststats.dump_data)
        return None

    def start_twitter(self, database, conf, user):
        d = defer.succeed(Microblog('twitter', conf, bearer_token=self.fact.twitter_token))
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        if config.DEBUG:
            self.log("Query @%s's %s" % (user, database), database)
        def passs(*args, **kwargs):
            raise Exception("No process existing for %s" % database)
        source = getattr(Microblog, 'get_%s' % database, passs)
        processor = getattr(self, 'process_%s' % database, passs)
        d.addCallback(source, db=self.db, retweets_processed=self.fact.retweets_processed, bearer_token=self.fact.twitter_token)
        d.addErrback(self._handle_error, "downloading %s for" % database, user)
        d.addCallback(check_twitter_results)
        d.addErrback(self._handle_error, "examining %s for" % database, user)
        d.addCallback(processor, user.lower())
        d.addErrback(self._handle_error, "working on %s for" % database, user)
        return d

    def start_twitter_search(self, query_list, randorder=None, max_id=None, pagecount=0):
        d = defer.succeed(True)
        self.fact.status = "running"
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        if config.DEBUG and not max_id:
            self.log("Start search feeder for Twitter %s" % query_list, "search", hint=True)
        for i, query in enumerate(query_list):
            text = "results of Twitter search for %s" % unquote(query)
            if max_id:
                text = "%s before id %s" % (text, str(max_id))
            d.addCallback(self.search_twitter, query, max_id=max_id, page=i, randorder=randorder)
            d.addErrback(self._handle_error, "downloading", text)
            d.addCallback(check_twitter_results)
            d.addErrback(self._handle_error, "examining", text)
            d.addCallback(self.process_twitter_feed, "search", query=query, pagecount=pagecount)
            d.addErrback(self._handle_error, "working on", text)
        return d

    def search_twitter(self, data, query, max_id=None, page=0, randorder=None):
        if page and randorder:
            try:
                query = getFeeds(self.fact.channel, "tweets", self.db, randorder=randorder)[page]
            except:
                return None
        if config.DEBUG:
            text = unquote(query)
            if max_id:
                text = "%s before id %s" % (text, max_id.encode('utf-8'))
            self.log("Query Twitter search for %s" % text, "search")
        conn = Microblog('twitter', chanconf(self.fact.channel), bearer_token=self.fact.twitter_token)
        return conn.search(query, max_id=max_id)

    re_twitter_account = re.compile('^@[A-Za-z0-9_]{1,15}$')
    def start_stream(self, conf):
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        queries = list(self.db["feeds"].find({'database': "tweets", 'channel': self.fact.channel}, fields=['query']))
        track = []
        skip = []
        k = 0
        for query in queries:
            q = str(query['query'].encode('utf-8')).lower()
            # queries starting with @ should return only tweets from corresponding user, stream doesn not know how to handle this so skip
            if self.re_twitter_account.match(q):
                continue
            elif " OR " in q or " -" in q or '"' in q or len(q) > 60 or len(q) < 6:
                skip.append(q)
                continue
            track.append(q)
            k += 1
            if k > 395:
                break
        user = self.fact.twitter_user.lower()
        if user not in track:
            track.append(user)
        if len(skip):
            self.log("Skipping unprocessable queries for streaming: « %s »" % " » | « ".join(skip), "stream", hint=True)
        self.log("Start search streaming for: « %s »" % " » | « ".join(track), "stream", hint=True)
        conn = Microblog("twitter", conf, bearer_token=self.fact.twitter_token)
        # tries to find users corresponding with queries to follow with stream
        users, self.fact.ircclient.twitter['users'] = conn.lookup_users(track, self.fact.ircclient.twitter['users'])
        return deferToThreadPool(reactor, self.threadpool, self.follow_stream, conf, users.values(), track)

    def follow_stream(self, conf, follow, track):
        conn = Microblog("twitter", conf, streaming=True)
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        ct = 0
        tweets = []
        deleted = []
        flush = time.time() + 14
        self.fact.status = "running"
        try:
            for tweet in conn.search_stream(follow, track):
                if self.fact.status.startswith("clos"):
                    break
                if tweet:
                    if tweet.get("disconnect"):
                        self.log("Disconnected %s" % tweet, "stream", error=True)
                        break
                    if tweet.get('text'):
                        tweets.append(tweet)
                        ct += 1
                    else:
                        try:
                            deleted.append(tweet['delete']['status']['id'])
                        except:
                            if config.DEBUG:
                                self.log(tweet, "stream", hint=True)
                elif not (ct + len(deleted)):
                    continue
                if ct > 9 or len(deleted) or time.time() > flush:
                    self._flush_tweets(tweets, deleted)
                    ct = 0
                    tweets = []
                    deleted = []
                    flush = time.time() + 14
        except Exception as e:
            if not str(e).strip():
                self.log("Stream crashed with %s: %s", (type(e), e), error=True)
            else:
                self._handle_error(e, "following", "stream")
        self._flush_tweets(tweets, deleted, wait=False)
        self.log("Feeder closed.", "stream", hint=True)
        return

    def _flush_tweets(self, tweets, deleted, wait=True):
        if deleted:
            if config.DEBUG:
                self.log("Mark %s tweets as deleted." % len(deleted), "stream", hint=True)
            args = {'spec': {'id': {'$in': deleted}}, 'document': {'$set': {'deleted': True}}, 'multi': True}
            if wait:
                reactor.callLater(3, self.db["tweets"].update, **args)
            else:
                self.db["tweets"].update(**args)
        if tweets:
            if config.DEBUG:
                self.log("Flush %s tweets." % len(tweets), "stream", hint=True)
            reactor.callLater(0, self.process_twitter_feed, tweets, "stream")


class FeederFactory(protocol.ClientFactory):

    def __init__(self, ircclient, channel, database, delay=90, timeout=20, feeds=None, tweetsSearchPage=None, twitter_token=None, back_pages_limit=3):
        self.ircclient = ircclient
        self.cache = {}
        self.cache_urls = ircclient.cache_urls
        self.channel = channel
        self.database = database

        self.delay = delay
        self.timeout = timeout
        self.feeds = feeds
        conf = chanconf(channel)
        self.displayRT = chan_displays_rt(channel, conf)
        self.displayMyRT = chan_displays_my_rt(channel, conf)
        self.twitter_user = get_chan_twitter_user(channel, conf)
        self.retweets_processed = {}
        self.tweets_search_page = tweetsSearchPage
        self.back_pages_limit = back_pages_limit
        self.twitter_token = twitter_token
        self.db = pymongo.Connection(config.MONGODB['HOST'], config.MONGODB['PORT'])[config.MONGODB['DATABASE']]
        self.protocol = FeederProtocol(self)
        self.cache_dir = os.path.join('cache', channel)
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.runner = None
        self.status = "init"
        if not config.DEBUG:
            self.errorlogs = {}

    def log(self, msg, action="", error=False, hint=False):
        color = None
        if hint:
            color = 'yellow'
        if error and not config.DEBUG:
            hmd5 = md5(str(msg)).hexdigest()
            if hmd5 not in self.errorlogs or self.errorlogs[hmd5]['ts'] < time.time() - 3600*24:
                self.errorlogs[hmd5] = {'n': 1, 'ts': time.time()}
            else:
                self.errorlogs[hmd5]['n'] += 1
                if self.errorlogs[hmd5]['n'] > 3:
                    return
                elif self.errorlogs[hmd5]['n'] == 3:
                    msg += " [#3, skipping these errors now for the next 24h...]"
                else:
                    msg += " [#%d]" % self.errorlogs[hmd5]['n']
                self.errorlogs[hmd5]['ts'] = time.time()
        return logg(msg, channel=self.channel, action=action, error=error, color=color)

    def start(self):
        if config.DEBUG:
            self.log("Start %s feeder every %ssec %s" % (self.database, self.delay, self.feeds), self.database, hint=True)
        args = {}
        conf = chanconf(self.channel)
        if self.database in ["retweets", "dms", "stats", "mentions", "mytweets"]:
            run_command = self.protocol.start_twitter
            args = {'database': self.database, 'conf': conf, 'user': self.twitter_user.lower()}
        elif self.database == "tweets" and not self.tweets_search_page:
            run_command = self.run_twitter_search
        elif self.database == "stream":
            run_command = self.protocol.start_stream
            args['conf'] = conf
        else:
            run_command = self.run_rss_feeds
        self.runner = LoopingCall(run_command, **args)
        self.runner.start(self.delay)

    def end(self):
        if self.runner and self.runner.running:
            self.status = "closing"
            self.protocol.threadpool.stop()
            self.runner.stop()
            if config.DEBUG and self.database != "stream":
                self.log("Feeder closed.", self.database, hint=True)
            self.runner = None
            self.status = "closed"


    def run_twitter_search(self):
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        nqueries = self.db["feeds"].find({'database': self.database, 'channel': self.channel}).count()
        randorder = range(nqueries)
        shuffle(randorder)
        urls = getFeeds(self.channel, self.database, self.db, randorder=randorder)
        return self.protocol.start_twitter_search(urls, randorder=randorder)

    def run_rss_feeds(self):
        urls = self.feeds
        if not urls:
            urls = getFeeds(self.channel, self.database, self.db, add_url=self.tweets_search_page)
        ct = 0
        for url in urls:
            ct += 3 + int(random()*500)/100
            reactor.callFromThread(reactor.callLater, ct, self.protocol.start, url)
        return defer.succeed(True)

