#!/bin/python
# -*- coding: utf-8 -*-
# adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os, sys, time, hashlib, random
from datetime import datetime, timedelta
import feedparser, pymongo, urllib2
from twisted.internet import reactor, protocol, defer, task
from twisted.python import failure
from httpget import conditionalGetPage
try:
    import cStringIO as _StringIO
except ImportError:
    import StringIO as _StringIO
from utils import *
sys.path.append('..')
from config import DEBUG, MONGODB
from microblog import Sender
from stats import Stats

re_tweet_url = re.compile(r'twitter.com/([^/]+)/statuse?s?/(\d+)$', re.I)

class FeederProtocol():
    def __init__(self, factory):
        self.fact = factory
        self.db = self.fact.db

    def _handle_error(self, traceback, msg, url):
        if not msg.startswith("downloading"):
            self.fact.ircclient._show_error(failure.Failure(Exception("%s %s : %s" % (msg, url, traceback.getErrorMessage()))), self.fact.channel)
        print "ERROR while %s %s : %s" % (msg, url, traceback)
        if '403 Forbidden' in str(traceback) and 'icerocket' in url:
            self.fact.ircclient.breathe = datetime.today() + timedelta(minutes=30)

    def in_cache(self, url):
        if 'icerocket' in url and datetime.today() < self.fact.ircclient.breathe:
            return True
        already_got = self.fact.cache.get(url, None)
        if already_got:
            elapsed_time = time.time() - already_got
            if elapsed_time < self.fact.delay:
                return True
        return False

    def get_page(self, nodata, url):
        return conditionalGetPage(self.fact.cache_dir, url, timeout=self.fact.timeout)

    def get_data_from_page(self, page, url):
        try:
            feed = feedparser.parse(_StringIO.StringIO(page+''))
        except TypeError:
            feed = feedparser.parse(_StringIO.StringIO(str(page)))
        self.fact.cache[url] = time.time()
        return feed

    def process_elements(self, feed, url):
        if not feed.entries:
            return None
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
            link, self.fact.cache_urls = clean_redir_urls(i.get('link', ''), self.fact.cache_urls)
            if not link.startswith('http'):
                link = "%s/%s" % (url[:url.find('/',8)], link.lstrip('/'))
            if link in links:
                continue
            links.append(link)
            title = unescape_html(i.get('title', '').replace('\n', ' '))
            _id = hashlib.md5(("%s:%s:%s" % (self.fact.channel, link, title)).encode('utf-8')).hexdigest()
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
        return None

    def process_tweets(self, feed, url):
        if not feed.entries:
            return None
        ids = []
        hashs = []
        tweets = []
        fresh = True
        for i in feed.entries:
            date = datetime.fromtimestamp(time.mktime(i.get('published_parsed', ''))-4*60*60)
            if datetime.today() - date > timedelta(hours=config.BACK_HOURS):
                fresh = False
                break
            tweet, self.fact.cache_urls = clean_redir_urls(i.get('title', '').replace('\n', ' '), self.fact.cache_urls)
            tweet = tweet.replace('&#126;', '~')
            link = i.get('link', '')
            res = re_tweet_url.search(link)
            if res:
                user = res.group(1)
                tid = long(res.group(2))
                ids.append(tid)
                tweets.append({'_id': "%s:%s" % (self.fact.channel, tid), 'channel': self.fact.channel, 'id': tid, 'user': user.lower(), 'screenname': user, 'message': tweet, 'uniq_rt_hash': uniq_rt_hash(tweet), 'link': link, 'date': date, 'timestamp': datetime.today(), 'source': url})
        existing = [t['_id'] for t in self.db['tweets'].find({'channel': self.fact.channel, 'id': {'$in': ids}}, fields=['_id'], sort=[('id', pymongo.DESCENDING)])]
        news = [t for t in tweets if t['_id'] not in existing]
        if news:
            news.reverse()
            if fresh and len(news) > len(feed.entries) / 2 and url[-1:] <= "3":
                reactor.callFromThread(reactor.callLater, 10, self.start, next_page(url))
            text = []
            if not self.fact.displayRT:
                hashs = [t['uniq_rt_hash'] for t in news if t['uniq_rt_hash'] not in hashs]
                existing = [t['uniq_rt_hash'] for t in self.db['tweets'].find({'channel': self.fact.channel, 'uniq_rt_hash': {'$in': hashs}}, fields=['uniq_rt_hash'], sort=[('id', pymongo.DESCENDING)])]
                for t in news:
                    if t['uniq_rt_hash'] not in existing:
                        existing.append(t['uniq_rt_hash'])
                        text.append(self.displayTweet(t))
            else:
                text = [self.displayTweet(t) for t in news]
            try:
                self.db['tweets'].insert(news, continue_on_error=True, safe=True)
            except Exception as e:
                self._handle_error(e, "recording tweets batch", url)
            self.fact.ircclient._send_message(text, self.fact.channel)
        return None

    def displayTweet(self, t):
        return (True, "%s: %s — %s" % (t['screenname'].encode('utf-8'), t['message'].encode('utf-8'), t['link'].encode('utf-8')))

    def start(self, url=None):
        d = defer.succeed('')
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        if not self.in_cache(url):
            if DEBUG:
                print "[%s/%s] Query %s" % (self.fact.channel, self.fact.database, url)
            d.addCallback(self.get_page, url)
            d.addErrback(self._handle_error, "downloading", url)
            d.addCallback(self.get_data_from_page, url)
            d.addErrback(self._handle_error, "parsing", url)
            if self.fact.database == "tweets":
                d.addCallback(self.process_tweets, url)
            else:
                d.addCallback(self.process_elements, url)
            d.addErrback(self._handle_error, "working on", url)
        return d

    def process_dms(self, listdms, user):
        if not listdms:
            return None
        ids = []
        dms = []
        for i in listdms:
            try:
                date = datetime.fromtimestamp(time.mktime(time.strptime(i.get('created_at', ''), '%a %b %d %H:%M:%S +0000 %Y'))+2*60*60)
                if datetime.today() - date > timedelta(hours=config.BACK_HOURS):
                    break
            except:
                print i, listdms
                continue
            tid = long(i.get('id', ''))
            if tid:
                ids.append(tid)
                sender = i.get('sender_screen_name', '')
                dm, self.fact.cache_urls = clean_redir_urls(i.get('text', '').replace('\n', ' '), self.fact.cache_urls)
                dms.append({'_id': "%s:%s" % (self.fact.channel, tid), 'channel': self.fact.channel, 'id': tid, 'user': user, 'sender': sender.lower(), 'screenname': sender, 'message': dm, 'date': date, 'timestamp': datetime.today()})
        existing = [t['_id'] for t in self.db['dms'].find({'channel': self.fact.channel, 'id': {'$in': ids}}, fields=['_id'], sort=[('id', pymongo.DESCENDING)])]
        news = [t for t in dms if t['_id'] not in existing]
        if news:
            news.reverse()
            try:
                self.db['dms'].insert(news, continue_on_error=True, safe=True)
            except pymongo.errors.OperationFailure as e:
                self._handle_error(e, "recording DMs batch", url)
            self.fact.ircclient._send_message([(True, "[DM] @%s: %s — https://twitter.com/%s" % (n['screenname'].encode('utf-8'), n['message'].encode('utf-8'), n['screenname'].encode('utf-8'))) for n in news], self.fact.channel)
        return None

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
        re_match_rts = re.compile(u'(([MLR]T|%s|♺)\s*)+@?%s' % (QUOTE_CHARS, user), re.I)
        rts = self.db['tweets'].find({'channel': self.fact.channel, 'message': re_match_rts, 'timestamp': {'$gte': since}}, snapshot=True, fields=['_id'])
        nb_rts = rts.count() if rts.count() else 0
        stat = {'user': user, 'timestamp': timestamp, 'tweets': stats.get('updates', last['tweets']), 'followers': stats.get('followers', last['followers']), 'rts_last_hour': nb_rts}
        self.db['stats'].insert(stat)
        weekday = timestamp.weekday()
        laststats = Stats(self.db, config, user)
        if (timestamp.hour == 13 and weekday < 5) or timestamp.hour == 18:
            self.fact.ircclient._send_message(laststats.print_last(), self.fact.channel)
        last_tweet = self.db['tweets'].find_one({'channel': self.fact.channel, 'user': user}, fields=['date'], sort=[('timestamp', pymongo.DESCENDING)])
        if last_tweet and timestamp - last_tweet['date'] > timedelta(days=3) and (timestamp.hour == 11 or timestamp.hour == 17) and weekday < 5:
            reactor.callFromThread(reactor.callLater, 3, self.fact.ircclient._send_message, "[FYI] No tweet was sent since %s days." % (timestamp - last_tweet['date']).days, self.fact.channel)
        reactor.callFromThread(reactor.callLater, 1, laststats.dump_data)
        return None

    def start_twitter(self, database, conf, user):
        d = defer.succeed(Sender('twitter', conf))
        self.db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
        if DEBUG:
            print "[%s/%s] Query @%s's %s" % (self.fact.channel, database, user, database)
        def passs(*args, **kwargs):
            raise Exception("No process existing for %s" % database)
        source = getattr(Sender, 'get_%s' % database, passs)
        processor = getattr(self, 'process_%s' % database, passs)
        d.addCallback(source, db=self.db)
        d.addErrback(self._handle_error, "downloading %s for" % database, user)
        d.addCallback(processor, user.lower())
        d.addErrback(self._handle_error, "working on %s for" % database, user)
        return d


class FeederFactory(protocol.ClientFactory):

    def __init__(self, ircclient, channel, database="news", delay=90, timeout=20, feeds=None, displayRT=False):
        self.ircclient = ircclient
        self.channel = channel
        self.database = database
        self.delay = delay
        self.timeout = timeout
        self.feeds = feeds
        self.displayRT = displayRT
        self.db = pymongo.Connection(MONGODB['HOST'], MONGODB['PORT'])[MONGODB['DATABASE']]
        self.protocol = FeederProtocol(self)
        self.cache_dir = os.path.join('cache', channel)
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.cache = {}
        self.cache_urls = {}
        self.runner = None

    def start(self):
        if DEBUG:
            print "Start %s feeder for %s every %ssec %s" % (self.database, self.channel, self.delay, self.feeds)
        if self.database == "dms" or self.database == "stats":
            conf = chanconf(self.channel)
            self.runner = task.LoopingCall(self.protocol.start_twitter, self.database, conf, conf['TWITTER']['USER'].lower())
        else:
            self.runner = task.LoopingCall(self.run)
        self.runner.start(self.delay)

    def end(self):
        if self.runner and self.runner.running:
            self.runner.stop()

    def run(self):
        urls = self.feeds
        if not urls:
            urls = getFeeds(self.channel, self.database, self.db)
        ct = 0
        for url in urls:
            ct += 1 + int(random.random()*500)/100
            reactor.callFromThread(reactor.callLater, ct, self.protocol.start, url)
        return defer.succeed(True)

