#!/usr/bin/env python
# -*- coding: utf-8 -*-
# RSS feeder part adapted from http://www.phppatterns.com/docs/develop/twisted_aggregator (Christian Stocker)

import os, time, socket
from random import shuffle, random
from operator import itemgetter
from hashlib import md5
from datetime import datetime, timedelta
from urllib import unquote
from feedparser import parse as parse_feed
from warnings import filterwarnings
filterwarnings(action='ignore', category=DeprecationWarning, module='feedparser', message="To avoid breaking existing software while fixing issue 310")
filterwarnings(action='ignore', category=DeprecationWarning, message="BaseException.message has been deprecated")
from twisted.internet import reactor, protocol
from twisted.internet.defer import succeed, inlineCallbacks, returnValue as returnD
from twisted.internet.task import LoopingCall
from twisted.internet.threads import deferToThreadPool, deferToThread
from twisted.python.threadpool import ThreadPool
from twisted.python import failure
from lxml.etree import HTML as html_tree, tostring as html2str
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from gazouilleur import config
from gazouilleur.lib.log import logg
from gazouilleur.lib.mongo import sortdesc, count_followers
from gazouilleur.lib.httpget import conditionalGetPage
from gazouilleur.lib.utils import *
from gazouilleur.lib.microblog import Microblog, check_twitter_results, grab_extra_meta, reformat_extended_tweets
from gazouilleur.lib.stats import Stats
from gazouilleur.lib.webmonitor import WebMonitor

class FeederProtocol(object):

    def __init__(self, factory):
        self.fact = factory
        self.threadpool = ThreadPool(1,25)
        reactor.callFromThread(self.threadpool.start)
        # Allow Ctrl-C to get you out cleanly:
        reactor.addSystemEventTrigger('after', 'shutdown', self.threadpool.stop)
        self.pile = []
        self.depiler = None
        self.depiler_running = False

    def log(self, msg, error=False, hint=False):
        self.fact.log(msg, error=error, hint=hint)

    def _handle_error(self, traceback, msg, details):
        trace_str = str(traceback)
        try:
            error_message = traceback.getErrorMessage()
        except:
            try:
                error_message = getattr(traceback, 'message')
            except:
                error_message = trace_str
        error_message = error_message.replace(details, '')
        if not (msg.startswith("downloading") and ("503 " in trace_str or "307 Temporary" in trace_str or "406 Not Acceptable" in trace_str or "was closed cleanly" in trace_str or "User timeout caused" in trace_str)):
            self.log("while %s %s : %s" % (msg, details, error_message.replace('\n', '')), error=True)
        if trace_str and not (msg.startswith("downloading") or "status 503" in trace_str or "ERROR 503" in trace_str or "ERROR 500" in trace_str or "ERROR 111: Network difficulties" in trace_str or '111] Connection refused' in trace_str):
            if (config.DEBUG and "429" not in trace_str) or not msg.startswith("examining"):
                self.log(trace_str, error=True)
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
        return conditionalGetPage(self.fact.cache_dir, url, timeout=self.fact.pagetimeout)

    re_tweet_infos_icerocket = re.compile(r'&amp;in_reply_to_status_id=(\d+)&amp;in_reply_to=([^"]*)">')
    def _get_tweet_infos(self, text, regexp=re_tweet_url, reverse=False):
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
                tweet['user'], tweet['id_str'] = self._get_tweet_infos(div.xpath('h4/div/a')[0].attrib['href'])
                tweet['text'] = html2str(div.xpath('div[@class="message"]')[0])
            elif 'topsy' in url:
                linkstring = html2str(div.xpath('div[@class="actions"]/a')[0]).replace('\n', ' ')
                tweet['user'], tweet['id_str'] = self._get_tweet_infos(linkstring)
                tweet['text'] = html2str(div.xpath('div[@class="body"]/span')[0])
            tweet['text'] = cleanblanks(unescape_html(clean_html(tweet['text'].replace('\n', ' ').replace('&#183;', ' ').replace('>t.co/', '>https://t.co/')))).replace('%s: ' % tweet['user'], '')
            if tweet['id_str'] not in ids:
                ids.append(tweet['id_str'])
                feed.append({'created_at': 'now', 'title': tweet['text'], 'link': "https://twitter.com/%s/status/%s" % (tweet['user'], tweet['id_str'])})
        return {"nexturl": nexturl, "tweets": feed}

    def get_data_from_page(self, page_content, url):
        if not page_content:
            # empty result from ConditionalGetPage when Last-Modified header not changed
            return
        self.fact.cache[url] = time.time()
        if self.fact.name == "pages":
            return page_content
        try:
            feed = parse_feed(StringIO(page_content+''))
        except TypeError:
            feed = parse_feed(StringIO(str(page_content)))
        return feed

    @inlineCallbacks
    def process_elements(self, data, url, name=None):
        if not data:
            returnD(False)
        if self.fact.name == "pages":
            differ = WebMonitor(name, url, self.fact.channel)
            info = yield differ.check_new(data)
            if info:
                self.fact.ircclient._send_message(info, self.fact.channel)
            returnD(True)
        if not data.entries:
            returnD(False)
        sourcename = url
        if data.feed and 'title' in data.feed:
            sourcename = data.feed['title']
            sourcename = unescape_html(sourcename)
        ids = []
        news = []
        links = []
        for i in data.entries:
            date = i.get('published_parsed', i.get('updated_parsed', ''))
            if date:
                date = datetime.fromtimestamp(time.mktime(date))
                if datetime.today() - date > timedelta(hours=config.BACK_HOURS+6):
                    break
            link, self.fact.cache_urls = yield clean_redir_urls(i.get('link', ''), self.fact.cache_urls)
            if not link.startswith('http'):
                link = "%s/%s" % (url[:url.find('/',8)], link.lstrip('/'))
            if link in links:
                continue
            links.append(link)
            title = i.get('title', '').replace('\n', ' ')
            try:
                title = unescape_html(title)
            except:
                pass
            _id = md5(("%s:%s:%s" % (self.fact.channel, link, title.lower())).encode('utf-8')).hexdigest()
            ids.append(_id)
            news.append({'_id': _id, 'channel': self.fact.channel, 'message': title, 'link': link, 'date': date, 'timestamp': datetime.today(), 'source': url, 'sourcename': sourcename})
        existings = yield self.fact.db['news'].find({'channel': self.fact.channel, '_id': {'$in': ids}}, fields=['_id'], filter=sortdesc('_id'))
        existing = [n['_id'] for n in existings]
        new = [n for n in news if n['_id'] not in existing]
        if new:
            new.reverse()
            new = new[:5]
            try:
                yield self.fact.db['news'].insert(new, safe=True)
            except Exception as e:
                self._handle_error(e, "recording news batch", url)
            self.fact.ircclient._send_message([(True, "[%s] %s" % (n['sourcename'].encode('utf-8'), self.format_tweet(n))) for n in new], self.fact.channel)
        returnD(True)

    re_cleantwitpicurl = re.compile(r'( https?(://twitter\.com/\S+/statuse?s?/\d+)/(photo|video)/1) — https?\2$')
    format_tweet = lambda self, t: self.re_cleantwitpicurl.sub(r' —\1', "%s — %s" % (t['message'].encode('utf-8'), t['link'].encode('utf-8')))

    @inlineCallbacks
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
                returnD(False)
        if query:
            source = "%s https://api.twitter.com/api/1.1/search/tweets.json?q=%s" % (source, query)
        ids = []
        hashs = []
        tweets = []
        fresh = True
        for i in elements:
            try:
                date = datetime.fromtimestamp(time.mktime(i.get('published_parsed', '')) - 4*60*60)
            except:
                if i.get('created_at', '') == "now":
                    date = datetime.now()
                else:
                    #date = datetime.strptime(i.get('created_at', ''), '%a %b %d %H:%M:%S +0000 %Y') + timedelta(hours=2)
                    date = parse_date(i.get('created_at', ''))
            if datetime.today() - date > timedelta(hours=config.BACK_HOURS):
                fresh = False
                break
            tweet, self.fact.cache_urls = yield clean_redir_urls(i.get('title', '').replace('\n', ' '), self.fact.cache_urls)
            link = i.get('link', '')
            res = re_tweet_url.search(link)
            if res:
                user = res.group(1)
                tid = long(res.group(2))
                ids.append(tid)
                tw = {'_id': "%s:%s" % (self.fact.channel, tid), 'channel': self.fact.channel, 'id': tid, 'user': user.lower(), 'screenname': user, 'message': tweet, 'uniq_rt_hash': uniq_rt_hash(tweet), 'link': link, 'date': date, 'timestamp': datetime.today(), 'source': source}
                tw = grab_extra_meta(i, tw)
                tweets.append(tw)
        # Delay displaying to avoid duplicates from the stream
        if source != "mystream" and not self.fact.tweets_search_page:
            yield deferredSleep()
        existings = yield self.fact.db['tweets'].find({'channel': self.fact.channel, 'id': {'$in': ids}}, fields=['_id'], filter=sortdesc('id'))
        existing = [t['_id'] for t in existings]
        news = [t for t in tweets if t['_id'] not in existing]
        if not news:
            returnD(False)
        good = []
        news.sort(key=itemgetter('id'))
        if fresh and not source.startswith("my") and len(news) > len(elements) / 2:
            if query and nexturl and pagecount < 3*self.fact.back_pages_limit:
                deferToThreadPool(reactor, self.threadpool, reactor.callLater, 15, self.start_twitter_search, [query], max_id=nexturl, pagecount=pagecount+1)
            elif not query and nexturl and "p=%d" % (self.fact.back_pages_limit+1) not in nexturl and "page=%s" % (2*self.fact.back_pages_limit) not in nexturl:
                deferToThreadPool(reactor, self.threadpool, reactor.callLater, 41, self.start_web, nexturl)
            elif not query and not nexturl and int(source[-1:]) <= self.fact.back_pages_limit:
                deferToThreadPool(reactor, self.threadpool, reactor.callLater, 41, self.start_web, next_page(source))
        if self.fact.displayRT:
            good = news
        else:
            hashs = [t['uniq_rt_hash'] for t in news if t['uniq_rt_hash'] not in hashs]
            existings = yield self.fact.db['tweets'].find({'channel': self.fact.channel, 'uniq_rt_hash': {'$in': hashs}}, fields=['uniq_rt_hash'], filter=sortdesc('id'))
            existing = [t['uniq_rt_hash'] for t in existings]

            for t in news:
                if self.fact.twuser == t['user'] or t['uniq_rt_hash'] not in existing or (self.fact.displayMyRT and "@%s" % self.fact.twuser in t['message'].lower()):
                    existing.append(t['uniq_rt_hash'])
                    good.append(t)
        if config.DEBUG:
            nb_rts_str = ""
            nb_rts = len(news) - len(good)
            if nb_rts:
                nb_rts_str = " (%s RTs filtered)" % nb_rts
            self.log("Displaying %s tweets%s" % (len(good), nb_rts_str), hint=True)
        if self.fact.status != "closed":
            for t in good:
                msg = "%s: %s" % (t['screenname'].encode('utf-8'), self.format_tweet(t))
                self.fact.ircclient._send_message(msg, self.fact.channel)
        for t in news:
            yield self.fact.db['tweets'].save(t, safe=True)
        returnD(True)

    def start_web(self, url=None, name=None):
        d = succeed('')
        if not self.in_cache(url):
            if config.DEBUG:
                self.log("Query %s" % url)
            d.addCallback(self.get_page, url)
            d.addErrback(self._handle_error, "downloading", url)
            if self.fact.tweets_search_page:
                d.addCallback(self.get_data_from_tweets_search_page, url)
            else:
                d.addCallback(self.get_data_from_page, url)
            d.addErrback(self._handle_error, "parsing", url)
            if self.fact.name == "tweets":
                d.addCallback(self.process_tweets, url)
            else:
                d.addCallback(self.process_elements, url, name)
            d.addErrback(self._handle_error, "working on", url)
        return d

    def process_retweets(self, listretweets, *args):
        if not listretweets:
            return None
        retweets, retweets_processed = listretweets
        if retweets:
            self.fact.retweets_processed = retweets_processed
            if config.DEBUG:
                self.log("INFO: RTs processed: %s" % retweets_processed, hint=True)
            return self.process_twitter_feed(retweets, "retweets")
        return None

    def process_mentions(self, listmentions, *args):
        return self.process_twitter_feed(listmentions, "mentions")

    def process_mytweets(self, listtweets, *args):
        return self.process_twitter_feed(listtweets, "tweets")

    re_max_id = re.compile(r'^.*max_id=(\d+)(&.*)?$', re.I)
    @inlineCallbacks
    def process_twitter_feed(self, listtweets, feedtype, query=None, pagecount=0):
        if not listtweets:
            returnD(False)
        if query:
            if not isinstance(listtweets, dict):
                returnD(False)
            nexturl = ""
            if 'max_id_str' in listtweets['search_metadata']:
                nexturl = listtweets['search_metadata']['max_id_str']
            elif 'next_results' in listtweets['search_metadata']:
                nexturl = self.re_max_id.sub(r'\1', listtweets['search_metadata']['next_results'])
            res = {'nexturl':  nexturl}
            listtweets = listtweets['statuses']
        elif not isinstance(listtweets, list):
            returnD(False)
        feed = []
        for tweet in listtweets:
            if not isinstance(tweet, dict):
                continue
            tw = {'created_at': tweet['created_at'], 'title': unescape_html(tweet['text']), 'link': tweet['url']}
            tw = grab_extra_meta(tweet, tw)
            feed.append(tw)
        if query:
            res['tweets'] = feed
            processed = yield self.process_tweets(res, 'search', query=query, pagecount=pagecount)
        else:
            processed = yield self.process_tweets(feed, 'my%s' % feedtype)
        returnD(processed)

    @inlineCallbacks
    def process_dms(self, listdms, user):
        if not listdms:
            returnD(False)
        ids = []
        dms = []
        try:
            listdms = listdms["events"]
            assert(isinstance(listdms, list))
        except:
            self.log("downloading DMs: %s" % listdms, error=True)
            returnD(False)
        for i in listdms:
            try:
                date = parse_timestamp(i.get('created_timestamp', ''))
                if datetime.today() - date > timedelta(hours=config.BACK_HOURS):
                    break
            except Exception as e:
                self.log("processing DM %s: %s %s" % (i.get('created_timestamp'), type(e), e), error=True)
                continue
            tid = long(i.get('id', ''))
            msg = i.get('message_create', {})
            if tid and msg:
                ids.append(tid)
                sender = msg.get('sender_id', '')
                target = msg.get('target', {}).get('recipient_id', '')
                dm, self.fact.cache_urls = yield clean_redir_urls(msg.get('message_data', {}).get('text', '').replace('\n', ' '), self.fact.cache_urls)
                dms.append({'_id': "%s:%s" % (self.fact.channel, tid), 'channel': self.fact.channel, 'id': tid, 'user': user, 'sender_id': sender, 'target_id': target, 'message': dm, 'date': date, 'timestamp': datetime.today()})
        existings = yield self.fact.db['dms'].find({'channel': self.fact.channel, 'id': {'$in': ids}}, fields=['_id'], filter=sortdesc('id'))
        existing = [t['_id'] for t in existings]
        news = [t for t in dms if t['_id'] not in existing]
        if news:
            news.reverse()
            conf = chanconf(self.fact.channel)
            conn = Microblog('twitter', conf, bearer_token=conf["oauth2"])
            res = yield conn.resolve_userids([n["sender_id"] for n in news] + [n["target_id"] for n in news])
            if "ERROR 429" in res or "ERROR 404" in res or not isinstance(res, list):
                self.log("resolving users from DMs %s: %s %s" % (res, type(e), e), error=True)
                returnD(False)
            users = dict((u['id_str'], u['screen_name']) for u in res)
            for n in news:
                n["screenname"] = users.get(n["sender_id"], "unknown")
                n["sender"] = n["screenname"].lower()
                n["target_screenname"] = users.get(n["target_id"], "unknown")
                n["target"] = n["target_screenname"].lower()
            yield self.fact.db['dms'].insert(news, safe=True)
            self.fact.ircclient._send_message([(True, "[DM] @%s ➜ @%s: %s — https://twitter.com/%s" % (n['screenname'].encode('utf-8'), n['target_screenname'].encode('utf-8'), n['message'].encode('utf-8'), n['screenname'].encode('utf-8'))) for n in news], self.fact.channel)
        returnD(True)

    @inlineCallbacks
    def process_stats(self, stats, user):
      # Update followers list
        conf = chanconf(self.fact.channel)
        conn = Microblog('twitter', conf, bearer_token=conf["oauth2"])
        lost = yield conn.update_followers(self.fact.db)
        ct = len(lost)
        if ct:
            self.fact.ircclient._send_message('[twitter] Lost %s follower%s: %s%s' % (ct, "s" if ct>1 else "", format_4_followers(lost), "…" if ct>4 else ""), self.fact.channel)
      # Update stats
        if not stats:
            returnD(False)
        stats, last, timestamp = stats
        if not stats or type(stats) is str:
            returnD(False)
        if not last:
            last = {'tweets': 0, 'followers': 0}
            since = timestamp - timedelta(hours=1)
        else:
            since = last['timestamp']
        if 'lists' not in last:
            last['lists'] = 0
        re_match_rts = re.compile(u'(([MLR]T|%s|♺)\s*)+@?%s' % (QUOTE_CHARS, user), re.I)
        rts = yield self.fact.db['tweets'].find({'channel': self.fact.channel, 'message': re_match_rts, 'timestamp': {'$gte': since}}, fields=['_id'])
        nb_rts = len(rts)
        nb_fols = yield count_followers(user)
        stat = {'user': user, 'timestamp': timestamp, 'tweets': stats.get('statuses_count', last['tweets']), 'followers': nb_fols, 'rts_last_hour': nb_rts, 'lists': stats.get('listed_count', last['lists'])}
        yield self.fact.db['stats'].insert(stat)
        weekday = timestamp.weekday()
        laststats = Stats(user)
        if chan_displays_stats(self.fact.channel) and ((timestamp.hour == 13 and weekday < 5) or timestamp.hour == 18):
            stats = yield laststats.print_last()
            self.fact.ircclient._send_message(stats, self.fact.channel)
        last_tweet = yield self.fact.db['tweets'].find({'channel': self.fact.channel, 'user': user}, fields=['date'], limit=1, filter=sortdesc('timestamp'))
        if chan_displays_stats(self.fact.channel) and last_tweet and timestamp - last_tweet[0]['date'] > timedelta(days=3) and (timestamp.hour == 11 or timestamp.hour == 17) and weekday < 5:
            reactor.callFromThread(reactor.callLater, 3, self.fact.ircclient._send_message, "[FYI] No tweet was sent since %s days." % (timestamp - last_tweet[0]['date']).days, self.fact.channel)
        reactor.callFromThread(reactor.callLater, 1, laststats.dump_data)
        returnD(True)

    def start_twitter(self, name, conf, user):
        if not self.fact.__init_timeout__():
            returnD(False)
        d = succeed(Microblog('twitter', conf, bearer_token=self.fact.twitter_token))
        if config.DEBUG:
            self.log("Query @%s's %s" % (user, name))
        def passs(*args, **kwargs):
            raise Exception("No process existing for %s" % name)
        source = getattr(Microblog, 'get_%s' % name, passs)
        processor = getattr(self, 'process_%s' % name, passs)
        d.addCallback(source, retweets_processed=self.fact.retweets_processed, bearer_token=self.fact.twitter_token)
        d.addErrback(self._handle_error, "downloading %s for" % name, user)
        d.addCallback(check_twitter_results)
        d.addErrback(self._handle_error, "examining %s for" % name, user)
        d.addCallback(processor, user.lower())
        d.addErrback(self._handle_error, "working on %s for" % name, user)
        d.addCallback(self.end_twitter)
        return d

    def end_twitter(self, data):
        self.fact.status = "stopped"

    def start_twitter_search(self, query_list, randorder=None, max_id=None, pagecount=0):
        d = succeed(True)
        if config.DEBUG and not max_id:
            self.log("Start search feeder for Twitter %s" % query_list, hint=True)
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
            d.addCallback(self.fact.update_timeout)
        return d

    @inlineCallbacks
    def search_twitter(self, data, query, max_id=None, page=0, randorder=None):
        if page and randorder:
            try:
                query = yield getFeeds(self.fact.db, self.fact.channel, "tweets", randorder=randorder)
                query = query[page]
            except Exception as e:
                returnD(False)
        if config.DEBUG:
            text = unquote(query)
            if max_id:
                text = "%s before id %s" % (text, max_id.encode('utf-8'))
            self.log("Query Twitter search for %s" % text)
        conn = Microblog('twitter', chanconf(self.fact.channel), bearer_token=self.fact.twitter_token)
        res = conn.search(query, max_id=max_id)
        returnD(res)

    re_twitter_account = re.compile('^@[A-Za-z0-9_]{1,15}$')
    @inlineCallbacks
    def start_stream(self, conf):
        if not self.fact.__init_timeout__():
            returnD(False)
        queries = yield self.fact.db['feeds'].find({'database': 'tweets', 'channel': self.fact.channel}, fields=['query'])
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
        if self.fact.twuser not in track:
            track.append(self.fact.twuser)
        if len(skip):
            self.log("Skipping unprocessable queries for streaming: « %s »" % " » | « ".join(skip), hint=True)
        self.log("Start search streaming for: « %s »" % " » | « ".join(track), hint=True)
        conn = Microblog("twitter", conf, bearer_token=self.fact.twitter_token)
        # tries to find users corresponding with queries to follow with stream
        users, self.fact.ircclient.twitter['users'] = conn.lookup_users(track, self.fact.ircclient.twitter['users'])
        deferToThreadPool(reactor, self.threadpool, self.follow_stream, conf, users.values(), track)
        self.depiler = LoopingCall(self.flush_tweets)
        self.depiler.start(1)
        returnD(True)

    def follow_stream(self, conf, follow, track):
        conn = Microblog("twitter", conf, streaming=True)
        try:
            for tweet in conn.search_stream(follow, track):
                self.fact.update_timeout()
                if self.fact.status == "closed":
                    break
                if tweet:
                    if tweet.get("disconnect") or tweet.get("hangup"):
                        self.log("Disconnected %s" % ("(timeout)" if tweet.get("heartbeat_timeout") else tweet), error=True)
                        break
                    if tweet.get('timeout'):
                        continue    # heartbeat
                    if tweet.get('id_str'):
                        tweet = reformat_extended_tweets(tweet)
                        self.pile.insert(0, tweet)
                    else:
                        try:
                            self.fact.db['tweets'].update(spec={'id': tweet['delete']['status']['id']}, document={'$set': {'deleted': True}}, multi=True)
                            if config.DEBUG:
                                self.log("Mark a tweet as deleted: %s" % tweet['delete']['status']['id'], hint=True)
                        except:
                            if config.DEBUG:
                                self.log(tweet, hint=True)
        except socket.error as e:
            self.log("Stream lost connection with %s: %s" % (type(e), e), error=True)
        except Exception as e:
            if str(e).strip():
                self.log("Stream crashed with %s: %s" % (type(e), e), error=True)
            else:
                self._handle_error(failure.Failure(e), "following", "stream")
        self.depiler.stop()
        self.flush_tweets()
        self.log("Feeder closed.", hint=True)
        if self.fact.status != "closed":
            self.fact.status = "stopped"

    @inlineCallbacks
    def flush_tweets(self):
        if self.depiler_running or not self.pile:
            returnD(None)
        self.depiler_running = True
        todo = []
        while self.pile and len(todo) < 35:
            todo.append(self.pile.pop())
        if len(self.pile) > 1500:
            self.fact.ircclient._show_error(failure.Failure(Exception("Warning, stream on %s has %d tweets late to display. Dumping the data to the trash now... You should still use %sfuckoff and %sunfollow to clean the guilty query." % (self.fact.channel, len(self.pile), COMMAND_CHAR_DEF, COMMAND_CHAR_DEF))), self.fact.channel, admins=True)
            del self.pile[:]
        elif len(self.pile) > 500:
            self.fact.ircclient._show_error(failure.Failure(Exception("Warning, stream on %s has %d tweets late to display. You should use %sfuckoff and %sunfollow the guilty query or at least restart." % (self.fact.channel, len(self.pile), COMMAND_CHAR_DEF, COMMAND_CHAR_DEF))), self.fact.channel, admins=True)
        if config.DEBUG:
            self.log("Flush %s tweets%s." % (len(todo), " (%s left to do)" % len(self.pile) if len(self.pile) else ""), hint=True)
        yield self.process_twitter_feed(todo, "stream")
        self.depiler_running = False
        returnD(True)


class FeederFactory(protocol.ClientFactory):

    def __init__(self, ircclient, channel, name, delay=90, timeout=0, pagetimeout=0, feeds=None, tweets_search_page=None, twitter_token=None, back_pages_limit=3):
        self.ircclient = ircclient
        self.db = ircclient.db
        self.cache = {}
        self.cache_urls = ircclient.cache_urls
        self.channel = channel.lower()
        self.name = name
        self.delay = delay
        self.pagetimeout = pagetimeout
        self.feeds = feeds
        conf = chanconf(channel)
        self.displayRT = chan_displays_rt(channel, conf)
        self.displayMyRT = chan_displays_my_rt(channel, conf)
        self.twuser = get_chan_twitter_user(channel, conf).lower()
        self.retweets_processed = {}
        self.tweets_search_page = tweets_search_page
        self.back_pages_limit = back_pages_limit
        self.twitter_token = twitter_token
        self.protocol = FeederProtocol(self)
        self.cache_dir = os.path.join('cache', channel)
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.runner = None
        self.timeout = timeout if timeout else 5 * pagetimeout if pagetimeout else min(300, delay + 30)
        self.timedout = 0
        self.status = "init"
        self.supervisor = LoopingCall(self.__check_timeout__)
        self.supervisor.start(int(self.timeout/4))
        if not config.DEBUG:
            self.errorlogs = {}

    def log(self, msg, error=False, hint=False):
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
        return logg(msg, channel=self.channel, action=self.name, error=error, color=color)

    def start(self):
        if config.DEBUG and self.name != "stream":
            self.log("Start %s feeder every %ssec %s" % (self.name, self.delay, self.feeds if self.feeds else ""), hint=True)
        args = {}
        conf = chanconf(self.channel)
        if self.name in ["retweets", "dms", "stats", "mentions", "mytweets"]:
            run_command = self.protocol.start_twitter
            args = {'name': self.name, 'conf': conf, 'user': self.twuser}
        elif self.name == "search":
            run_command = self.run_twitter_search
        elif self.name == "stream":
            run_command = self.protocol.start_stream
            args['conf'] = conf
        else:
            run_command = self.run_web_feeds
        self.runner = LoopingCall(run_command, **args)
        self.runner.start(self.delay)

    def __init_timeout__(self):
        if self.status == "running":
            return False
        self.status = "running"
        self.update_timeout()
        return True

    def update_timeout(self, data=None, extra=0):
        self.timedout = time.time() + self.timeout + extra

    def __check_timeout__(self):
        if self.status == "running" and time.time() > self.timedout:
            self.log("%s feeder timed-out (action took looker than %ds), restarting..." % (self.name, self.timeout), error=True)
            self.status = "closed"
            if self.runner.running:
                self.runner.stop()
                self.protocol.threadpool.stop()
            self.start()

    def end(self):
        self.status = "closed"
        if self.supervisor.running:
            self.supervisor.stop()
        if self.runner and self.runner.running:
            self.runner.stop()
            self.protocol.threadpool.stop()
        if config.DEBUG and self.name != "stream":
            self.log("Feeder closed.", hint=True)
        self.runner = None

    @inlineCallbacks
    def run_twitter_search(self):
        if not self.__init_timeout__():
            returnD(False)
        queries = yield self.db['feeds'].find({'database': 'tweets', 'channel': self.channel})
        randorder = range(len(queries))
        shuffle(randorder)
        urls = yield getFeeds(self.db, self.channel, 'tweets', randorder=randorder)
        yield self.protocol.start_twitter_search(urls, randorder=randorder)
        self.status = "stopped"

    @inlineCallbacks
    def run_web_feeds(self):
        if not self.__init_timeout__():
            returnD(False)
        urls = self.feeds
        if not urls:
            urls = yield getFeeds(self.db, self.channel, self.name, add_url=self.tweets_search_page)
        ct = 0
        for url in urls:
            name = None
            if self.name == "pages":
                url, name = url
            yield deferredSleep(3 + int(random()*500)/100)
            self.update_timeout(extra=10)
            yield self.protocol.start_web(url, name=name)
        self.status = "stopped"

