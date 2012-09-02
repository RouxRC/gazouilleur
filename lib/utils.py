#!/bin/python
# -*- coding: utf-8 -*-

import sys, re, urllib, hashlib
from urllib2 import urlopen, URLError
from datetime import datetime, timedelta
import socket
import pymongo, htmlentitydefs
sys.path.append('..')
import config

SPACES = ur'[  \s\t\u0020\u00A0\u1680\u180E\u2000-\u200F\u2028-\u202F\u205F\u2060\u3000]'
re_clean_blanks = re.compile(r'%s+' % SPACES)
cleanblanks = lambda x: re_clean_blanks.sub(r' ', x.strip()).strip()

re_shortdate = re.compile(r'^....-(..)-(..)( ..:..).*$')
shortdate = lambda x: re_shortdate.sub(r'\2/\1\3', str(x))

re_clean_doc = re.compile(r'\.?\s*/[^/]+$')
clean_doc = lambda x: re_clean_doc.sub('.', x).strip()

re_clean_identica = re.compile(r'(and posts a ♻ status)? on Identi\.ca( and)?( as a)?', re.I)
clean_identica = lambda x: re_clean_identica.sub('', x)

re_sending_error = re.compile(r'^.* status (\d+) .*details: ({"error":"([^"]*)")?.*$', re.I|re.S)
def sending_error(error):
    error = str(error)
    res = re_sending_error.search(error)
    if res:
        if res.group(3):
            return re_sending_error.sub(r'ERROR \1: \3', error)
        return re_sending_error.sub(r'ERRROR \1', error)
    return "ERROR undefined"

re_handle_quotes = re.compile(r'("[^"]*")')
re_handle_simple_quotes = re.compile(r"('[^']*')")
def _handle_quotes(args, regexp):
    for m in regexp.finditer(args):
        args = args.replace(m.group(1), m.group(1)[1:-1].replace(' ', '\s'))
    return args

def handle_quotes(args):
    return _handle_quotes(_handle_quotes(args, re_handle_quotes), re_handle_simple_quotes)

QUOTES = u'«»„‟“”"\'’‘`‛'
def remove_ext_quotes(arg):
    quotes = QUOTES.encode('utf-8')
    return arg.strip().lstrip(quotes).rstrip(quotes).strip()

# URL recognition adapted from Twitter's
# https://github.com/BonsaiDen/twitter-text-python/blob/master/ttp.py
UTF_CHARS = ur'a-z0-9_\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u00ff'
QUOTE_CHARS = r'[%s]' % QUOTES
PRE_CHARS = ur'(?:^|$|%s|%s|[…<>:!()])' % (SPACES, QUOTE_CHARS)
DOMAIN_CHARS = ur'(?:[^\&=\s_\!\.\/]+\.)+[a-z]{2,3}(?::[0-9]+)?'
PATH_CHARS = ur'(?:\([^\)]*\)|[\.,]?[%s!\*\';:=\+\$/%s#\[\]\-_,~@])' % (UTF_CHARS, '%')
QUERY_CHARS = ur'(?:\([^\)]*\)|[a-z0-9!\*\';:&=\+\$/%#\[\]\-_\.,~])'
PATH_ENDING_CHARS = ur'[%s=#/]' % UTF_CHARS
QUERY_ENDING_CHARS = '[a-z0-9_&=#]'
URL_REGEX = re.compile('((%s+)((?:https?://|www\\.)?%s(?:\/%s*%s?)?(?:\?%s*%s)?)(%s))' % (PRE_CHARS, DOMAIN_CHARS, PATH_CHARS, PATH_ENDING_CHARS, QUERY_CHARS, QUERY_ENDING_CHARS, PRE_CHARS), re.I)

def _shorten_url(text):
    for res in URL_REGEX.findall(text):
        text = text.replace(res[0], '%shttp___t_co_xxxxxxxx%s' % (res[1], res[3]))
    return text

def countchars(text):
    return len(_shorten_url(_shorten_url(text.strip())).decode('utf-8'))

re_clean_url1 = re.compile(r'/#!/')
re_clean_url2 = re.compile(r'((\?|&)((utm_(term|medium|source|campaign|content)|xtor)=[^&#]*))', re.I)
re_clean_url3 = re.compile(ur'(%s|%s|[\.…<>:?!=)])+$' % (SPACES, QUOTE_CHARS))
def clean_url(url):
    url = re_clean_url1.sub('/', url)
    for i in re_clean_url2.findall(url):
        if i[1] == "?":
            url = url.replace(i[2], '')
        else:
            url = url.replace(i[0], '')
    url = re_clean_url3.sub('', url)
    return url  

def _clean_redir_urls(text, urls={}, first=True):
    for res in URL_REGEX.findall(text):
        url00 = res[2].encode('utf-8')
        url0 = url00
        if not url00.startswith('http'):
            url0 = "http://%s" % url00
        if url0 in urls:
            url1 = urls[url0]
            if url1 == url0:
                continue
        else:
            try:
                url1 = urlopen(url0, timeout=20).geturl()
                url1 = clean_url(url1)
                urls[url0] = url1
                urls[url1] = url1
            except Exception as e:
                if config.DEBUG and not first:
                    print "ERROR trying to access %s : %s" % (url0, e)
                url1 = url00
        if first:
            url1 = url1.replace('http', '##HTTP##')
        text = text.replace(res[0], '%s%s%s' % (res[1], url1.decode('utf-8'), res[3]))
    if not first:
        text = text.replace('##HTTP##', 'http')
    return text, urls

def clean_redir_urls(text, urls):
    text, urls = _clean_redir_urls(text, urls)
    return _clean_redir_urls(text, urls, False)

def get_hash(url):
    hash = hashlib.md5(url)
    return hash.hexdigest()

re_uniq_rt_hash = re.compile(r'([MLR]T|%s)+\s*@[a-zA-Z0-9_]{1,15}[: ,]*' % QUOTE_CHARS)
re_clean_spec_chars = re.compile(r'(%s|[-_.,;:?!<>(){}[\]/\\~^+=|#@&$%s])+' % (QUOTE_CHARS, '%'))
def uniq_rt_hash(text):
    text = re_uniq_rt_hash.sub(' ', text)
    text = re_clean_spec_chars.sub(' ', text)
    text = cleanblanks(text)
    return get_hash(text.encode('utf-8'))

re_entities = re.compile(r'&([^;]+);')
def unescape_html(text):
    return re_entities.sub(lambda x: unichr(htmlentitydefs.name2codepoint[x.group(1)]), text)

def getIcerocketFeedUrl(query):
    return 'http://www.icerocket.com/search?tab=twitter&q=%s&rss=1' % query

def formatQuery(query, nourl=False):
    if query:
        query = query[:-2]
    if not nourl:
        query = getIcerocketFeedUrl(query)
    return query

def getFeeds(channel, database, db, nourl=False):
    urls = []
    db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
    queries = db["feeds"].find({'database': database, 'channel': channel}, fields=['name', 'query'], sort=[('timestamp', pymongo.ASCENDING)])
    if database == "tweets":
        # create combined queries on Icerocket from search words retrieved in db
        query = ""
        for feed in queries:
            arg = str(feed['query'].encode('utf-8')).replace('@', 'from:')
            if not nourl:
                arg = "(%s)OR" % urllib.quote(arg, '')
            else:
                arg = " «%s»  | " % arg
            if len(query+arg) < 200:
                query += arg
            else:
                urls.append(formatQuery(query, nourl))
                query = arg
        if query != "":
            urls.append(formatQuery(query, nourl))
    else:
        if nourl:
            query = ""
            for feed in queries:
                query += " «%s»  | " % str(feed['name'].encode('utf-8'))
                if len(query) > 300:
                    urls.append(formatQuery(query, nourl))
                    query = ""
            if query != "":
                urls.append(formatQuery(query, nourl))
        else:
            urls = [str(feed['query']) for feed in queries]
    return urls

re_arg_page = re.compile(r'&p=(\d+)', re.I)
def next_page(url):
    p = 1
    res = re_arg_page.search(url)
    if res:
        p = int(res.group(1))
        url = re_arg_page.sub('', url)
    p += 1
    return "%s&p=%s" % (url, p)

def safeint(n):
    try:
        return int(n.strip())
    except:
        return 0

def chanconf(chan, conf=None):
    if conf:
        return conf
    if chan:
        chan = chan.lstrip('#')
    try:
        return config.CHANNELS[chan]
    except:
        return None

def chan_has_protocol(chan, protocol, conf=None):
    protocol = protocol.upper()
    if protocol == "IDENTICA":
        return chan_has_identica(chan, conf)
    elif protocol == "TWITTER":
        return chan_has_twitter(chan, conf)
    return False

def chan_has_identica(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'IDENTICA' in conf and 'USER' in conf['IDENTICA'] and 'PASS' in conf['IDENTICA']

def chan_has_twitter(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'TWITTER' in conf and 'KEY' in conf['TWITTER'] and 'SECRET' in conf['TWITTER'] and 'OAUTH_TOKEN' in conf['TWITTER'] and 'OAUTH_SECRET' in conf['TWITTER']

def chan_displays_rt(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'DISPLAY_RT' in conf and conf['DISPLAY_RT']

def chan_displays_my_rt(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'TWITTER' in conf and 'DISPLAY_RT' in conf['TWITTER'] and conf['TWITTER']['DISPLAY_RT']

def is_user_admin(nick):
    return nick in config.ADMINS

def is_user_global(nick):
    return nick in config.GLOBAL_USERS

def is_user_auth(nick, channel, conf=None):
    conf = chanconf(channel, conf)
    return conf and (is_user_global(nick) or is_user_admin(nick) or ('USERS' in conf and nick in conf['USERS']))

def has_user_rights_in_doc(nick, channel, command_doc, conf=None):
    if command_doc is None:
        return True if is_user_admin(nick) else False
    conf = chanconf(channel, conf)
    auth = is_user_auth(nick, channel, conf)
    if command_doc.endswith('/TWITTER'):
        return auth and ((chan_has_identica(channel, conf) and 'identi.ca' in command_doc.lower()) or (chan_has_twitter(channel, conf) and 'twitter' in clean_doc(command_doc).lower()))
    if auth:
        return True
    if command_doc.endswith('/AUTH') or command_doc.endswith('/TWITTER'):
        return False
    return True

timestamp_hour = lambda date : date - timedelta(minutes=date.minute, seconds=date.second, microseconds=date.microsecond)

def print_stats(db, user):
    now = timestamp_hour(datetime.today())
    since = now - timedelta(days=30)
    db.authenticate(config.MONGODB['USER'], config.MONGODB['PSWD'])
    stats = db['stats'].find({'user': user, 'timestamp': {'$gte': since}}, sort=[('timestamp', pymongo.DESCENDING)])
    if not stats.count():
        return "%s %s %s" % (user, now, since)
    stat = stats[0]
    rts = 0
    fols = 0
    twts = 0
    delays = {1: 'hour', 6: '6 hours', 24: 'day', 7*24: 'week', 30*24: 'month'}
    order = delays.keys()
    order.sort()
    olds = {'tweets': {}, 'followers': {}, 'rts': {}}
    for s in stats:
        d = now - s['timestamp']
        delay = d.seconds / 3600 + d.days * 24
        fols = stat['followers'] - s['followers']
        twts = stat['tweets'] - s['tweets']
        for i in order:
            if delay == i:
                if 'stats%sH' % i not in olds['tweets']:
                    olds['tweets']['stats%sH' % i] = twts if twts not in olds['tweets'].values() else 0
                if 'stats%sH' % i not in olds['followers']:
                    olds['followers']['stats%sH' % i] = fols if fols not in olds['followers'].values() else 0
                if 'stats%sH' % i not in olds['rts']:
                    olds['rts']['stats%sH' % i] = rts if rts not in olds['rts'].values() else 0
        rts += s['rts_last_hour']
    olds['rts']['stats1H'] = stat['rts_last_hour']
    for i in order:
        if rts and 'stats%sH' % i not in olds['rts'] and rts not in olds['rts'].values():
            olds['rts']['stats%sH' % i] = rts
            rts = 0
        if fols and 'stats%sH' % i not in olds['followers']  and fols not in olds['followers'].values():
            olds['followers']['stats%sH' % i] = fols
            fols = 0
        if twts and 'stats%sH' % i not in olds['tweets'] and twts not in olds['tweets'].values():
            olds['tweets']['stats%sH' % i] = twts
            twts = 0
    res = []
    res.append("Tweets: %d total" % stat['tweets'] + " ; ".join([""]+["%d last %s" %  (olds['tweets']['stats%sH' % i], delays[i]) for i in order if 'stats%sH' % i in olds['tweets'] and olds['tweets']['stats%sH' % i]]))
    res.append("Followers: %d total" % stat['followers'] + " ; ".join([""]+["%+d last %s" %  (olds['followers']['stats%sH' % i], delays[i]) for i in order if 'stats%sH' % i in olds['followers'] and olds['followers']['stats%sH' % i]]))
    res.append("RTs: " + " ; ".join(["%d last %s" % (olds['rts']['stats%sH' % i], delays[i]) for i in order if 'stats%sH' % i in olds['rts'] and olds['rts']['stats%sH' % i]]))
    return [(True, "[Stats] %s" % m) for m in res]

