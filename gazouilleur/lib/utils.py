#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re, urllib, hashlib, exceptions
from datetime import timedelta
import htmlentitydefs
from twisted.internet import defer, reactor
from twisted.internet.error import DNSLookupError
from twisted.internet.task import deferLater
from gazouilleur.lib.resolver import ResolverAgent
from gazouilleur import config
from gazouilleur.lib.irccolors import ColorConf
from gazouilleur.lib.mongo import sortasc
from gazouilleur.lib.log import loggerr

COMMAND_CHARACTER = [config.COMMAND_CHARACTER[i] for i in range(len(config.COMMAND_CHARACTER))] if type(config.COMMAND_CHARACTER) is str and len(config.COMMAND_CHARACTER) > 1 else config.COMMAND_CHARACTER
COMMAND_CHARACTER = COMMAND_CHARACTER[0] if type(COMMAND_CHARACTER) is list and len(COMMAND_CHARACTER) == 1 else COMMAND_CHARACTER

COMMAND_CHAR_DEF = COMMAND_CHARACTER if type(COMMAND_CHARACTER) is str else COMMAND_CHARACTER[0]
COMMAND_CHAR_STR = COMMAND_CHARACTER if type(COMMAND_CHARACTER) is str else ''.join(COMMAND_CHARACTER)
COMMAND_CHAR_REG = COMMAND_CHARACTER if type(COMMAND_CHARACTER) is str else '['+''.join(COMMAND_CHARACTER)+']'

def startsWithCommandChar(message):
    if type(COMMAND_CHARACTER) is str:
        return message.startswith(COMMAND_CHARACTER)
    for char in COMMAND_CHARACTER:
        if message.startswith(char):
            return True
    return False


SPACES = ur'[  \s\t\u0020\u00A0\u1680\u180E\u2000-\u200F\u2028-\u202F\u205F\u2060\u3000]'
re_clean_blanks = re.compile(r'%s+' % SPACES)
cleanblanks = lambda x: re_clean_blanks.sub(r' ', x.strip()).strip()

re_shortdate = re.compile(r'^....-(..)-(..)( ..:..).*$')
shortdate = lambda x: re_shortdate.sub(r'\2/\1\3', str(x))

re_leftacc = re.compile(r'(\{)([^\}]*)$')
re_righacc = re.compile(r'^([^\{]*)(\})')
re_leftbrk = re.compile(r'(\[)([^\]]*)$')
re_righbrk = re.compile(r'^([^\[]*)(\])')
def clean_regexp(text):
    return re_leftacc.sub(r'\\\1\2', re_leftbrk.sub(r'\\\1\2', re_righacc.sub(r'\1\\\2', re_righbrk.sub(r'\1\\\2', text))))

re_clean_doc = re.compile(r'\.?\s*/[^/]+$')
clean_doc = lambda x: re_clean_doc.sub('.', x).strip()

re_clean_html = re.compile(r'<[^>]*>')
clean_html = lambda x: re_clean_html.sub('', x)

re_clean_identica = re.compile(r'(and posts a ♻ status)? on Identi\.ca( and)?( as a)?', re.I)
clean_identica = lambda x: re_clean_identica.sub('', x)

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
DOMAIN_CHARS = ur'(?:[^\&=\s_\!\.\/]+\.)+[a-z]{2,4}(?::[0-9]+)?'
PATH_CHARS = ur'(?:\([^\)]*\)|[\.,]?[%s!\*\';:=\+\$/%s#\[\]\-_,~@])' % (UTF_CHARS, '%')
QUERY_CHARS = ur'(?:\([^\)]*\)|[a-z0-9!\*\';:&=\+\$/%#\[\]\-_\.,~])'
PATH_ENDING_CHARS = ur'[%s=#/]' % UTF_CHARS
QUERY_ENDING_CHARS = '[a-z0-9_&=#]'
URL_REGEX = re.compile('(?=((%s+)((?:http(s)?://|www\\.)?%s(?:\/%s*%s?)?(?:\?%s*%s)?)(%s)))' % (PRE_CHARS, DOMAIN_CHARS, PATH_CHARS, PATH_ENDING_CHARS, QUERY_CHARS, QUERY_ENDING_CHARS, PRE_CHARS), re.I)

ACCENTS = "àÀâÂçÇéÉèÈêÊëËîÎïÏôÔöÖûÛüÜ"
ACCENTS_URL = re.compile(r'^\w*[%s]' % ACCENTS)

def _shorten_url(text, twitter_url_length):
    tco_extra = "x" * (twitter_url_length - 13)
    for res in URL_REGEX.findall(text):
        if ACCENTS_URL.match(res[2]) or "@" in res[2] and not res[2].startswith('http'):
            continue
        text = text.replace(res[0], '%shttp%s___t_co_%s%s' % (res[1], res[3], tco_extra, res[4]))
    return text

re_clean_twitter_command = re.compile(r'^\s*((%s(count|identica|(twitt?|answ)(er|only|last|pic)*)|\d{14}\d*|%sdm\s+@?[a-z0-9_]*)\s*)+' % (COMMAND_CHAR_REG, COMMAND_CHAR_REG), re.I)
def countchars(text, twitter_url_length):
    return len(_shorten_url(_shorten_url(re_clean_twitter_command.sub('', text.decode('utf-8').strip()).strip(), twitter_url_length), twitter_url_length).replace(' --nolimit', '').replace(' --force', ''))

re_clean_url1 = re.compile(r'/#!/')
re_clean_url2 = re.compile(r'((\?|&)((utm_(term|medium|source|campaign|content)|xtor|ei)=[^&#]*))', re.I)
re_clean_url3 = re.compile(ur'(%s|%s|[\.…<>:?!=)])+$' % (SPACES, QUOTE_CHARS))
def clean_url(url, url0, cache_urls):
    url = re_clean_url1.sub('/', url)
    for i in re_clean_url2.findall(url):
        if i[1] == "?":
            url = url.replace(i[2], '')
        else:
            url = url.replace(i[0], '')
    url = re_clean_url3.sub('', url)
    cache_urls[url0] = url
    return url, cache_urls

@defer.inlineCallbacks
def _clean_redir_urls(text, cache_urls, last=False):
    for res in URL_REGEX.findall(text):
        url00 = res[2].encode('utf-8')
        url0 = url00
        if not url00.startswith('http'):
            if "@" in url00 or url00.startswith('#'):
                continue
            url0 = "http://%s" % url00
        if url0.startswith('http://t.co/') and url0[-1] in ".,:\"'":
            url0 = url0[:-1]
        if url0 in cache_urls:
            url1 = cache_urls[url0]
            if url1 == url0:
                continue
        else:
            try:
                agent = ResolverAgent(url0)
                yield agent.resolve()
                url1, cache_urls = clean_url(agent.lastURI, url0, cache_urls)
            except DNSLookupError:
                if url00.startswith('http'):
                    url1, cache_urls = clean_url(agent.lastURI, url0, cache_urls)
                else:
                    url1 = url00
                    cache_urls[url0] = url00
            except Exception as e:
                if config.DEBUG and last and url00.startswith('http'):
                    loggerr("%s trying to resolve %s : %s" % (type(e), url0, e), action="utils")
                if "403" in str(e) or "Error 30" in str(e):
                    cache_urls[url0] = url00
                url1 = url00
        if not last and url1 != url00 and not re_shorteners.search(url1):
            url1 = url1.replace('http', '##HTTP##')
        try:
            url1 = url1.decode('utf-8')
            text = text.replace(res[0], '%s%s%s' % (res[1], url1, res[4]))
        except:
            if config.DEBUG:
                loggerr("encoding %s" % url1, action="utils")
    if last:
        text = text.replace('##HTTP##', 'http')
    defer.returnValue((text, cache_urls))

re_shorteners = re.compile(r'://[a-z0-9\-]{1,8}\.[a-z]{2,3}/[^/\s]+(\s|$)', re.I)
re_clean_bad_quotes = re.compile(r'(://[^\s”“]+)[”“]+"*(\s|$)')
re_clean_google_news = re.compile(r'^https?://[^/]*.google.com/(?:.*url=)?(https?://)', re.I)
@defer.inlineCallbacks
def clean_redir_urls(text, cache_urls):
    try:
        text = re_clean_bad_quotes.sub(r'\1"\2', text.encode('utf-8')).decode('utf-8')
    except (exceptions.UnicodeDecodeError, exceptions.UnicodeEncodeError):
        pass
    if re_shorteners.search(text):
        text, cache_urls = yield _clean_redir_urls(text, cache_urls)
    text, cache_urls = yield _clean_redir_urls(text, cache_urls, True)
    text = re_clean_google_news.sub(r'\1', text)
    defer.returnValue((text, cache_urls))

def get_hash(url):
    hash = hashlib.md5(url)
    return hash.hexdigest()

re_uniq_rt_hash = re.compile(r'([MLR]T|%s)+\s*@[a-zA-Z0-9_]{1,15}[: ,]*' % QUOTE_CHARS)
re_clean_spec_chars = re.compile(r'(%s|[-_.,;:?!<>(){}[\]/\\~^+=|#@&$%s%s])+' % (QUOTE_CHARS, '%', '…'.decode('utf-8')))
def uniq_rt_hash(text):
    text = re_uniq_rt_hash.sub(' ', text)
    text = re_clean_spec_chars.sub(' ', text)
    text = cleanblanks(text)
    return get_hash(text.encode('utf-8'))

re_entities = re.compile(r'&([^;]+);')
def unescape_html(text):
    return re_entities.sub(lambda x: unichr(int(x.group(1)[1:])) if x.group(1).startswith('#') else unichr(htmlentitydefs.name2codepoint[x.group(1)]), text)

def getTopsyFeedUrl(query):
    return 'http://topsy.com/s/%s/tweet?order=date&window=realtime' % query

def getIcerocketFeedUrl(query, rss=False):
    rss_arg = "&rss=1" if rss else "";
    return 'http://www.icerocket.com/search?tab=twitter&q=%s%s' % (query, rss_arg)

def assembleResults(results, limit=300):
    assemble = []
    line = ""
    for result in results:
        line += " «%s»  | " % str(result.encode('utf-8'))
        if len(line) > limit:
            assemble.append(formatQuery(line, None))
            line = ""
    if line != "":
        assemble.append(formatQuery(line, None))
    return assemble

def formatQuery(query, add_url=None):
    if query:
        query = query[:-4]
    if add_url:
        if add_url.lower() == "icerocket":
            query = getIcerocketFeedUrl(query)
        elif add_url.lower() == "topsy":
            query = getTopsyFeedUrl(query)
    return query

@defer.inlineCallbacks
def getFeeds(db, channel, database, url_format=True, add_url=None, randorder=None):
    urls = []
    queries = yield db['feeds'].find({'database': database, 'channel': re.compile("^%s$" % channel, re.I)}, fields=['name', 'query'], filter=sortasc('timestamp'))
    if database == "tweets":
        # create combined queries on Icerocket/Topsy or the Twitter API from search words retrieved in db
        query = ""
        try:
            queries = [queries[i] for i in randorder]
        except:
            pass
        for feed in queries:
            # queries starting with @ should return only tweets from corresponding user
            arg = str(feed['query'].encode('utf-8')).replace('@', 'from:')
            rawrg = arg
            space = " OR "
            if url_format:
                if not arg.startswith('from:') and not arg.startswith('#'):
                   arg = "(%s)" % urllib.quote(arg, '')
                if add_url:
                    space = "+OR+"
                arg = "%s%s" % (arg, space)
            else:
                arg = " «%s»  | " % arg
            if " OR " in rawrg or " -" in rawrg:
                urls.append(formatQuery(arg, add_url))
            elif query.count(space) < 3:
                query += arg
            else:
                urls.append(formatQuery(query, add_url))
                query = arg
        if query != "":
            urls.append(formatQuery(query, add_url))
    else:
        if not url_format:
            urls = assembleResults([feed['name'] for feed in queries])
        else:
            urls = [str(feed['query']) for feed in queries]
    defer.returnValue(urls)

def deferredSleep(sleep=5):
    return deferLater(reactor, sleep, lambda : None)

re_arg_page = re.compile(r'&p=(\d+)', re.I)
def next_page(url):
    p = 1
    res = re_arg_page.search(url)
    if res:
        p = int(res.group(1))
        url = re_arg_page.sub('', url)
    p += 1
    return "%s&p=%s" % (url, p)

re_tweet_url = re.compile(r'twitter.com/([^/]+)/statuse?s?/(\d+)(\D.*)?$', re.I)
def safeint(n, twitter=False):
    try:
        if twitter:
            res = re_tweet_url.search(n)
            if res:
                n = res.group(2)
        return int(n.strip())
    except:
        return 0

def chanconf(chan, conf=None):
    if conf:
        return conf
    if chan:
        chan = "#"+chan.lower()
    while chan:
        try:
            return config.CHANNELS[chan]
        except:
            if chan.startswith("#"):
                chan = chan[1:]
            else:
                break
    return None

def get_master_chan(default=config.BOTNAME):
    for chan in config.CHANNELS:
        if "MASTER" in config.CHANNELS[chan] and config.CHANNELS[chan]["MASTER"]:
            return "#%s" % chan.lower()
    return default.lower()

def chan_is_verbose(chan, conf=None):
    conf = chanconf(chan, conf)
    return not conf or "DISCREET" not in conf or str(conf["DISCREET"]).lower() == "false"

def chan_color_conf(chan=None):
    try:
        colors = chanconf(chan)['FORMAT']
    except:
        try:
            colors = config.FORMAT
        except:
            colors = "default"
    return ColorConf(colors)

def chan_has_protocol(chan, protocol, conf=None):
    protocol = protocol.upper()
    if protocol == "IDENTICA":
        return chan_has_identica(chan, conf)
    elif protocol == "TWITTER":
        return chan_has_twitter(chan, conf)
    return False

def chan_has_identica(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'IDENTICA' in conf and 'USER' in conf['IDENTICA']

def chan_has_twitter(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'TWITTER' in conf and 'KEY' in conf['TWITTER'] and 'SECRET' in conf['TWITTER'] and 'OAUTH_TOKEN' in conf['TWITTER'] and 'OAUTH_SECRET' in conf['TWITTER'] and ('FORBID_POST' not in conf['TWITTER'] or str(conf['TWITTER']['FORBID_POST']).lower() != "true")

def get_chan_twitter_user(chan, conf=None):
    conf = chanconf(chan, conf)
    if conf and 'TWITTER' in conf and 'USER' in conf['TWITTER']:
        return conf['TWITTER']['USER'].lstrip("@")
    return ""

def chan_displays_stats(chan, conf=None):
    conf = chanconf(chan, conf)
    return chan_has_twitter(chan, conf) and ('DISPLAY_STATS' not in conf['TWITTER'] or str(conf['TWITTER']['DISPLAY_STATS']).lower() != 'false')

def chan_displays_rt(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'DISPLAY_RT' in conf and conf['DISPLAY_RT']

def chan_displays_my_rt(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'TWITTER' in conf and 'DISPLAY_RT' in conf['TWITTER'] and conf['TWITTER']['DISPLAY_RT']

def chan_allows_twitter_for_all(chan, conf=None):
    conf = chanconf(chan, conf)
    return conf and 'TWITTER' in conf and 'ALLOW_ALL' in conf['TWITTER'] and conf['TWITTER']['ALLOW_ALL']

def is_user_admin(nick):
    return nick in config.ADMINS

def is_user_auth(nick, channel, conf=None):
    conf = chanconf(channel, conf)
    return is_user_admin(nick) or nick in config.GLOBAL_USERS or (conf and 'USERS' in conf and nick in conf['USERS'])

def has_user_rights_in_doc(nick, channel, command, command_doc, conf=None):
    if channel.lower() == config.BOTNAME.lower():
        channel = get_master_chan()
    conf = chanconf(channel, conf)
    if conf and 'EXCLUDE_COMMANDS' in conf and command:
        for regexp in conf['EXCLUDE_COMMANDS']:
            if re.match(re.compile(r"^%s$" % regexp, re.I), command):
                return False
    if command_doc is None:
        return is_user_admin(nick)
    if command_doc.endswith('/ADMIN'):
        return is_user_admin(nick)
    auth = is_user_auth(nick, channel, conf) or is_user_auth(nick.rstrip("_1"), channel, conf)
    identica = chan_has_identica(channel, conf)
    twitter = chan_has_twitter(channel, conf)
    tw_rights = chan_allows_twitter_for_all(channel, conf) or auth
    if "/IDENTICA" in command_doc:
        if "/TWITTER" in command_doc:
            return identica and twitter and tw_rights
        return identica and tw_rights
    if "/TWITTER" in command_doc:
        return twitter and tw_rights
    if auth:
        return True
    if command_doc.endswith('/AUTH'):
        return False
    return True

timestamp_hour = lambda date : date - timedelta(minutes=date.minute, seconds=date.second, microseconds=date.microsecond)

def is_ssl(conf):
    return hasattr(conf, "SSL") and str(conf.SSL).lower() == "true"

