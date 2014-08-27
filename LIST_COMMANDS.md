
# Default commands
 * Available to anyone
 * **Exclude regexp :** `'(help|test|chans|source)'`
 * **List :**

  + `help [<command>]`

     > Prints general help or help for specific &lt;command&gt;.

  + `test`

     > Simple test to check whether I'm present.

  + `chans`

     > Prints the list of all the channels I'm in.

  + `source`

     > Gives the link to my sourcecode.

# Logs Query commands
 * Available to anyone
 * **Exclude regexp :** `'(last(from|with|seen)?|.*more)'`
 * **List :**

  + `last [<N>] [--from <nick>] [--with <text>] [--chan <chan>|--allchans] [--skip <nb>] [--filtered|--nofilter]`

     > Prints the last or &lt;N&gt; (max 5) last message(s) from current or main channel if &lt;chan&gt; is not given, optionally starting back &lt;nb&gt; results earlier and filtered by user &lt;nick&gt; and by &lt;text&gt;. --nofilter includes tweets that were not displayed because of filters, --filtered searches only through these.

  + `lastfrom <nick> [<N>]`

     > Alias for "last --from", prints the last or &lt;N&gt; (max 5) last message(s) from user &lt;nick&gt; (options from "last" except --from can apply).

  + `lastwith <text> [<N>]`

     > Alias for "last --with", prints the last or &lt;N&gt; (max 5) last message(s) matching &lt;text&gt; (options from "last" can apply).

  + `lastmore [<N>]`

     > Prints 1 or &lt;N&gt; more result(s) (max 5) from previous "last" "lastwith" "lastfrom" or "lastcount" command (options from "last" except --skip can apply; --from and --with will reset --skip to 0).

  + `more [<N>]`

     > Alias for "lastmore". Prints 1 or &lt;N&gt; more result(s) (max 5) from previous "last" "lastwith" "lastfrom" or "lastcount" command (options from "last" except --skip can apply; --from and --with will reset --skip to 0).

  + `lastseen <nickname>`

     > Prints the last time &lt;nickname&gt; was seen logging in and out.

# Twitter counting commands
 * Available to anyone
 * **Exclude regexp :** `'.*count'`
 * **List :**

  + `count <text>`

     > Prints the character length of &lt;text&gt; (spaces will be trimmed, urls will be shortened to Twitter's t.co length).

  + `lastcount`

     > Prints the latest "count" command and its result (options from "last" except &lt;N&gt; can apply).

# Twitter &amp; Identi.ca sending commands
 * Twitter available when TWITTER's USER, KEY, SECRET, OAUTH_TOKEN and OAUTH_SECRET are provided in gazouilleur/config.py for the chan and FORBID_POST is not given or set to True.
 * Identi.ca available when IDENTICA's USER is provided in gazouilleur/config.py for the chan.
 * available to anyone if TWITTER's ALLOW_ALL is set to True, otherwise only to GLOBAL_USERS and chan's USERS
 * **Exclude regexp :** `'(identica|twit.*|answer.*|rt|(rm|last)+tweet|dm|finduser|stats)'`
 * **List :**

  + `lasttweet [<N>] [<options>]`

     > Prints the last or &lt;N&gt; last tweets sent with the channel's account (options from "last" except --from can apply).
     > > restricted to /TWITTER

  + `identica <text> [--nolimit]`

     > Posts &lt;text&gt; as a status on Identi.ca (--nolimit overrides the minimum 30 characters rule).
     > > restricted to /IDENTICA

  + `twitteronly <text> [--nolimit] [--force] [img:<url>]`

     > Posts &lt;text&gt; as a status on Twitter (--nolimit overrides the minimum 30 characters rule / --force overrides the restriction to mentions users I couldn't find on Twitter).
     > > restricted to /IDENTICA

  + `twitter <text> [--nolimit] [--force] [img:<url>]`

     > Posts &lt;text&gt; as a status on Identi.ca and on Twitter (--nolimit overrides the minimum 30 characters rule / --force overrides the restriction to mentions users I couldn't find on Twitter). Add an image with img:&lt;url&gt; as with command twitpic.
     > > restricted to /TWITTER

  + `twitpic <text> <img url> [--nolimit] [--force]`

     > Posts &lt;text&gt; with a tweetpic of the image at &lt;img url&gt; as a status on Twitter (options --nolimit and --force from command twitter apply).
     > > restricted to /TWITTER

  + `answer <tweet_id> <@author text> [--nolimit] [--force] [img:<url>]`

     > Posts &lt;text&gt; as a status on Identi.ca and as a response to &lt;tweet_id&gt; on Twitter. &lt;text&gt; must include the @author of the tweet answered to except when answering myself. (--nolimit overrides the minimum 30 characters rule / --force overrides the restriction to mentions users I couldn't find on Twitter).
     > > restricted to /TWITTER

  + `answerpic <tweet_id> <@author text> <img url> [--nolimit] [--force]`

     > Posts &lt;text&gt; with a tweetpic of the image at &lt;img url&gt; as a response to &lt;tweet_id&gt; on Twitter (same rules and options from command answer apply).
     > > restricted to /TWITTER

  + `answerlast <text> [--nolimit] [--force]`

     > Send &lt;text&gt; as a tweet in answer to the last tweet sent to Twitter from the channel.
     > > restricted to /TWITTER

  + `rt <tweet_id>`

     > Retweets &lt;tweet_id&gt; on Twitter and posts a ♻ status on Identi.ca.
     > > restricted to /TWITTER

  + `rmtweet <tweet_id>`

     > Deletes &lt;tweet_id&gt; from Twitter.
     > > restricted to /TWITTER

  + `rmlasttweet`

     > Deletes last tweet sent to Twitter from the channel.
     > > restricted to /TWITTER

  + `dm <user> <text> [--nolimit]`

     > Posts &lt;text&gt; as a direct message to &lt;user&gt; on Twitter (--nolimit overrides the minimum 30 characters rule).
     > > restricted to /TWITTER

  + `finduser <query> [<N=3>]`

     > Searches &lt;query&gt;through Twitter User and returns &lt;N&gt; results (defaults 3, max 20).
     > > restricted to /TWITTER

  + `show <tweet_id|@twitter_user>`

     > Displays message and info on tweet with id &lt;tweet_id&gt; or on user &lt;@twitter_user&gt;.

  + `stats`

     > Prints stats on the Twitter account set for the channel.
     > > restricted to /TWITTER

# Twitter &amp; RSS Feeds monitoring commands
 * (Un)Follow and (Un)Filter available only to GLOBAL_USERS and chan's USERS
 * Others available to anyone
 * **Exclude regexp :** `'(u?n?f(ollow|ilter)|list|newsurl|last(tweet|news))'`
 * **List :**

  + `follow <name url|text|@user>`

     > Asks me to follow and display elements from a RSS named &lt;name&gt; at &lt;url&gt;, or tweets matching &lt;text&gt; or from &lt;@user&gt;.
     > > restricted to /AUTH

  + `unfollow <name|text|@user>`

     > Asks me to stop following and displaying elements from a RSS named &lt;name&gt;, or tweets matching &lt;text&gt; or from &lt;@user&gt;.
     > > restricted to /AUTH

  + `filter <word|@user>`

     > Filters the display of tweets or news containing &lt;word&gt; or sent by user &lt;@user&gt;.
     > > restricted to /AUTH

  + `unfilter <word|@user>`

     > Removes a tweets display filter for &lt;word&gt; or &lt;@user&gt;.
     > > restricted to /AUTH

  + `list [--chan <channel>] <tweets|news|filters>`

     > Displays the list of filters or news or tweets queries followed for current channel or optional &lt;channel&gt;.

  + `newsurl <name>`

     > Displays the url of a RSS feed saved as &lt;name&gt; for current channel.

  + `tweetswith <match>`

     > Prints the total number of tweets seen matching &lt;match&gt; and the first one seen.

  + `lasttweets [<N>] [<options>]`

     > Prints the last or &lt;N&gt; last tweets displayed on the chan (options from "last" except --from can apply).

  + `lastnews [<N>] [<options>]`

     > Prints the last or &lt;N&gt; last news displayed on the chan (options from "last" except --from can apply).

# Ping commands
 * Available only to GLOBAL_USERS and chan's USERS except for NoPing to anyone
 * **Exclude regexp :** `'.*ping.*'`
 * **List :**

  + `ping [<text>]`

     > Pings all ops, admins, last 18h speakers and at most 5 more random users on the chan saying &lt;text&gt; except for users set with noping.
     > > restricted to /AUTH

  + `pingall [<text>]`

     > Pings all ops, admins and at most 50 more random users on the chan by saying &lt;text&gt; except for users set with noping.
     > > restricted to /AUTH

  + `pingteam [<text>]`

     > Pings all ops and admins on the chan by saying &lt;text&gt; except for users set with noping.
     > > restricted to /AUTH

  + `noping <user1> [<user2> [<userN>...]] [--stop] [--list]`

     > Deactivates pings from ping command for &lt;users 1 to N&gt; listed. With --stop, reactivates pings for those users. With --list just gives the list of deactivated users.

# Tasks commands
 * RunLater available to anyone
 * Cancel &amp; Tasks available only to GLOBAL_USERS and chan's USERS
 * **Exclude regexp :** `'(runlater|tasks|cancel)'`
 * **List :**

  + `runlater <minutes> [--chan <channel>] <command [arguments]>`

     > Schedules &lt;command&gt; in &lt;minutes&gt; for current channel or optional &lt;channel&gt;.

  + `tasks [--chan <channel>]`

     > Prints the list of coming tasks scheduled for current channel or optional &lt;channel&gt;.
     > > restricted to /AUTH

  + `cancel [--chan <channel>] <task_id>`

     > Cancels the scheduled task &lt;task_id&gt; for current channel or optional &lt;channel&gt;.
     > > restricted to /AUTH

# Other commands...
 * Pad &amp; Title available to anyone
 * FuckOff/ComeBack &amp; SetPad available only to GLOBAL_USERS and chan's USERS
 * **Exclude regexp :** `'(fuckoff|comeback|.*pad|title)'`
 * **List :**

  + `fuckoff [<N>]`

     > Tells me to shut up for the next &lt;N&gt; minutes (defaults to 5).
     > > restricted to /AUTH

  + `comeback`

     > Tells me to start talking again after use of "fuckoff".
     > > restricted to /AUTH

  + `setpad <url>`

     > Defines &lt;url&gt; of the current etherpad.
     > > restricted to /AUTH

  + `pad`

     > Prints the url of the current etherpad.

  + `title <url>`

     > Prints the title of the webpage at &lt;url&gt;.

# Admin commands
 * AddAuth available only to GLOBAL_USERS and  chan's USERS
 * Restart available only to GLOBAL_USERS
 * **Exclude regexp :** `'(addauth|restart)'`
 * **List :**

  + `addauth <user>`

     > Gives auth rights to &lt;user&gt; until next reboot.
     > > restricted to /AUTH

  + `restart`

     > Tries to reboot me.
     > > restricted to /ADMIN
