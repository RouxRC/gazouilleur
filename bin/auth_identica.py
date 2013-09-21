#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, datetime
try:
    from pypump import PyPump
except ImportError:
    sys.stderr.write("ERROR: Could not load module PyPump.\nERROR: Please run this command from gazouilleur's virtualenv:\n  source /usr/local/bin/virtualenvwrapper.sh\n  workon gazouilleur\n  python bin/auth_identica.py\n  deactivate\nERROR: Otherwise check your install or run `pip install -r requirements.txt` from gazouilleur's virtualenv.\n")
    exit(1)
try:
    from gazouilleur import config
except ImportError:
    sys.stderr.write("ERROR: Could not find `gazouilleur/config.py`.\nERROR: Please run `b ash bin/configure.sh` to create it, then edit it to prepare your bot.\n")
    exit(1)
except SyntaxError as e:
    import traceback
    _, _, exc_traceback = sys.exc_info()
    sys.stderr.write("ERROR: Could not read `gazouilleur/config.py`.\nERROR: Please edit it to fix the following syntax issue:\nERROR: %s\n%s\n" % (e, "\n".join(traceback.format_exc().splitlines()[-3:-1])))
    exit(1)

confs = []
for chan, conf in config.CHANNELS.iteritems():
    if 'IDENTICA' in conf and 'USER' in conf['IDENTICA']:
        user = conf['IDENTICA']['USER'].lower()
        print "Configuring Identi.ca OAuth for @%s for channel %s..." % (user, chan)
        print "Please make sure to be not logged in on Identi.ca with another account than this one in your browser before clicking the authorize url."
        try:
            pump = PyPump("%s@identi.ca", client_name="Gazouilleur")
            client_credentials = pump.get_registration()
            client_tokens = pump.get_token()
            confs.append('"%s": {"key": "%s", "secret": "%s", "token": "%s", "token_secret": "%s"}' % (user, client_credentials[0], client_credentials[1], client_tokens[0], client_tokens[1]))
        except Exception as e:
            print "Could not properly get Identi.ca OAuth credits for user @%s:" % user
            print e

if confs:
    with open('gazouilleur/identica_auth_config.py', 'w') as conf_file:
        conf_file.write("""#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file was generated automatically by `python bin/auth_identica.py` on %s
# Do not modify unless you are sure of what you are doing.
identica_auth={%s}""" % (datetime.datetime.today(), ", ".join(confs)))

