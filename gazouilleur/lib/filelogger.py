#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from logging import getLogger, Formatter
from logging.handlers import RotatingFileHandler
from gazouilleur.config import BOTNAME
from gazouilleur.lib.log import logg

class FileLogger:

    def __init__(self, channel='private'):
        filename = BOTNAME
        if channel:
            filename += '_' + channel
        if not os.path.isdir('log'):
            os.mkdir('log')
        self.loggers = {}
        for name, suffix in [("normal", ""), ("filtered", "_filtered")]:
            f = str(os.path.join('log', "%s%s.log" % (filename, suffix)))
            self.loggers[name] = getLogger("%s%s" % (channel, suffix))
            self.loggers[name].addHandler(RotatingFileHandler(f, backupCount=1000, encoding="utf-8"))
            self.loggers[name].handlers[0].setFormatter(Formatter('%(asctime)s %(message)s', "%Y-%m-%d %H:%M:%S"))
            if os.path.isfile(f) and os.path.getsize(f) > 1024*1024:
                logg("Rolling log file %s" % f, color="yellow", action="LOGS", channel=(channel if channel != "private" else None))
                self.loggers[name].handlers[0].doRollover()

    def log(self, message, filtered=False):
        if filtered:
            self.loggers['filtered'].warn(message)
        else:
            self.loggers['normal'].warn(message)

    def close(self):
        for i in self.loggers:
            self.loggers[i].handlers[0].flush()
            self.loggers[i].handlers[0].close()
