#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from codecs import open
from datetime import datetime
from gazouilleur.config import BOTNAME

class FileLogger:
    def __init__(self, channel=''):
        filename = BOTNAME
        if channel:
            filename += '_' + channel
        filename += '.log'
        if not os.path.isdir('log'):
            os.mkdir('log')
        self.file = open(os.path.join('log', filename), "a", encoding="utf-8")
        self.file_filtered = open(os.path.join('log', filename.replace('.log', '_filtered.log')), "a", encoding="utf-8")

    def log(self, message, filtered=False):
        if filtered:
            self.log_to_file(self.file_filtered, message)
        else:
            self.log_to_file(self.file, message)

    def log_to_file(self, file, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if not file.closed:
            file.write('%s %s\n' % (timestamp, message))
            file.flush()

    def close(self):
        self.file.close()
        self.file_filtered.close()
