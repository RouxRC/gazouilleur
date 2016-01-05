#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, time
from gazouilleur.lib.templater import Templater

class WebMonitor(Templater):

    def __init__(self, name):
        Templater.__init__(self)
        self.name = name
        basedir = os.path.join('web', 'monitor')
        self.path = os.path.join(basedir, name)
        if not os.path.exists(basedir):
            os.makedirs(basedir)
            os.chmod(basedir, 0o755)
        if not os.path.exists(self.path):
            os.makedirs(self.path)
            os.chmod(self.path, 0o755)

    def check_diff(self, url, data):
        # TODO:
        # - handle error pages
        # - apply url_rewrite for '<[^>]*=['"]/([^/]|$)' et '<[^>]*=['"](!:http)'
        # - check if file -last exists
        # - if so diff md5 current/last
        # - check if exist and not diff
        if False:
            return None
        for name in ["last", time.strftime("%y%m%d-%H%M")]:
            fil = os.path.join(self.path, "%s.html" % name)
            with open(fil, "w") as f:
                f.write(data)
            os.chmod(fil, 0o644)
        msg = "Looks like the webpage %s at %s just changed!" % (self.name, url)
        if self.url:
            self.build_diff_page(url)
            msg += "\nYou can check the different versions and diffs at %smonitor_%s.html" % (self.url, self.name)
        return msg

    def build_diff_page(self, url):
        data = {
          "name": self.name,
          "url": url,
        }
        data["versions"] = sorted(os.listdir(os.path.join('web', 'monitor', self.name)), reverse=True)
        self.render_template("monitor.html", self.name, data)
