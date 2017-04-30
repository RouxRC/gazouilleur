#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, re, time
from hashlib import sha512
from gazouilleur.lib.templater import Templater

# TODO:
# - handle error pages
# - handle redirects
# - store screenshot via manet

class WebMonitor(Templater):

    def __init__(self, name, url):
        Templater.__init__(self)
        self.name = name
        self.url = url
        basedir = os.path.join('web', 'monitor')
        self.path = os.path.join(basedir, name)
        if not os.path.exists(basedir):
            os.makedirs(basedir)
            os.chmod(basedir, 0o755)
        if not os.path.exists(self.path):
            os.makedirs(self.path)
            os.chmod(self.path, 0o755)
        self.versions = self.get_versions()

    def get_versions(self):
        files = os.listdir(os.path.join('web', 'monitor', self.name))
        versions = [f.replace(".html", "") for f in files if f.endswith(".html")]
        return sorted(versions)

    def get_last(self):
        if self.versions:
            return self.versions[-1]
        return None

    def get_file(self, version, ftype):
        return os.path.join(self.path, "%s.%s" % (version, ftype))

    def add_version(self, data):
        version = time.strftime("%y%m%d-%H%M")
        for ftype in data:
            name = self.get_file(version, ftype)
            with open(name, "w") as f:
                f.write(data[ftype])
            os.chmod(name, 0o644)
        self.versions.append(version)

    def check_new(self, page):
        new = {
            "html": absolutize_links(self.url, page),
            "links": "\n".join(extract_links(page)),
            "txt": extract_raw_text(page)
        }
        last = self.get_last()
        if not last:
            self.add_version(new)
            return
        with open(self.get_file(last, "links")) as f:
            lastlinks = f.read()
        with open(self.get_file(last, "txt")) as f:
            lasttext = f.read()
        if differ(lastlinks, new["links"]) or differ(lasttext, new["txt"]):
            self.add_version(new)
            msg = "Looks like the monitored page %s at %s just changed!" % (self.name, self.url)
            if self.public_url:
                self.build_diff_page()
                msg += "\nYou can check the different versions and diffs at %smonitor_%s.html" % (self.public_url, self.name)
            return msg

    def build_diff_page(self):
        data = {
          "name": self.name,
          "url": self.url,
        }
        data["versions"] = sorted(self.versions, reverse=True)
        self.render_template("monitor.html", self.name, data)

re_abslink = re.compile(r'(src|href)="((https?:)?//)', re.I)
re_rootlink = re.compile(r'(src|href)="/', re.I)
re_rellink = re.compile(r'(src|href)="', re.I)
def absolutize_link(link, host, folder):
    if re_abslink.search(link):
        return link
    if re_rootlink.search(link):
        return re_rootlink.sub(r'\1="' + host + '/', link)
    return re_rellink.sub(r'\1="' + folder + '/', link)

re_host = re.compile(r'^(https?://[^/]+)/?.*$', re.I)
re_folder = re.compile(r'^(.*?)(/[^/]*)?$', re.I)
re_css = re.compile(r'<link (?:[^>]*(?:rel="stylesheet"|type="text/css") [^>]*href="[^"]+"|href="[^"]+"[^>]* (?:rel="stylesheet"|type="text/css"))[^>]*>', re.I)
re_link = re.compile(r'<(?:a|img|script) [^>]*(?:src|href)="[^"]+"[^>]*>', re.I)
def absolutize_links(url, html):
    html2 = html
    host = re_host.sub(r'\1', url)
    folder = re_folder.sub(r'\1', url)
    for regexp in re_css, re_link:
        for link in regexp.findall(html):
            html2 = html2.replace(link, absolutize_link(link, host, folder))
    return html2

def extract_raw_text(html):
    # TODO
    return html

def extract_links(html):
    # TODO
    return []

sha = lambda text: sha512(text).digest()
differ = lambda old, new: len(old) != len(new) or sha(old) != sha(new)

