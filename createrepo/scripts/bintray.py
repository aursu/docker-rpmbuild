#!/usr/bin/python
# pylint: disable=F0401

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import os
import sys
import string
import rpm
import rpmUtils, rpmUtils.transaction
from distutils.version import LooseVersion
from optparse import OptionParser
import httplib
import urllib2
import json
import hashlib

# global
debugmode = False
if 'BINTRAY_DEBUG' in os.environ:
    debugmode = True

def errorprint(msg):
    print >> sys.stderr, msg

class RPMPackage(object):

    package = None
    sha256 = None
    hdr = None

    def __init__(self, package):
        if os.path.isfile(package):
            self.package = package
            self.hdrFromPackage()
            self.__hash()

    def __hash(self):
        if self.package:
            sha256 = hashlib.sha256()
            with open(self.package, 'rb') as fp:
                for chunk in iter(lambda: fp.read(4096), b''):
                    sha256.update(chunk)
            self.sha256 = sha256.hexdigest()

    def hdrFromPackage(self):
        if self.package:
            ts = rpmUtils.transaction.initReadOnlyTransaction()
            try:
                self.hdr = rpmUtils.miscutils.hdrFromPackage(ts, self.package)
            except rpmUtils.RpmUtilsError, e:
                msg = "Error opening package %s: %s" % (self.package, str(e))
                errorprint(msg)
        return self.hdr

    def getPackageAttr(self, attr):
        if self.hdr:
            return self.hdr[attr]
        return None

    def path(self):
        return self.package

    def size(self):
        if self.package:
            return os.stat(self.package).st_size
        return None

    def filename(self):
        if self.package:
            return os.path.basename(self.package)
        return None

    def sha256sum(self):
        return self.sha256

    def name(self):
        return self.getPackageAttr(rpm.RPMTAG_NAME)

    def version(self):
        return self.getPackageAttr(rpm.RPMTAG_VERSION)

    def release(self):
        return self.getPackageAttr(rpm.RPMTAG_RELEASE)

    def dist(self):
        release = self.release()
        if release and '.' in release:
            # only CentOS (el) and Fedora (fc) supported
            s = release.split('.')
            f = filter(lambda x: len(x) > 2 and x[:2] in ['el', 'fc'], s)
            if len(f):
                # in case of el6_8, el6_3.1 etc
                return f[0].split('_')[0]
        return None

    def osname(self):
        dist = self.dist()
        if dist and dist[:2] == 'fc':
            return 'fedora'
        if dist and dist[:2] == 'el':
            return 'centos'
        return None

    def osmajor(self):
        dist = self.dist()
        if self.osname():
            try:
                return int(dist[2:])
            except ValueError:
                pass
        return None

    def arch(self):
        return self.getPackageAttr(rpm.RPMTAG_ARCH)

    def desc(self):
        return self.getPackageAttr(rpm.RPMTAG_DESCRIPTION)

    def url(self):
        return self.getPackageAttr(rpm.RPMTAG_URL)

class Bintray(object):

    username = None
    apikey = None
    curl = None
    package = None
    repo = None
    # list: list of files uploaded to Bintray for this package
    files = None
    # flag: True if package already exists on Bintray
    remote = None

    def __init__(self, username, apikey, repo = None):
        self.username = username
        self.apikey = apikey
        self.set_curl()
        self.set_repo(repo)

    def set_auth(self):
        auth_handler = urllib2.HTTPBasicAuthHandler()
        auth_handler.add_password(realm='Bintray API Realm',
                          uri='https://api.bintray.com',
                          user=self.username,
                          passwd=self.apikey)
        if self.curl:
            self.curl.add_handler(auth_handler)

    def set_method(self, req, method):
        if isinstance(req, urllib2.Request) and method:
            req.get_method = lambda: method
        return req

    def send(self, req, data = None, method = None):
        # we try to relogin only once
        attempts = 2
        # check if request is urllib2.Request
        if isinstance(req, basestring):
            req = urllib2.Request(req)
        # set MIME data
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        # set HTTP method if provided
        if method:
            req = self.set_method(req, method)
        # add POST data if provided
        if data:
            req.add_data(data)
        while attempts:
            try:
                return self.curl.open(req)
            except urllib2.HTTPError, e:
                if debugmode:
                    errorprint("URL: %s" % req.get_full_url())
                    errorprint("Method: %s" % req.get_method())
                    errorprint("Request Headers: %s" % req.header_items())
                    errorprint("Error Message: %s" % str(e))
                    errorprint("Error Headers: %s" % e.hdrs)
                if e.getcode() == 401:
                    self.set_curl()
                    attempts -= 1
                    continue
                raise e
            except urllib2.URLError as e:
                # DNS error could appear
                if 'Name or service not known' in str(e.reason):
                    self.set_curl()
                    attempts -= 1
                    continue
                elif 'EOF occurred in violation of protocol' in str(e.reason):
                    self.set_curl()
                    attempts -= 1
                    continue
                raise e
            except httplib.BadStatusLine:
                self.set_curl()
                attempts -= 1
                continue
            break

    def set_curl(self):
        self.curl = urllib2.build_opener()
        self.set_auth()

    def set_package(self, package):
        rpmpackage = RPMPackage(package)
        if rpmpackage.name():
            self.package = rpmpackage
            self.update_stats()

    def update_stats(self):
        if self.package:
            self.files = self.package_files()
            # sort it out
            if self.files:
                self.files.sort(key=lambda x: LooseVersion(x['name']))
            self.remote = self.files is not None

    def set_repo(self, repo):
        if self.check_repo(repo):
            self.repo = repo

    def check_repo(self, repo):
        if isinstance(repo, basestring) and repo:
            req = "https://api.bintray.com/repos/%(subject)s/%(repo)s" % {
                'subject': self.username,
                'repo': repo
            }
            resp = self.send(req)
            return resp.getcode() == 200
        return False

    def package_files(self):
        if self.repo and self.package:
            req = "https://api.bintray.com/packages/%(subject)s/%(repo)s/%(name)s/files" % {
                'subject': self.username,
                'repo': self.repo,
                'name': self.package.name()
            }
            try:
                resp = self.send(req)
            except urllib2.HTTPError, e:
                if e.code == 404:
                    if debugmode:
                        errorprint("Error: %s" % e.read())
                    # package was not found
                    return None
                raise e
            if resp.getcode() == 200:
                return json.load(resp)
        return None

    def check_package_exists(self):
        return self.remote

    def check_file_exists(self):
        if self.files:
            target = filter(lambda x: x['sha256'] == self.package.sha256sum(), self.files)
            return len(target) > 0
        return None

    def create_package(self, vcs_url, licenses = ['Apache-2.0', 'GPL-3.0']):
        if self.repo and self.package:
            req = "https://api.bintray.com/packages/%(subject)s/%(repo)s" % {
                'subject': self.username,
                'repo': self.repo
            }
            data = json.dumps({
                'name': self.package.name(),
                'desc': self.package.desc(),
                'website_url': self.package.url(),
                'licenses': licenses,
                'vcs_url': vcs_url
            })
            resp = self.send(req, data)
            if resp.getcode() == 201:
                self.update_stats()
                return True
        return None

    def delete_package(self):
        if self.repo and self.package:
            req = "https://api.bintray.com/packages/%(subject)s/%(repo)s/%(name)s" % {
                'subject': self.username,
                'repo': self.repo,
                'name': self.package.name()
            }
            resp = self.send(req, method='DELETE')
            if resp.getcode() == 200:
                self.update_stats()
                return True
        return None

    def handle_upload_error(self, err):
        # conflict, package already exists
        if err.getcode() == 409:
            try:
                rawmsg = err.read()
            except httplib.IncompleteRead as e:
                rawmsg = e.partial
            if debugmode:
                errorprint("Error: %s" % rawmsg)
            try:
                msg = json.loads(rawmsg)
                if "message" in msg:
                    msg = msg["message"]
            except ValueError:
                msg = rawmsg
            errorprint("Conflict: %s" % msg)
            return False
        raise err

    def upload_content(self, repo_path = None):
        if self.repo and self.package:
            if repo_path is None:
                repo_path = "%(osname)s/%(osmajor)s" % {
                    'osname': self.package.osname(),
                    'osmajor': self.package.osmajor()
                }
            req = "https://api.bintray.com/content/%(subject)s/%(repo)s/%(path)s/%(filename)s" % {
                'subject': self.username,
                'repo': self.repo,
                'path': repo_path,
                'filename': self.package.filename()
            }
            with open(self.package.path(), 'rb') as fp:
                reqobj = urllib2.Request(req, data=fp.read(), headers={
                    'Content-Length': self.package.size(),
                    'X-Bintray-Package': self.package.name(),
                    'X-Bintray-Version': self.package.version(),
                    'X-Checksum-Sha2': self.package.sha256sum(),
                    'X-Bintray-Publish': '1'
                })
                try:
                    resp = self.send(reqobj, method='PUT')
                except urllib2.HTTPError, e:
                    return self.handle_upload_error(e)
                if resp.getcode() == 201:
                    self.update_stats()
                    return True
        return None


    # https://bintray.com/docs/api/#_delete_content
    # DELETE /content/:subject/:repo/:file_path
    def delete_content(self, file_path):
        if not self.files:
            return None
        check = filter(lambda x: x['path'] == file_path, self.files)
        if len(check) > 0:
            req = "https://api.bintray.com/content/%(subject)s/%(repo)s/%(file_path)s" % {
                'subject': self.username,
                'repo': self.repo,
                'file_path': file_path
            }
            resp = self.send(req, method='DELETE')
            if resp.getcode() == 200:
                self.update_stats()
                return True
        return False

    # not more than 2 packages (hardcoded) of the same version in repo
    def cleanup_packages(self):
        if not self.files:
            return None
        # filter by distribution
        dist = '.' + self.package.dist()
        arch = '.' + self.package.arch()
        distfiles = filter(lambda x: dist in x['name'] and arch in x['name'], self.files)
        # filter by version
        verfiles = filter(lambda x: x['version'] == self.package.version(), distfiles)
        cleanup = []
        if len(verfiles) > 2:
            cleanup = verfiles[:-2]
        status = False
        for p in cleanup:
            if self.delete_content(p['path']):
                status = True
        return status

    # https://bintray.com/docs/api/#_publish_discard_uploaded_content
    def deploy_rpm(self):
        if self.repo and self.package:
            req = "https://api.bintray.com/content/%(subject)s/%(repo)s/%(name)s/%(version)s/publish" % {
                'subject': self.username,
                'repo': self.repo,
                'name': self.package.name(),
                'version': self.package.version()
            }
            data = json.dumps({'discard': False})
            resp = self.send(req, data)
            return resp.getcode() == 201
        return None

def getFileList(path, ext, filelist):
    """Return all files in path matching ext, store them in filelist, recurse dirs
       return list object"""

    extlen = len(ext)
    try:
        dir_list = os.listdir(path)
    except OSError, e:
        errorprint('Error accessing directory %s, %s' % (path, str(e)))
        return []

    for d in dir_list:
        if os.path.isdir(path + '/' + d):
            filelist = getFileList(path + '/' + d, ext, filelist)
        else:
            if string.lower(d[-extlen:]) == '%s' % (ext):
                newpath = os.path.normpath(path + '/' + d)
                filelist.append(newpath)

    return filelist

def optparser():
    usage = "Usage: %prog [OPTION]... [FILE]..."

    parser = OptionParser(usage=usage)

    parser.add_option("-u", "--user",
                      metavar="USER",
                      dest="username",
                      help="Bintray username. If not set, environment "
                           "variable BINTRAY_USER is used for authentication.")
    parser.add_option("-k", "--key",
                      metavar="KEY",
                      dest="apikey",
                      help="Bintray API key. If not set, environment "
                           "variable BINTRAY_API_KEY is used for authentication.")
    parser.add_option("-r", "--repo",
                      help="Bintray repository name. If not set. environment "
                           "variable BINTRAY_REPO is used")
    parser.add_option("-v", "--vcs-url",
                      dest="vcs_url",
                      help="Package VCS URL. If not set. environment "
                           "variable PACKAGE_VCS_URL is used")
    parser.add_option("-l", "--licenses",
                      action="append",
                      dest="licenses",
                      default=['Apache-2.0', 'GPL-3.0'],
                      help="Package licenses [default: %default]")
    parser.add_option("-p", "--repo-path",
                      dest="path",
                      help="Repository path (excluding package name) "
                           "[default: <os name>/<os major>]")
    parser.add_option("-d", "--delete",
                      action="store_true",
                      dest="delete",
                      default=False,
                      help="Delete package [default: %default]")
    parser.add_option("-c", "--cleanup",
                      action="store_true",
                      dest="cleanup",
                      default=False,
                      help="Cleanup packages (keep only 2 packages of "
                           "specified version) [default: %default]")
    return parser

def usage(parser = None, exit = False):
    if parser is None:
        parser = optparser()
    print parser.format_help()
    if exit:
        sys.exit(1)

def parseargs(parser = None):

    if parser is None:
        parser = optparser()

    (opts, args) = parser.parse_args()

    if not opts.username:
        if 'BINTRAY_USER' in os.environ and os.environ['BINTRAY_USER']:
            opts.ensure_value('username', os.environ['BINTRAY_USER'])
        else:
            errorprint('\nPass either --user or envirenmont variable BINTRAY_USER\n')
            usage(parser, exit=True)

    if not opts.apikey:
        if 'BINTRAY_API_KEY' in os.environ and os.environ['BINTRAY_API_KEY']:
            opts.ensure_value('apikey', os.environ['BINTRAY_API_KEY'])
        else:
            errorprint('\nPass either --key or envirenmont variable BINTRAY_API_KEY\n')
            usage(parser, exit=True)

    if not opts.repo:
        if 'BINTRAY_REPO' in os.environ and os.environ['BINTRAY_REPO']:
            opts.ensure_value('repo', os.environ['BINTRAY_REPO'])
        else:
            errorprint('\nPass either --repo or envirenmont variable  BINTRAY_REPO\n')
            usage(parser, exit=True)

    if not opts.vcs_url:
        if 'PACKAGE_VCS_URL' in os.environ and os.environ['PACKAGE_VCS_URL']:
            opts.ensure_value('vcs_url', os.environ['PACKAGE_VCS_URL'])
        else:
            errorprint('\nPass either --vcs-url or envirenmont variable PACKAGE_VCS_URL\n')
            usage(parser, exit=True)

    if len(args) < 1:
        errorprint('Error: Must specify a package(s) or directory to upload.')
        usage(parser, exit=True)

    return (opts, args)

def main():

    (opts, args) = parseargs()

    packages = []
    for p in args:
        if isinstance(p, basestring):
            if os.path.isfile(p) \
            and len(p) > 4 and p[-4:] == '.rpm':
                packages += [p]
            elif os.path.isdir(p):
                packages = getFileList(p, '.rpm', packages)

    bintray = Bintray(opts.username, opts.apikey, opts.repo)
    for p in packages:
        bintray.set_package(p)

        # delete package if --delete specified
        if opts.delete and bintray.check_package_exists():
            if bintray.delete_package():
                print "Package %s removed from Bintray repo %s" % \
                    (bintray.package.name(), bintray.repo)
                continue

        # check if package exist and create it if not
        if not bintray.check_package_exists():
            if bintray.create_package(opts.vcs_url, opts.licenses):
                print "Package %s added to Bintray repo %s" % \
                    (bintray.package.name(), bintray.repo)

        if not bintray.check_file_exists():
            if bintray.upload_content():
                print "Package %s uploaded into Bintray repo %s" % \
                    (bintray.package.filename(), bintray.repo)
        else:
            print "Package %s already exists in Bintray repo %s" % \
                (bintray.package.filename(), bintray.repo)

        if opts.cleanup:
            if bintray.cleanup_packages():
                print "Bintray repo %s has been cleaned up" % bintray.repo

if __name__ == "__main__":
    main()
