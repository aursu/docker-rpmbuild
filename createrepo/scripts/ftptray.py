#!/usr/bin/python
# pylint: disable=F0401

import socket
import sys
import os
import rpm
import rpmUtils, rpmUtils.transaction
from distutils.version import LooseVersion
import hashlib
from datetime import datetime
import string
from optparse import OptionParser

import ftplib
from ftplib import FTP

from urllib2 import Request

FTP_SIZE_OK  = 213
FTP_TRANS_OK = 226
FTP_AUTH_OK  = 230
FTP_OK       = 250
FTP_PWD_OK   = 257

# global
debugmode = False
if 'BINTRAY_DEBUG' in os.environ:
    debugmode = True

def errorprint(msg):
    print >> sys.stderr, msg

class FTPRequest(Request):
    lines = None

    def __init__(self, url, data=None, headers={},
                 origin_req_host=None, unverifiable=False):
        Request.__init__(self, url, data, headers, origin_req_host, unverifiable)
        self.get_type()
        self.type = 'ftp'
        self.get_host()
        if self.port is None:
            self.port = ftplib.FTP_PORT
        self.reset()

    def get_path(self):
        selector = self.get_selector()
        if selector[0] == '/':
            return selector[1:]
        return selector

    def set_method(self, method):
        self.get_method = lambda: method

    def add_line(self, line):
        self.lines += [line]

    def reset(self):
        self.lines = []

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

class FTPRPMPackage(object):

    package = None
    arch = None
    name = None
    version = None
    release = None
    osid = None
    dist = None
    relmaj = None
    relmin = None
    size = None
    user = None
    group = None
    created = None

    json = None

    def __init__(self, package):
        if ' ' in package:
            self.set_dirlist_entry(package)
        else:
            self.set_package(package)

    def set_package(self, package):
        self.package = None
        if isinstance(package, basestring) and package:
            # rpmbuild/RPMS/gawk-4.0.2-4.el7_3.1.x86_64.rpm -> gawk-4.0.2-4.el7_3.1.x86_64.rpm
            filename = package
            if '/' in package:
                filename = package.split('/')[-1]

            # "awscli-1.14.28-5.el7_5.1.noarch" , "rpm"
            # "ca-certificates-2018.2.22-70.0.el7_5.noarch", "rpm"
            __p_arch, ext = filename.rsplit(".", 1)
            if ext == 'rpm':
                # "awscli-1.14.28-5.el7_5.1", "noarch"
                # "ca-certificates-2018.2.22-70.0.el7_5", "noarch"
                __p_release, arch = __p_arch.rsplit(".", 1)

                if arch in ['noarch', 'i686', 'x86_64']:
                    self.arch = arch
                else:
                    # wrong arch or wrong package name
                    return None

                # "awscli", "1.14.28", "5.el7_5.1"
                # "ca-certificates", "2018.2.22", "70.0.el7_5"
                name, version, release = __p_release.rsplit("-", 2)

                if 'el' in release:
                    osid = 'el'
                elif 'fc' in release:
                    osid = 'fc'
                else:
                    # wrong OS identifier
                    return None

                dist = ".%s" % osid

                # "5.el7_5.1" -> "5", "7_5.1"
                # "70.0.el7_5" -> "70.0", "7_5"
                relmaj, distver = release.split(dist)
                relmin = None

                if "." in distver:
                    distver, relmin = distver.split(".", 1)

                dist = osid + distver

                # awscli-1.14.28-5.el7_5.1.noarch.rpm
                # ca-certificates-2018.2.22-70.0.el7_5.noarch.rpm
                self.package = package
                self.filename = filename
                self.name = name       # ca-certificates # awscli
                self.version = version # 2018.2.22       # 1.14.28
                self.release = release # 70.0.el7_5      # 5.el7_5.1
                self.osid = osid       # el              # el
                self.dist = dist       # el7_5           # el7_5
                self.relmaj = relmaj   # 70.0            # 5
                self.relmin = relmin   # None            # 1

    def set_size(self, size):
        try:
            self.size = int(size)
        except ValueError:
            self.size = None

    def get_path(self):
        return self.package

    def get_size(self):
        if self.package:
            return self.size
        return None

    def get_filename(self):
        if self.package:
            return self.filename
        return None

    def get_name(self):
        if self.package:
            return self.name

    def get_version(self):
        if self.package:
            return self.version

    def get_release(self):
        if self.package:
            return self.release

    def get_dist(self):
        if self.package:
            # in case of el6_8, el6_3 etc
            return  self.dist.split('_')[0]
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

    def get_arch(self):
        if self.package:
            return self.arch

    def set_dirlist_entry(self, entry):
        # -rw-r--r--   1 centos-8 centos   12185279 Oct  4 16:21 php-7.3.9-1.fc31.src.rpm
        if isinstance(entry, basestring) and entry:
            data = entry.split()
            # 7 - perms, links, user, group, size, date, filename
            if entry[0] == '-' and len(data) >= 7:
                package = data[-1]

                # check if RPM package name
                self.set_package(package)
                if self.package:
                    _perms, _links, user, group, size = data[:5]
                    self.user = user
                    self.group = group
                    self.set_size(size)

                    mtime = data[5:-1]
                    d1 = d2 = None

                    try:
                        # Oct  4 16:21
                        d1 = datetime.strptime(mtime, '%b %d %H:%M').replace(year=datetime.now().year)
                    except ValueError:
                        pass

                    try:
                        # Oct  7  2018
                        d2 = datetime.strptime(mtime, '%b %d %Y')
                    except ValueError:
                        pass

                    d = d1 or d2
                    if d:
                        self.created = d.isoformat()

    def to_json(self):
        # {
        #   u'name': u'httpd-2.4.41-1.el6.x86_64.rpm',
        #   u'package': u'httpd',
        #   u'created': u'2019-08-15T12:10:06.176Z',
        #   u'version': u'2.4.41',
        #   u'owner': u'aursu',
        #   u'path': u'centos/6/httpd-2.4.41-1.el6.x86_64.rpm',
        #   u'size': 983096
        # },
        self.json = None
        if self.package:
            self.json = { 'name': self.filename }
            self.json['path'] = self.package
            self.json['package'] = self.name
            if self.created:
                self.json['created'] = self.created
            self.json['version'] = self.version
            if self.user:
                self.json['owner'] = self.user
            if self.size:
                self.json['size'] = self.size
        return self.json

class Ftptray(object):
    hostname = None
    repo = None

    username = None
    password = None

    ftp = None
    status = None
    auth = None
    entrypoint = None

    package = None
    files = None
    remote = None

    # by initialisation Ftptray object we setup location (FTP host and RPM repository)
    def __init__(self, hostname, username, passwd = "", repo = "custom"):
        # connect to server
        self.set_ftp(hostname)
        self.set_auth(username, passwd)
        self.entrypoint = self.pwd()
        self.set_repo(repo)

    def set_ftp(self, hostname = None):
        if isinstance(hostname, basestring) and hostname:
            try:
                self.hostname = socket.gethostbyname(hostname)
            except socket.error, e:
                self.status = int(e.errno)
                msg = "gethostbyname(%s) [Errno %s] %s" % (hostname, e.errno, e.strerror)
                errorprint(msg)
        self.status = None
        if self.hostname:
            # close current connection if exist
            if self.ftp:
                self.ftp.close()
                self.ftp = None
            try:
                self.ftp = FTP(self.hostname)
                self.status = 0
            except socket.error, e:
                self.status = int(e.errno)
                msg = "FTP [Errno %s] %s" % (e.errno, e.strerror)
                errorprint(msg)
        self.set_auth()
        if self.status == FTP_AUTH_OK:
          self.entrypoint = self.pwd()

    def set_auth(self, username = None, passwd = None):
        if isinstance(username, basestring) and username:
            if isinstance(passwd, basestring):
                self.username = username
                self.password = passwd
        self.status = None
        self.auth = False
        if self.ftp and self.username and isinstance(self.password, basestring):
            try:
                status = self.ftp.login(self.username, self.password)
                status, _strerror = status.split(' ', 1)
                self.auth = True
            except ftplib.error_perm, e:
                status, strerror = e.message.split(' ', 1)
                msg = "login [Errno %s] %s" % (status, strerror)
                errorprint(msg)
            self.status = int(status)

    def pwd(self):
        curdir = None
        self.status = None
        if self.ftp:
            try:
                curdir = self.ftp.pwd()
                # 257 "<curdir>" is the current directory
                status = FTP_PWD_OK
            except ftplib.error_perm, e:
                status, strerror = e.message.split(' ', 1)
                msg = "pwd [Errno %s] %s" % (status, strerror)
                errorprint(msg)
            self.status = int(status)
        return curdir

    def cwd(self, path):
        self.status = None
        if self.ftp and isinstance(path, basestring) and path:
            try:
                self.ftp.cwd(path)
                # 250 CWD command successful
                status = FTP_OK
            except ftplib.error_perm, e:
                status, strerror = e.message.split(' ', 1)
                msg = "cwd [Errno %s] %s" % (status, strerror)
                errorprint(msg)
            self.status = int(status)

    # only for FTPRequest object (due to add_line callback)
    #
    # return: array of strings (each directory item per line)
    # return: None in case of error (and set status into according error code)
    def dir(self, req):
        if isinstance(req, basestring):
            req = FTPRequest(req)

        path = req.get_path()

        directory = None
        self.status = None
        if self.ftp and isinstance(path, basestring) and path:
            try:
                # lambda x: x - avoid printing output of command into stdout
                self.ftp.dir(path, req.add_line)
                directory = req.lines

                # 226 Transfer complete
                status = FTP_TRANS_OK
            except ftplib.error_temp, e:
                status, strerror = e.message.split(' ', 1)
                msg = "dir [Errno %s] %s" % (status, strerror)
                errorprint(msg)
            except ftplib.error_perm, e:
                status, strerror = e.message.split(' ', 1)
                msg = "dir [Errno %s] %s" % (status, strerror)
                errorprint(msg)
            self.status = int(status)
        return directory

    # return: File size in bytes (set status to 213)
    # return: None in case of error (set status code to according error code or
    #         unset it)
    def size(self, path):
        self.status = None
        size = None
        if self.ftp and isinstance(path, basestring) and path:
            # avoid error: 550 SIZE not allowed in ASCII mode
            self.ftp.voidcmd('TYPE I')
            try:
                size = self.ftp.size(path)
                # 213 <size>
                status = FTP_SIZE_OK
            except ftplib.error_perm, e:
                status, strerror = e.message.split(' ', 1)
                msg = "size [Errno %s] %s" % (status, strerror)
                errorprint(msg)
            self.status = int(status)
        return size

    def check(self, req):
        self.dir(req)
        return (self.status == FTP_TRANS_OK)

    def check_file(self, req):
        if isinstance(req, basestring):
            req = FTPRequest(req)

        path = req.get_path()

        if self.check(req) and self.size(path):
            return True

        return False

    def check_dir(self, req):
        if isinstance(req, basestring):
            req = FTPRequest(req)

        path = req.get_path()

        if self.check(req):
            self.cwd(path)

            if self.status == FTP_OK:
                self.cwd(self.entrypoint)
                return True

        return False

    def delete(self, path):
        self.status = None
        if self.ftp and isinstance(path, basestring) and path:
            try:
                self.ftp.delete(path)
                # 250 DELE command successful
                status = FTP_OK
            except ftplib.error_perm, e:
                status, strerror = e.message.split(' ', 1)
                msg = "delete [Errno %s] %s" % (status, strerror)
                errorprint(msg)
            self.status = int(status)

    def stor(self, req, fp):
        if isinstance(req, basestring):
            req = FTPRequest(req)

        path = req.get_path()
        cmd = "STOR %s" % path

        self.status = None
        if self.ftp and isinstance(path, basestring) and path:
            try:
                self.ftp.storbinary(cmd, fp)

                # 226 Transfer complete
                status = FTP_TRANS_OK
            except ftplib.error_perm, e:
                status, strerror = e.message.split(' ', 1)
                msg = "storbinary [Errno %s] %s" % (status, strerror)
                errorprint(msg)
            self.status = int(status)

    def check_repo(self, repo):
        if isinstance(repo, basestring) and repo:
            if repo == "custom":
                repo = "RPMS"
            req = "ftp://%(hostname)s/rpmbuild/%(repo)s" % {
                'hostname': self.hostname,
                'repo': repo
            }
            return self.check_dir(req)
        return False

    def set_repo(self, repo):
        if self.check_repo(repo):
            if repo == "custom":
                repo = "RPMS"
            self.repo = repo

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

    def package_files(self):
        files = None
        if self.repo and self.package:
            name = self.package.name()

            req = "ftp://%(hostname)s/rpmbuild/%(repo)s" % {
                'hostname': self.hostname,
                'repo': self.repo
            }
            directory = self.dir(req)

            for entry in directory:
                if name in entry:
                    pinfo = FTPRPMPackage(entry).to_json()
                    if pinfo and pinfo['package'] == name:

                        if self.repo == 'RPMS':
                            pinfo['repo'] = 'custom'
                        else:
                            pinfo['repo'] = self.repo

                        if files is None:
                            files = [pinfo]
                        else:
                            files += [pinfo]
        return files

    def check_package_exists(self):
        return self.remote

    def check_file_exists(self):
        if self.files:
            target = filter(lambda x: x['name'] == self.package.filename(), self.files)
            return len(target) > 0
        return None

    def delete_content(self, file_path):
        if not self.files:
            return None
        check = filter(lambda x: x['path'] == file_path, self.files)
        if len(check) > 0:
            self.delete(file_path)
            if self.status == FTP_OK:
                self.update_stats()
                return True
        return False

    def delete_package(self):
        if self.repo and self.package:
            if not self.files:
                return None

            name = self.package.name()

            check = filter(lambda x: x['package'] == name, self.files)
            status = True

            for p in check:
                file_path = p['path']
                status = (status and self.delete_content(file_path))
            return status
        return None

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

    def upload_content(self):
        if self.repo and self.package:

            req = "ftp://%(hostname)s/rpmbuild/%(repo)s/%(filename)s" % {
                'hostname': self.hostname,
                'repo': self.repo,
                'filename': self.package.filename()
            }

            with open(self.package.path(), 'rb') as fp:
                self.stor(req, fp)

            if self.status == FTP_TRANS_OK:
                self.update_stats()
                return True
        return None

    def __del__(self):
        if self.ftp:
            self.ftp.close()

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

    parser.add_option("-s", "--host",
                      metavar="HOST",
                      dest="hostname",
                      help="FTP hostname. If not set, environment "
                           "variable BINTRAY_HOST is used for authentication.")
    parser.add_option("-u", "--user",
                      metavar="USER",
                      dest="username",
                      help="FTP username. If not set, environment "
                           "variable BINTRAY_USER is used for authentication.")
    parser.add_option("-k", "--key",
                      metavar="KEY",
                      dest="apikey",
                      help="FTP password. If not set, environment "
                           "variable BINTRAY_API_KEY is used for authentication.")
    parser.add_option("-r", "--repo",
                      help="RPM repository name. If not set. environment "
                           "variable BINTRAY_REPO is used")
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

    if not opts.hostname:
        if 'BINTRAY_HOST' in os.environ:
            opts.ensure_value('hostname', os.environ['BINTRAY_HOST'])
        else:
            errorprint('\nPass either --hostname or envirenmont variable BINTRAY_HOST\n')
            usage(parser, exit=True)

    if not opts.username:
        if 'BINTRAY_USER' in os.environ:
            opts.ensure_value('username', os.environ['BINTRAY_USER'])
        else:
            errorprint('\nPass either --user or envirenmont variable BINTRAY_USER\n')
            usage(parser, exit=True)

    if not opts.apikey:
        if 'BINTRAY_API_KEY' in os.environ:
            opts.ensure_value('apikey', os.environ['BINTRAY_API_KEY'])
        else:
            errorprint('\nPass either --key or envirenmont variable BINTRAY_API_KEY\n')
            usage(parser, exit=True)

    if not opts.repo:
        if 'BINTRAY_REPO' in os.environ:
            opts.ensure_value('repo', os.environ['BINTRAY_REPO'])
        else:
            errorprint('\nPass either --repo or envirenmont variable  BINTRAY_REPO\n')
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

    ftptray = Ftptray(opts.hostname, opts.username, opts.apikey, opts.repo)
    for p in packages:
        errorprint("read RPM package: %s" % p)
        ftptray.set_package(p)

        # delete package if --delete specified
        if opts.delete and ftptray.check_package_exists():
            if ftptray.delete_package():
                print "Package %s removed from RPM repo %s" % \
                    (ftptray.package.name(), ftptray.repo)
                continue

        if not ftptray.check_file_exists():
            if ftptray.upload_content():
                print "Package %s uploaded into RPM repo %s" % \
                    (ftptray.package.filename(), ftptray.repo)
        else:
            print "Package %s already exists in RPM repo %s" % \
                (ftptray.package.filename(), ftptray.repo)

        if opts.cleanup:
            if ftptray.cleanup_packages():
                print "RPM repo %s has been cleaned up" % ftptray.repo

if __name__ == "__main__":
    main()
