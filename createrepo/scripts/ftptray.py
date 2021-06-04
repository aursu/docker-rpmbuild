#!/usr/bin/python3
# pylint: disable=F0401

import sys
from argparse import ArgumentParser
import os
import re
import glob

import socket
import ftplib
from ftplib import FTP
from urllib.request import Request

import hashlib
import rpm
from datetime import datetime
from distutils.version import LooseVersion

FTP_SIZE_OK      = 213
FTP_SERVER_READY = 220
FTP_TRANS_OK     = 226
FTP_AUTH_OK      = 230
FTP_OK           = 250
FTP_PWD_OK       = 257

class ErrorPrintInterface(object):
  def error_print(self, msg):
    print(msg, file=sys.stderr)

class FTPRequest(Request):
  lines = None
  port = None

  def __init__(self, url, data=None, headers={},
                origin_req_host=None, unverifiable=False,
                method=None):
    Request.__init__(self, url, data, headers, origin_req_host, unverifiable, method)
    self.type = 'ftp'
    if self.port is None:
        self.port = ftplib.FTP_PORT
    self.reset()

  def get_selector(self):
      return self.selector

  def get_path(self):
      path = self.get_selector()
      if path[0] == '/':
          return path[1:]
      return path

  def add_line(self, line):
      self.lines += [line]

  def reset(self):
      self.lines = []

class RPMPackage(ErrorPrintInterface):
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
      ts = rpm.transaction.TransactionSet()
      try:
        fdno = os.open(self.package, os.O_RDONLY)
        self.hdr = ts.hdrFromFdno(fdno)
        os.close(fdno)
      except rpm.error as e:
        msg = "Error opening package %s: %s" % (self.package, str(e))
        self.error_print(msg)
    return self.hdr

  def getPackageAttr(self, attr):
      if self.hdr:
        return self.hdr[attr].decode('utf-8')
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
          relinfo = release.split('.')
          disttag = list(filter(lambda x: len(x) > 2 and x[:2] in ['el', 'fc'], relinfo))
          if len(disttag) > 0:
            # in case of el6_8, el6_3.1 etc
            return disttag[0].split('_')[0]
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
    if isinstance(package, str) and package:
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
    if isinstance(entry, str) and entry:
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

          mtime = ' '.join(data[5:-1])
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
      if self.created: self.json['created'] = self.created
      self.json['version'] = self.version
      if self.user: self.json['owner'] = self.user
      if self.size: self.json['size'] = self.size
      self.json['properties'] = {
        'rpm.metadata.name': self.name,
        'rpm.metadata.version': self.version,
        'rpm.metadata.release': self.release,
        'rpm.metadata.arch': self.arch
      }
    return self.json

class Ftptray(ErrorPrintInterface):
  url = None
  username = None
  secret = None

  curl = None
  # FTP status
  status = None
  # FTP authentication
  auth = None
  # Entry point
  entrypoint = None

  repo = None

  package = None

  def __init__(self, url, repo, username, secret):
    self.set_url(url)
    self.set_curl()
    if self.set_auth(username, secret):
      self.entrypoint = self.pwd()
    self.set_repo(repo)

  def set_url(self, url):
    self.status = None
    if isinstance(url, str) and url:
      try:
        self.url = socket.gethostbyname(url)
        self.status = 0
      except socket.error as e:
        self.status = int(e.errno)
        msg = "gethostbyname(%s) [Errno %s] %s" % (url, e.errno, e.strerror)
        self.error_print(msg)

  def set_curl(self):
    self.status = None
    if self.url:
      # close current connection if exist
      if self.curl and self.curl.sock:
          self.curl.close()
          self.curl = None
      try:
        self.curl = FTP(self.url)
        status = self.curl.lastresp
      except (socket.error, OSError) as e:
        status = e.errno
        msg = "FTP [Errno %s] %s" % (e.errno, e.strerror)
        self.error_print(msg)
      self.status = int(status)

  def set_auth(self, username, passwd = None):
    self.status = None
    self.auth = False
    # by default password is empty
    if passwd is None:
      passwd = ""
    if self.curl:
      try:
        self.curl.login(username, passwd)
        status = self.curl.lastresp
      except ftplib.error_perm as e:
        status, strerror = str(e).split(' ', 1)
        msg = "FTP login [Errno %s] %s" % (status, strerror)
        self.error_print(msg)
      self.status = int(status)
    if self.status == FTP_AUTH_OK:
      self.auth = True
      self.username = username
      self.secret = passwd
    return self.auth

  def pwd(self):
    self.status = None
    directory = None
    if self.curl:
      try:
        directory = self.curl.pwd()
        # 257 "<curdir>" is the current directory
        status = self.curl.lastresp
      except ftplib.error_perm as e:
        status, strerror = str(e).split(' ', 1)
        msg = "FTP pwd [Errno %s] %s" % (status, strerror)
        self.error_print(msg)
      self.status = int(status)
    return directory

  # only for FTPRequest object (due to add_line callback)
  #
  # return: array of strings (each directory item per line)
  # return: None in case of error (and set status into according error code)
  def dir(self, req):
    self.status = None
    if isinstance(req, str):
      req = FTPRequest(req)
    path = req.get_path()
    directory = None
    if self.curl and isinstance(path, str) and path:
      try:
        # lambda x: x - avoid printing output of command into stdout
        self.curl.dir(path, req.add_line)
        directory = req.lines
        # 226 Transfer complete
        status = self.curl.lastresp
      except (ftplib.error_temp, ftplib.error_perm) as e:
        status, strerror = str(e).split(' ', 1)
        msg = "FTP dir [Errno %s] %s" % (status, strerror)
        self.error_print(msg)
      self.status = int(status)
    return directory

  # check if file or directory exists
  def check(self, req):
    self.dir(req)
    return (self.status == FTP_TRANS_OK)

  def cwd(self, path):
    self.status = None
    if self.curl and isinstance(path, str) and path:
      try:
        self.curl.cwd(path)
        # 250 CWD command successful
        status = self.curl.lastresp
      except ftplib.error_perm as e:
        status, strerror = str(e).split(' ', 1)
        msg = "FTP cwd [Errno %s] %s" % (status, strerror)
        self.error_print(msg)
      self.status = int(status)
    return (self.status == FTP_OK)

  # return: File size in bytes (set status to 213)
  # return: None in case of error (set status code to according error code or
  #         unset it)
  def size(self, path):
    self.status = None
    size = None
    if self.curl and isinstance(path, str) and path:
        # avoid error: 550 SIZE not allowed in ASCII mode
        self.curl.voidcmd('TYPE I')
        try:
            size = self.curl.size(path)
            # 213 <size>
            status = self.curl.lastresp
        except ftplib.error_perm as e:
            status, strerror = str(e).split(' ', 1)
            msg = "FTP size [Errno %s] %s" % (status, strerror)
            self.error_print(msg)
        self.status = int(status)
    return size

  def check_file(self, req):
    if isinstance(req, str):
      req = FTPRequest(req)
    path = req.get_path()
    if self.check(req) and self.size(path):
      return True
    return False

  def check_dir(self, req):
    if isinstance(req, str):
      req = FTPRequest(req)
    path = req.get_path()
    if self.check(req) and self.cwd(path):
      self.cwd(self.entrypoint)
      return True
    return False

  def check_repo(self, repo):
    if self.url:
      if repo == "custom":
        repo = "RPMS"
      req = "ftp://%(hostname)s/rpmbuild/%(repo)s" % {
        'hostname': self.url,
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

  def package_files(self):
    files = None
    if self.repo and self.package:
      name = self.package.name()
      req = "ftp://%(hostname)s/rpmbuild/%(repo)s" % {
        'hostname': self.url,
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

  def update_stats(self):
    files = self.package_files()
    if files:
      # sort it
      files.sort(key = lambda x: LooseVersion(x['path']))
      self.files = files
      self.remote = True
    else:
      self.files = None
      self.remote = False

  def remote_package_info(self):
    if self.remote:
      package_info = list(filter(
        lambda p:
          p["properties"]["rpm.metadata.name"] == self.package.name() and \
          p["properties"]["rpm.metadata.version"] == self.package.version() and \
          p["properties"]["rpm.metadata.release"] == self.package.release(),
        self.files))
      if package_info: # if not empty dict
        return package_info[0]
    return {}

  def delete_package(self):
    package_info = self.remote_package_info()
    if package_info:
      return self.delete_content(package_info["path"])
    return None

  def delete_content(self, path):
    if not self.remote:
      return None
    check = filter(lambda x: x['path'] == path, self.files)
    if check:
      if self.delete(path):
        self.update_stats()
        return True
      return False
    return None

  def delete(self, path):
    self.status = None
    if self.curl and isinstance(path, str) and path:
      try:
        self.curl.delete(path)

        # 250 DELE command successful
        status = self.curl.lastresp
      except ftplib.error_perm as e:
        status, strerror = str(e).split(' ', 1)
        msg = "FTP delete [Errno %s] %s" % (status, strerror)
        self.error_print(msg)
      self.status = int(status)
    return (self.status == FTP_OK)

  def check_file_exist(self):
    package_info = self.remote_package_info()
    if package_info:
      return package_info["size"] == self.package.size()
    return False

  def upload_content(self):
    if self.repo and self.package:
      req = "ftp://%(hostname)s/rpmbuild/%(repo)s/%(filename)s" % {
        'hostname': self.url,
        'repo': self.repo,
        'filename': self.package.filename()
      }

      with open(self.package.path(), 'rb') as fp:
        if self.stor(req, fp):
          self.update_stats()
          return True
        return False
    return None

  def stor(self, req, fp):
    if isinstance(req, str):
        req = FTPRequest(req)

    path = req.get_path()
    cmd = "STOR %s" % path

    self.status = None
    if self.curl and isinstance(path, str) and path:
      try:
        self.curl.storbinary(cmd, fp)

        # 226 Transfer complete
        status = self.curl.lastresp
      except ftplib.error_perm as e:
        status, strerror = str(e).split(' ', 1)
        msg = "FTP storbinary [Errno %s] %s" % (status, strerror)
        self.error_print(msg)
      self.status = int(status)
    return (self.status == FTP_TRANS_OK)

  def cleanup_packages(self, keep_version = True, keep = 2):
    if not self.remote:
      return None

    # filter by distribution
    dist = '.' + self.package.dist()
    distfiles = filter(
        lambda p:
          p["properties"]["rpm.metadata.arch"] == self.package.arch() and \
          dist in p["properties"]["rpm.metadata.release"],
        self.files)

    # filter by version
    if keep_version:
      verfiles = list(filter(lambda p: p["properties"]["rpm.metadata.version"] == self.package.version(), distfiles))
    else:
      verfiles = list(distfiles)

    cleanup = []
    if len(verfiles) > keep:
        cleanup = verfiles[:-keep]

    status = False
    for p in cleanup:
      if self.delete_content(p['path']):
        status = True

    return status

  def __del__(self):
    if self.curl:
      try:
        self.curl.close()
      except ftplib.all_errors:
        pass

class Application(ErrorPrintInterface):
  # CLI options parser
  __ap = None

  # CLI arguments
  args = None
  # Environment variables
  envs = None

  username = None
  apikey = None
  secret = None
  repo = None
  url = None
  path = None

  packages = None

  def __init__(self):
    self.__ap = ArgumentParser()

  def usage(self, exit = False):
    self.error_print(self.__ap.format_help())
    if exit:
      sys.exit(1)

  def __setup_options(self):
    self.__ap.add_argument("-u", "--user",
                      metavar="USER",
                      dest="username",
                      help="Artifactory username. If not set, environment "
                           "variable BINTRAY_USER is used for authentication.")

    secret = self.__ap.add_mutually_exclusive_group()
    secret.add_argument("-k", "--key",
                      metavar="KEY",
                      dest="apikey",
                      help="Artifactory API key. If not set, environment "
                           "variable BINTRAY_API_KEY is used for authentication.")

    secret.add_argument("-w", "--password",
                      metavar="PASSWD",
                      dest="passwd",
                      help="Artifactory password. If not set, environment "
                           "variable ARTIFACTORY_PASSWORD is used for authentication.")

    self.__ap.add_argument("-l", "--url",
                      help="Artifactory URL. If not set, environment "
                           "variable ARTIFACTORY_URL is used")

    self.__ap.add_argument("-r", "--repo",
                      help="Bintray repository name. If not set, environment "
                           "variable BINTRAY_REPO is used")

    self.__ap.add_argument("-p", "--repo-path",
                      dest="path",
                      help="Repository path (excluding package name) "
                           "[default: <os name>/<os major>]")

    self.__ap.add_argument("-d", "--delete",
                      action="store_true",
                      dest="delete",
                      default=False,
                      help="Delete package [default: %(default)s]")

    self.__ap.add_argument("-c", "--cleanup",
                      action="store_true",
                      dest="cleanup",
                      default=False,
                      help="Cleanup packages (keep only 2 packages of "
                           "specified version) [default: %(default)s]")

    self.__ap.add_argument("--newest-only",
                      action="store_true",
                      dest="newest_only",
                      default=False,
                      help="Keep only newest packages during cleanup [default: %(default)s]")

    self.__ap.add_argument("files",
                      metavar="FILE",
                      nargs='+',
                      help="Packages or directories to upload.")

  def process_config(self):
    pass

  def process_cli(self):
    self.__setup_options()
    self.args = self.__ap.parse_args()

  def process_env(self):
    self.envs = {}

    process_list = {
      "BINTRAY_USER": "username",
      "ARTIFACTORY_USER": "username",
      "BINTRAY_API_KEY": "apikey",
      "ARTIFACTORY_API_KEY": "apikey",
      "BINTRAY_REPO": "repo",
      "ARTIFACTORY_REPO": "repo",
      "ARTIFACTORY_PASSWORD": "password",
      "ARTIFACTORY_URL": "url",
      "REPO_PATH": "path"
    }

    for e in process_list:
      v = process_list[e]
      if e in os.environ and os.environ[e]:
        self.envs[v] = os.environ[e]

  def process_input(self):
    pass

  def get_packages_list(self, lookup_paths):
    if self.packages is None:
      self.packages = []

    for path in lookup_paths:
      # look for only rpm files
      if len(path) > 4 and path[-4:] == '.rpm' and os.path.isfile(path):
        packages = [path]
      elif os.path.isdir(path):
        packages = list(filter(lambda p: os.path.isfile(p), glob.glob(path + "/**/*.rpm", recursive=True)))
      else:
        packages = []

      # normalise packages path
      packages = list(map(lambda p: os.path.normpath(p), packages))

      # create set of packages to remove duplicate elements
      # https://docs.python.org/3.6/tutorial/datastructures.html#sets
      self.packages = list(set(self.packages + packages))

  def setup_properties(self):
    # CLI arguments have priority over environment variables
    # Username
    if self.args.username:
      self.username = self.args.username
    elif "username" in self.envs:
      self.username = self.envs["username"]

    # API Key
    if self.args.apikey:
      self.apikey = self.args.apikey
    elif "apikey" in self.envs:
      self.apikey = self.envs["apikey"]

    # Password
    # API key and password are mutual exclusive (exclusion is already implemented in argument parser)
    if self.apikey:
      self.secret = self.apikey
    elif self.args.passwd:
      self.secret = self.args.passwd
    elif "password" in self.envs:
      self.secret = self.envs["password"]
    else:
      self.secret = ""

    # URL
    if self.args.url:
      self.url = self.args.url
    elif "url" in self.envs:
      self.url = self.envs["url"]

    # Repository
    if self.args.repo:
      self.repo = self.args.repo
    elif "repo" in self.envs:
      self.repo = self.envs["repo"]

    # Repo path
    if self.args.path:
      self.path = self.args.path
    elif "path" in self.envs:
      self.path = self.envs["path"]

    # Packages
    self.get_packages_list(self.args.files)

  def validate_hostname(self, hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

  def validate_url(self):
    # check hostname
    if not self.validate_hostname(self.url):
      self.error_print("Provided URL is not valid. It must be valid hostname, not \"%s\"" % self.url)
      self.usage(True)

  def validate(self):
    # Username is mandatory
    if not self.username:
      self.error_print("One of the argument -u/--user or "
        "environment variable ARTIFACTORY_USER is required when password is in use")
      self.usage(True)

    if not self.repo:
      self.error_print("One of the arguments -r/--repo or "
        "environment variable ARTIFACTORY_REPO is required")
      self.usage(True)

    if not self.url:
      self.error_print("One of the arguments -l/--url or "
        "environment variable ARTIFACTORY_URL is required")
      self.usage(True)
    else:
      self.validate_url()

  def setup(self):
    self.process_config()
    self.process_env()
    self.process_cli()
    self.process_input()
    self.setup_properties()
    self.validate()

  def run(self):
    self.setup()

    a = Ftptray(self.url, self.repo, self.username, self.secret)
    for p in self.packages:
      a.set_package(p)

      # Delete package if option is set
      if self.args.delete:
        if a.delete_package():
          print("Package %s removed from FTPtray repo %s" % (a.package.name(), a.repo))
        continue

      # Upload package
      if not a.check_file_exist():
        if a.upload_content():
          print("Package %s uploaded into FTPtray repo %s" % (a.package.filename(), a.repo))
      else:
          print("Package %s already exists in FTPtray repo %s" % (a.package.filename(), a.repo))

      # Cleanup on upload
      if self.args.cleanup:
        if self.args.newest_only:
          if a.cleanup_packages(keep_version = False, keep = 1):
            print("FTPtray repo %s has been cleaned up with only newest versions kept" % a.repo)
        else:
          if a.cleanup_packages():
            print("FTPtray repo %s has been cleaned up" % a.repo)

def main():
  a = Application()
  a.run()

if __name__ == "__main__":
  main()