#!/usr/bin/python3
# pylint: disable=F0401
from argparse import ArgumentParser
import sys
import os
import glob
import hashlib
import rpm
import urllib.request
from urllib.parse import urlparse
import http.client
import base64
import re
import json
# from distutils.version import LooseVersion
from packaging.version import Version as LooseVersion
from datetime import datetime

# global
debugmode = False
if 'BINTRAY_DEBUG' in os.environ:
    debugmode = True

class ErrorPrintInterface(object):
  def __init__(self, *args,  **kwargs):
    pass

  def error_print(self, msg):
    print(msg, file=sys.stderr)

class Package(object):
  package = None
  _name = None
  _size = None
  _filename = None
  _version = None
  _release = None
  _dist = None
  _arch = None
  created = None
  user = None
  json = None
  sha256 = None

  def __init__(self, package):
    self.set_path(package)

  def set_path(self, package):
    self.package = package

  def get_path(self):
    return self.package

  def path(self):
    return self.get_path()

  def get_name(self):
    return self._name

  def name(self):
    return self.get_name()

  def get_size(self):
    return self._size

  def size(self):
    return self.get_size()

  def get_filename(self):
    return self._filename

  def filename(self):
    return self.get_filename()

  def get_version(self):
    return self._version

  def version(self):
    return self.get_version()

  def get_release(self):
    return self._release

  def release(self):
    return self.get_release()

  def get_dist(self):
    return self._dist

  def dist(self):
    return self.get_dist()

  def osname(self):
    dist = self.get_dist()
    if dist and dist[:2] == 'fc':
      return 'fedora'
    if dist and dist[:2] == 'el':
      return 'centos'
    return None

  def osmajor(self):
    dist = self.get_dist()
    if self.osname():
      try:
        return int(dist[2:])
      except ValueError:
        pass
    return None

  def get_arch(self):
    return self._arch

  def arch(self):
    return self.get_arch()

  def sha256sum(self):
    return self.sha256

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
    if self.get_path():
      self.json = { 'name': self.get_filename() }
      self.json['path'] = self.get_path()
      self.json['package'] = self.get_name()
      if self.created: self.json['created'] = self.created
      self.json['version'] = self.get_version()
      if self.user: self.json['owner'] = self.user
      if self.get_size(): self.json['size'] = self.get_size()
      self.json['properties'] = {
        'rpm.metadata.name': self.get_name(),
        'rpm.metadata.version': self.get_version(),
        'rpm.metadata.release': self.get_release(),
        'rpm.metadata.arch': self.get_arch()
      }
    return self.json

class RPMPackage(Package, ErrorPrintInterface):
  hdr = None

  def __init__(self, package):
    super().__init__(package)
    self.hdrFromPackage()

  def set_path(self, package):
    if os.path.isfile(package):
      self.package = package
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
        try:
          return self.hdr[attr].decode('utf-8')
        except AttributeError:
          return self.hdr[attr]
      return None

  def get_size(self):
    if self.package:
      return os.stat(self.package).st_size
    return None

  def get_filename(self):
    if self.package:
      return os.path.basename(self.package)
    return None

  def get_name(self):
      return self.getPackageAttr(rpm.RPMTAG_NAME)

  def get_version(self):
      return self.getPackageAttr(rpm.RPMTAG_VERSION)

  def get_release(self):
      return self.getPackageAttr(rpm.RPMTAG_RELEASE)

  def get_dist(self):
      release = self.get_release()
      if release and '.' in release:
          # only CentOS (el) and Fedora (fc) supported
          relinfo = release.split('.')
          disttag = list(filter(lambda x: len(x) > 2 and x[:2] in ['el', 'fc'], relinfo))
          if len(disttag) > 0:
            # in case of el6_8, el6_3.1 etc
            return disttag[0].split('_')[0]
      return None

  def get_arch(self):
      return self.getPackageAttr(rpm.RPMTAG_ARCH)

  def desc(self):
      return self.getPackageAttr(rpm.RPMTAG_DESCRIPTION)

  def url(self):
      return self.getPackageAttr(rpm.RPMTAG_URL)

class FTPRPMPackage(Package):
  osid = None
  relmaj = None
  relmin = None
  group = None

  def __init__(self, package):
    super().__init__(package)

  def set_size(self, size):
    try:
      self._size = int(size)
    except ValueError:
      self._size = None

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
          self._arch = arch
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
        self._filename = filename
        self._name = name       # ca-certificates # awscli
        self._version = version # 2018.2.22       # 1.14.28
        self._release = release # 70.0.el7_5      # 5.el7_5.1
        self.osid = osid       # el              # el
        self._dist = dist       # el7_5           # el7_5
        self.relmaj = relmaj   # 70.0            # 5
        self.relmin = relmin   # None            # 1

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

  def set_path(self, package):
    if ' ' in package:
      self.set_dirlist_entry(package)
    else:
      self.set_package(package)

  def get_size(self):
    if self.package:
      return self._size
    return None

  def get_filename(self):
    if self.package:
      return self._filename
    return None

  def get_name(self):
    if self.package:
      return self._name

  def get_version(self):
    if self.package:
      return self._version

  def get_release(self):
    if self.package:
      return self._release

  def get_dist(self):
    if self.package:
      # in case of el6_8, el6_3 etc
      return  self._dist.split('_')[0]
    return None

  def get_arch(self):
    if self.package:
      return self._arch

class ArtifactoryError(Exception):
    """Artifactory exception"""

    def __init__(self, *args):
        Exception.__init__(self, *args)
        try:
            self.response = args[0]
        except IndexError:
            self.response = 'No response given'

class ArtifactoryBasicAuthHandler(urllib.request.HTTPBasicAuthHandler):
  def _auth_credentials(self, realm, host):
    user, secret = self.passwd.find_user_password(realm, host)

    auth_header = None
    auth = None

    if secret is not None:
      if user is None:
        auth_header = "X-JFrog-Art-Api"
        auth = secret
      else:
        auth_header = self.auth_header
        raw = "%s:%s" % (user, secret)
        auth = "Basic " + base64.b64encode(raw.encode()).decode("ascii")
    return (auth_header, auth)

  def retry_http_basic_auth(self, host, req, realm):
    auth_header, auth = self._auth_credentials(realm, host)

    if auth is not None:
        if req.get_header(auth_header, None) == auth:
            return None
        req.add_unredirected_header(auth_header, auth)
        return self.parent.open(req, timeout=req.timeout)
    else:
        return None

  def http_request(self, req):
    if (not hasattr(self.passwd, 'is_authenticated') or
      not self.passwd.is_authenticated(req.full_url)):
      return req

    auth_header, auth = self._auth_credentials(None, req.full_url)

    if auth and not req.has_header(auth_header):
        req.add_unredirected_header(auth_header, auth)

    return req

  def http_error_403(self, req, fp, code, msg, headers):
    if req.get_method() == 'DELETE':
      return self.retry_http_basic_auth(req.full_url, req, None)

  def http_error_404(self, req, fp, code, msg, headers):
    return self.http_error_403(req, fp, code, msg, headers)

class Artifactory(ErrorPrintInterface):
  url = None
  username = None
  secret = None
  curl = None
  repo = None

  package = None

  # list of files uploaded to Bintray for this package
  files = None

  # True if package already exists in repo
  remote = None

  def __init__(self, url, repo, secret, username = None):
    self.secret = secret
    self.username = username
    self.set_url(url)
    self.set_curl()
    self.set_repo(repo)

  def set_url(self, url):
    url_info = urlparse(url)
    self.url = "%s://%s/artifactory" % (url_info.scheme, url_info.netloc)

  def set_curl(self):
    self.curl = urllib.request.build_opener()
    self.set_auth()

  def set_auth(self):
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(realm=None,
                              uri=self.url,
                              user=self.username,
                              passwd=self.secret)
    auth_handler = ArtifactoryBasicAuthHandler(password_mgr)
    if self.curl:
      self.curl.add_handler(auth_handler)

  def send(self, req, data = None, headers = {}, method = None):
    attempts = 4

    if isinstance(req, str):
      req = urllib.request.Request(req, data, headers, method = method)

    while attempts:
      try:
        resp = self.curl.open(req)
        if debugmode:
          self.error_print("URL: %s" % req.full_url)
          self.error_print("Method: %s" % req.get_method())
          self.error_print("Request Headers: %s" % req.header_items())
          self.error_print("Response Status: %s" % resp.status)
          self.error_print("Response Headers: %s" % resp.headers)
        return resp
      except urllib.error.HTTPError as e:
        if debugmode:
          self.error_print("URL: %s" % req.full_url)
          self.error_print("Method: %s" % req.get_method())
          self.error_print("Request Headers: %s" % req.header_items())
          self.error_print("Error Message: %s" % str(e))
          self.error_print("Error Headers: %s" % e.hdrs)
        if e.code == 401:
          self.set_curl()
          attempts -= 1
          continue
        raise e
      except urllib.error.URLError as e:
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
      except http.client.BadStatusLine:
        self.set_curl()
        attempts -= 1
        continue
      break
    if attempts == 0:
      raise ArtifactoryError('Send attempts exceeded')

  def set_package(self, package):
    rpmpackage = RPMPackage(package)

    if not rpmpackage.name():
      rpmpackage = FTPRPMPackage(package)

    if rpmpackage.name() and rpmpackage.version() and rpmpackage.release():
      self.package = rpmpackage
      self.update_stats()

  def package_files(self):
    if self.repo and self.package:
      query = {
        "rpm.metadata.name": self.package.name(),
        "repos": self.repo
      }
      req = "%(url)s/api/search/prop?%(query)s" % {
        "url": self.url,
        "query": urllib.parse.urlencode(query)
      }
      headers = {
        "X-Result-Detail": "info, properties"
      }

      resp = self.send(req, headers = headers)
      if resp.code == 200:
        data = json.load(resp)
        if debugmode:
          self.error_print("Response Data: %s" % data)
        return data["results"]
    return None

  def update_package_info(self, info):
    if "properties" in info:
      props = info["properties"]
      info["properties"] = dict([(p, v[0] if isinstance(v, list) and len(v) == 1 else v) for p, v in props.items()])
    return info

  def update_stats(self):
    files = self.package_files()
    if files:
      # adjust it
      self.files = [self.update_package_info(f) for f in files]
      # sort it
      self.files.sort(key = lambda x: LooseVersion(x['path']))
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

  def check_package_exist(self, match_version = False):
    if self.remote:
      if match_version:
        if self.remote_package_info(): # if not empty hash
          return True
      else:
        return True
    return False

  def check_file_exist(self):
    package_info = self.remote_package_info()
    if package_info:
      return package_info["checksums"]["sha256"] == self.package.sha256sum()
    return False

  # https://www.jfrog.com/confluence/display/JFROG/Artifactory+REST+API#ArtifactoryRESTAPI-GetRepositories
  def check_repo(self, repo):
    if isinstance(repo, str) and repo:
      query = {
        "type": "local",
        "packageType": "yum"
      }
      req = "%(url)s/api/repositories?%(query)s" % {
        "url": self.url,
        "query": urllib.parse.urlencode(query)
      }

      resp = self.send(req)
      if resp.code == 200:
        data = json.load(resp)
        if debugmode:
          self.error_print("Response Data: %s" % data)
        repo_match = list(filter(lambda x: x["key"] == repo, data))
        return len(repo_match) > 0
    return False

  def set_repo(self, repo):
    if self.check_repo(repo):
      self.repo = repo

  def delete_content(self, path):
    if not self.remote:
        return None
    check = list(filter(lambda p: p['path'] == path, self.files))
    if check:
      req = "%(url)s/%(repo)s/%(path)s" % {
        "url": self.url,
        "repo": self.repo,
        "path": path
      }
      resp = self.send(req, method='DELETE')

      # HTTP/1.1 200 OK
      # HTTP/1.1 204 No Content
      if resp.code in [200, 204]:
        self.update_stats()
        return True
      return False
    return None

  def cleanup_packages(self, keep_version = True, keep = 2, repo_path = None):
    if not self.remote:
      return None

    dist = '.' + self.package.dist()
    if repo_path is None:
      repo_path = "%(osname)s/%(osmajor)s" % {
        'osname': self.package.osname(),
        'osmajor': self.package.osmajor()
      }

    # filter by distribution
    distfiles = filter(
        lambda p:
          p["properties"]["rpm.metadata.arch"] == self.package.arch() and \
          dist in p["properties"]["rpm.metadata.release"] and \
          repo_path in p["path"],
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

  def delete_package(self):
    package_info = self.remote_package_info()
    if package_info:
      return self.delete_content(package_info["path"])
    return None

  def upload_content(self, repo_path = None):
    if self.repo and self.package:
      if repo_path is None:
        repo_path = "%(osname)s/%(osmajor)s" % {
          'osname': self.package.osname(),
          'osmajor': self.package.osmajor()
        }

      req = "%(url)s/%(repo)s/%(path)s/%(filename)s" % {
        "url": self.url,
        "repo": self.repo,
        "path": repo_path,
        "filename": self.package.filename()
      }

      with open(self.package.path(), 'rb') as fp:
        reqobj = urllib.request.Request(
          req,
          data = fp.read(),
          headers = { 'Content-Length': self.package.size() },
          method = 'PUT')
        resp = self.send(reqobj)
        if resp.code == 201:
          self.update_stats()
          return True
    return None

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
  repo_path = None

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
                      dest="repo_path",
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
                      help="Cleanup packages (keep only 2 packages of "
                           "specified version) [default: %(default)s]")

    self.__ap.add_argument("--newest-only",
                      action="store_true",
                      dest="newest_only",
                      help="Keep only newest packages during cleanup [default: %(default)s]")

    self.__ap.add_argument("--no-check",
                      action="store_true",
                      dest="skip_files_check",
                      help="Do not check if file exists before processing [default: %(default)s]")

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
      "REPO_PATH": "repo_path"
    }

    for e in process_list:
      v = process_list[e]
      if e in os.environ and os.environ[e]:
        self.envs[v] = os.environ[e]

  def process_input(self):
    pass

  # create packages list based on lookup_paths provided (local system)
  #
  def get_packages_list(self, lookup_paths, skip_files_check = False):
    if self.packages is None:
      self.packages = []

    for path in lookup_paths:
      # look for only rpm files
      if len(path) > 4 and path[-4:] == '.rpm' and (os.path.isfile(path) or skip_files_check):
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
    if self.args.repo_path:
      self.repo_path = self.args.repo_path
    elif "repo_path" in self.envs:
      self.repo_path = self.envs["repo_path"]

    # Packages
    self.get_packages_list(self.args.files, self.args.skip_files_check)

  def validate_hostname(self, hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

  def validate_url(self):
    url_info = urlparse(self.url)
    if ':' in url_info.netloc:
      host, port = url_info.netloc.split(':', 1)
    else:
      host = url_info.netloc
      port = None
    # check scheme, hostname, path
    if url_info.scheme in ['http', 'https'] and \
      host and self.validate_hostname(host) and \
      url_info.path in ["", '/', "/artifactory", "/artifactory/"]:
      try:
        if port:
          int(port)
      except ValueError as e:
        self.error_print("Provided URL is not valid. Server port must be Integer value "
          "%s" % str(e))
        self.usage(True)
    else:
      self.error_print("Provided URL is not valid. It must contain valid scheme (either http or https), "
        "valid server location and optionaly /artifactory/ path, not \"%s\"" % self.url)
      self.usage(True)

  def validate(self):
    # Check API Key or Password
    if self.apikey:
      # Username is optional if API key is provided
      pass
    elif self.secret:
      # Username is mandatory if password is provided
      if not self.username:
        self.error_print("One of the argument -u/--user or "
          "environment variable ARTIFACTORY_USER is required when password is in use")
        self.usage(True)
    else:
      # Either API key or password are mandatory
      self.error_print("One of the arguments -k/--key -w/--password or "
        "one of the environment variables ARTIFACTORY_API_KEY/ARTIFACTORY_PASSWORD is required")
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

    a = Artifactory(self.url, self.repo, self.secret, self.username)
    for p in self.packages:
      a.set_package(p)

      # Delete package if option is set
      if self.args.delete:
        if a.delete_package():
          print("Package %s removed from Bintray repo %s" % (a.package.name(), a.repo))
        continue

      # Upload package
      if a.package.sha256sum():
        if not a.check_file_exist():
          if a.upload_content(self.repo_path):
            print("Package %s uploaded into Bintray repo %s" % (a.package.filename(), a.repo))
        else:
            print("Package %s already exists in Bintray repo %s" % (a.package.filename(), a.repo))
      else:
        print("Package %s is not exists on local filesystem" % a.package.path())

      # Cleanup on upload
      if self.args.cleanup:
        if self.args.newest_only:
          if a.cleanup_packages(keep_version = False, keep = 1, repo_path = self.repo_path):
            print("Bintray repo %s has been cleaned up with only newest versions kept" % a.repo)
        else:
          if a.cleanup_packages(repo_path = self.repo_path):
            print("Bintray repo %s has been cleaned up" % a.repo)

def main():
  a = Application()
  a.run()

if __name__ == "__main__":
  main()