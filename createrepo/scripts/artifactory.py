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
from distutils.version import LooseVersion

# global
debugmode = False
if 'BINTRAY_DEBUG' in os.environ:
    debugmode = True

class ErrorPrintInterface(object):

  def error_print(self, msg):
    print(msg, file=sys.stderr)

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
    if req.method == 'DELETE':
      url = req.full_url
      return self.retry_http_basic_auth(url, req, None)

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
        return self.curl.open(req)
      except urllib.error.HTTPError as e:
        if debugmode:
          self.error_print("URL: %s" % req.full_url)
          self.error_print("Method: %s" % req.method)
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
    if rpmpackage.name():
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
        return json.load(resp)["results"]
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
        repo_match = list(filter(lambda x: x["key"] == repo, json.load(resp)))
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

  def delete_package(self):
    package_info = self.remote_package_info()
    if package_info:
      return self.delete_content(package_info["path"])
    return None

  def upload_content(self, path = None):
    if self.repo and self.package:
      if path is None:
        path = "%(osname)s/%(osmajor)s" % {
          'osname': self.package.osname(),
          'osmajor': self.package.osmajor()
        }

      req = "%(url)s/%(repo)s/%(path)s/%(filename)s" % {
        "url": self.url,
        "repo": self.repo,
        "path": path,
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
      if not a.check_file_exist():
        if a.upload_content(self.path):
          print("Package %s uploaded into Bintray repo %s" % (a.package.filename(), a.repo))
      else:
          print("Package %s already exists in Bintray repo %s" % (a.package.filename(), a.repo))

      # Cleanup on upload
      if self.args.cleanup:
        if self.args.newest_only:
          if a.cleanup_packages(keep_version = False, keep = 1):
            print("Bintray repo %s has been cleaned up with only newest versions kept" % a.repo)
        else:
          if a.cleanup_packages():
            print("Bintray repo %s has been cleaned up" % a.repo)

def main():
  a = Application()
  a.run()

if __name__ == "__main__":
  main()