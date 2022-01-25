#!/usr/bin/python3

import os
import sys
import urllib.request
from urllib.parse import urlparse
import http.client
import json
from argparse import ArgumentParser
import re

# global
debugmode = False
if 'FOREMAN_DEBUG' in os.environ:
    debugmode = True

class ErrorPrintInterface(object):
  def __init__(self, *args,  **kwargs):
    pass

  def error_print(self, msg):
    print(msg, file=sys.stderr)

class ForemanError(Exception):
    """Foreman exception"""

    def __init__(self, *args):
        Exception.__init__(self, *args)
        try:
            self.response = args[0]
        except IndexError:
            self.response = 'No response given'

class ForemanBasicAuthHandler(urllib.request.HTTPBasicAuthHandler):

  # Foreman does not return WWW-Authenticate header
  def http_error_auth_reqed(self, authreq, host, req, headers):
    return self.retry_http_basic_auth(host, req, None)


class ForemanAPI(ErrorPrintInterface):
  url = None
  username = None
  secret = None
  curl = None

  def __init__(self, url, username, secret):
    self.secret = secret
    self.username = username
    self.set_url(url)
    self.set_curl()

  def set_api_endpoint(self, scheme, netloc):
    self.url = "%s://%s/%s" % (scheme, netloc, "api")

  def set_url(self, url):
    url_info = urlparse(url)
    self.set_api_endpoint(url_info.scheme, url_info.netloc)

  def set_curl(self):
    self.curl = urllib.request.build_opener()
    self.set_auth()

  def set_auth(self):
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(realm=None,
                              uri=self.url,
                              user=self.username,
                              passwd=self.secret)
    auth_handler = ForemanBasicAuthHandler(password_mgr)
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
      raise ForemanError('Send attempts exceeded')

  def get_results(self, req):
    resp = self.send(req)
    if resp.code == 200:
      data = json.load(resp)
      if debugmode:
        self.error_print("Response Data: %s" % data)
      return data["results"]
    return None  

class Foreman(ForemanAPI):
  def users(self, login = None, mail = None,  lastname = None, firstname = None):
    if isinstance(login, str) and login:
      query = { "search": "login = %s" % login }
    elif isinstance(mail, str) and mail:
      query = { "search": "mail = %s" % mail }
    elif isinstance(lastname, str) and lastname:
      query = { "search": "lastname = %s" % lastname }
      if isinstance(firstname, str) and firstname:
        query = { "search": "lastname = %s and firstname = %s" % (lastname, firstname) }

    req = "%(url)s/users?%(query)s" % {
      "url": self.url,
      "query": urllib.parse.urlencode(query)
    }

    return self.get_results(req)

class Katello(ForemanAPI):
  def set_api_endpoint(self, scheme, netloc):
    self.url = "%s://%s/%s" % (scheme, netloc, "katello/api")

  def organizations(self, name = None, id = None):
    query = {}
    if isinstance(id, int) and id >= 0:
      query["search"] = "id=%d" % id
    elif isinstance(name, str) and name:
      query["search"] = "name = \"%(name)s\" or label = \"%(name)s\"" % { "name": name }

    req = "%(url)s/organizations?%(query)s" % {
      "url": self.url,
      "query": urllib.parse.urlencode(query)
    }

    return self.get_results(req)

  def products(self, organization_id, name = None):
    query = { "organization_id": organization_id }
    if isinstance(name, str) and name:
      query["search"] = "name = \"%(name)s\" or label = \"%(name)s\"" % { "name": name }

    req = "%(url)s/products?%(query)s" % {
      "url": self.url,
      "query": urllib.parse.urlencode(query)
    }

    return self.get_results(req)

  def content_views(self, organization_id = None, name = None, composite = None):
    query = {}
    if isinstance(organization_id, int) and organization_id > 0:
      query["organization_id"] = organization_id
    if isinstance(name, str) and name:
      query["search"] = "name = \"%(name)s\" or label = \"%(name)s\"" % { "name": name }
    if (isinstance(composite, int) and composite  in [0, 1]) or \
      isinstance(composite, bool):
      query["composite"] = composite

    req = "%(url)s/content_views?%(query)s" % {
      "url": self.url,
      "query": urllib.parse.urlencode(query)
    }

    return self.get_results(req)


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
  url = None

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
                           "variable FOREMAN_USER is used for authentication.")

    secret = self.__ap.add_mutually_exclusive_group()
    secret.add_argument("-k", "--key",
                      metavar="KEY",
                      dest="apikey",
                      help="Artifactory API key. If not set, environment "
                           "variable FOREMAN_API_KEY is used for authentication.")

    secret.add_argument("-w", "--password",
                      metavar="PASSWD",
                      dest="passwd",
                      help="Artifactory password. If not set, environment "
                           "variable FOREMAN_PASSWORD is used for authentication.")

    self.__ap.add_argument("-l", "--url",
                      help="Artifactory URL. If not set, environment "
                           "variable FOREMAN_URL is used")

  def process_config(self):
    pass

  def process_cli(self):
    self.__setup_options()
    self.args = self.__ap.parse_args()

  def process_env(self):
    self.envs = {}

    process_list = {
      "FOREMAN_USER": "username",
      "FOREMAN_API_KEY": "apikey",
      "FOREMAN_PASSWORD": "password",
      "FOREMAN_URL": "url",
    }

    for e in process_list:
      v = process_list[e]
      if e in os.environ and os.environ[e]:
        self.envs[v] = os.environ[e]

  def process_input(self):
    pass

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
    if url_info.scheme in ["http", "https"] and \
      host and self.validate_hostname(host) and \
      url_info.path in ["", '/', "/api", "/api/", "/katello/api", "/katello/api/"]:
      try:
        if port:
          int(port)
      except ValueError as e:
        self.error_print("Provided URL is not valid. Server port must be Integer value "
          "%s" % str(e))
        self.usage(True)
    else:
      self.error_print("Provided URL is not valid. It must contain valid scheme (either http or https), "
        "valid server location and optionaly /api or /katello/api path, not \"%s\"" % self.url)
      self.usage(True)

  def validate(self):
    # Check API Key or Password
    if self.secret:
      # Username is mandatory if password is provided
      if not self.username:
        self.error_print("One of the argument -u/--user or "
          "environment variable FOREMAN_USER is required when password is in use")
        self.usage(True)
    else:
      # Either API key or password are mandatory
      self.error_print("One of the arguments -k/--key -w/--password or "
        "one of the environment variables FOREMAN_API_KEY/FOREMAN_PASSWORD is required")
      self.usage(True)

    if not self.url:
      self.error_print("One of the arguments -l/--url or "
        "environment variable FOREMAN_URL is required")
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

    k = Katello(self.url, self.username, self.secret)
    k.content_views(composite=1)

    # product -> repo (GET /katello/api/products/:product_id/repositories)
    #                 (GET /katello/api/products - list products)
    # content view -> repo (GET /katello/api/content_views/:id/repositories)
    #                       (GET /katello/api/content_views)
    # Upload content into the repository (POST /katello/api/repositories/:id/upload_content)

def main():
  a = Application()
  a.run()

if __name__ == "__main__":
  main()