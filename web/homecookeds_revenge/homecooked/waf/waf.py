from homecooked.request import Request
from homecooked.constants import HTTPMethods
from homecooked.config import HomecookedConfig
import re

enc = HomecookedConfig.char_encoding

REGEX_FLAGS = {
    'i': re.IGNORECASE,
    'm': re.MULTILINE,
    's': re.DOTALL,
    'x': re.VERBOSE,
    'u': re.UNICODE,
}

def recursive_boolean(data, func):
    res = True
    if isinstance(data, dict):
        for k, v in data.items():
            res &= recursive_boolean(k, func) & recursive_boolean(v, func)
    elif isinstance(data, list):
        for v in data:
            res &= recursive_boolean(v, func)
    else:
        res &= func(str(data))
    
    return res

class HomecookedWAF():
  def __init__(self):
    self.blocked_ips = set()
    self.waf_regex = []
    self.load_rules()

  def load_rules(self):
    with open(HomecookedConfig().waf_rules, "r") as f:
      for line in f.readlines():
        flags = 0
        spl = line.split("=", maxsplit=2)
        flags_txt = spl[1]
        regex = spl[2]

        for flag in flags_txt:
          flags |= REGEX_FLAGS.get(flag, 0)

        self.waf_regex.append(re.compile(regex, flags))

  async def block_ip(self, ip):
    self.blocked_ips.add(ip)

  async def unblock_ip(self, ip):
    self.blocked_ips.remove(ip)

  def is_blocked(self, ip):
    return ip in self.blocked_ips
  
  async def check_request(self, request: Request):
    if self.is_blocked(request.client_ip):
      return False
    
    return self.check_path(request) and \
            self.check_headers(request) and \
            self.check_query(request) and \
            self.check_params(request) and \
            await self.check_body(request)
    
  def check_headers(self, request : Request):
    content_type = request.headers.get("content-type")
    content_length = request.headers.get("content-length")
    user_agent = request.headers.get("user-agent")

    if request.method == HTTPMethods.POST and content_type is None:
      return False
        
    if request.method == HTTPMethods.POST and user_agent is None:
      return False

    if request.body and content_length is None:
      return False
    
    if not request.body and content_length is not None:
      return False
        
    if request.method == HTTPMethods.POST and len(request.body.encode(enc)) != int(content_length):
      return False

    for header in request.headers:
        if not self._checkRegex(header):
            return False
                    
    return True
  
  def check_path(self, request : Request):
    return self._checkRegex(request.path)
  
  def check_query(self, request : Request):
    if not request.query:
      return True
   
    return recursive_boolean(request.query, self._checkRegex)
  
  def check_params(self, request : Request):
    if not request.params:
      return True
    
    return recursive_boolean(request.params, self._checkRegex)
  
  async def check_body(self, request : Request):
    if not request.body:
      return True
    
    return self.check_json(await request.json())

  def check_json(self, data : dict):
    if not data:
      return True
        
    return recursive_boolean(data, self._checkRegex)
  
  def _checkRegex(self, data):
    for regex in self.waf_regex:
      if regex.search(data):
        return False
    
    return True
    