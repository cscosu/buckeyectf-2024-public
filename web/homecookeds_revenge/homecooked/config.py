from dataclasses import dataclass
import os

@dataclass
class HomecookedConfig:
    _static_dir : str = "static"
    _template_dir : str = "templates"
    char_encoding : str = "utf-8"
    debug : bool = False
    port : int = 8001
    max_request_size : int = 1024 * 1024
    waf_rules : str = "/app/homecooked/waf/waf.rules"
    flag: str = os.getenv("FLAG") or "flag{fake_flag}"

    @property
    def static_dir(self):
        return os.path.join(os.getcwd(), self._static_dir)
    
    @static_dir.setter
    def static_dir(self, value):
        self._static_dir = value

    @property
    def template_dir(self):
        return os.path.join(os.getcwd(), self._template_dir)
    
    @template_dir.setter
    def template_dir(self, value):
        self._template_dir = value