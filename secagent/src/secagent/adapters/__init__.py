"""Adapter layer — wraps each open-source tool behind a uniform interface."""

from secagent.adapters.base import BaseAdapter
from secagent.adapters.dnsx import DnsxAdapter
from secagent.adapters.ffuf import FfufAdapter
from secagent.adapters.gitleaks import GitleaksAdapter
from secagent.adapters.httpx_adapter import HttpxAdapter
from secagent.adapters.katana import KatanaAdapter
from secagent.adapters.naabu import NaabuAdapter
from secagent.adapters.nuclei import NucleiAdapter
from secagent.adapters.simple_crawler import SimpleCrawlerAdapter
from secagent.adapters.subfinder import SubfinderAdapter
from secagent.adapters.theharvester import TheHarvesterAdapter
from secagent.adapters.tlsx import TlsxAdapter
from secagent.adapters.uncover import UncoverAdapter
from secagent.adapters.web_vuln import WebVulnAdapter

__all__ = [
    "BaseAdapter",
    "DnsxAdapter",
    "FfufAdapter",
    "GitleaksAdapter",
    "HttpxAdapter",
    "KatanaAdapter",
    "NaabuAdapter",
    "NucleiAdapter",
    "SimpleCrawlerAdapter",
    "SubfinderAdapter",
    "TlsxAdapter",
    "UncoverAdapter",
    "TheHarvesterAdapter",
    "WebVulnAdapter",
]
