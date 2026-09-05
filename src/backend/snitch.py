## snitch.py: Analyze pcap network captures, extract TCP, UDP, and ICMP packet data, and gather extra information.
#
# This script processes .pcap files, extracting TCP, UDP, and ICMP packet payloads and
# metadata, and generates testcases and info files for each packet. It enriches the
# output with MIME types, entropy, geoip, network class, banners, and more. DNS packets
# (UDP/53) are decoded and the query/answer records are included in the output JSON.
# SNMP (UDP/TCP 161/162), DHCP (UDP 67/68), NTP (UDP 123), and SIP (UDP/TCP 5060/5061)
# packets are also decoded and their protocol-specific fields included. ICMP packets are
# fully supported with type, code, ID, and sequence fields. Optionally, it performs
# active reconnaissance to gather additional network and server information.
#
# Features:
#   - Extracts TCP, UDP, and ICMP packet data and metadata from .pcap files.
#   - Decodes DNS queries and responses from UDP port 53 packets.
#   - Decodes SNMP, DHCP, NTP, and SIP protocol-specific fields.
#   - Decodes ICMP type, code, ID, and sequence fields.
#   - Writes raw payloads and info files to output directories.
#   - Determines MIME types, entropy, geoip, network class, banners, and more.
#   - Optionally performs active reconnaissance (reverse DNS, banners, SSL info, etc.).
#   - Supports multi-threaded processing for large captures.
#   - Outputs consolidated JSON and summary files.
#
# Usage:
#   python3 snitch.py <pcap_file> [options]
#   See command-line argument parser below for available options.
#
# Dependencies:
#   - scapy, numpy, requests, chardet, geoip2, magic, yaml, bs4, scipy, etc.
#
# Author: oxagast
# Import standard and third-party libraries for argument parsing, file handling, networking, compression, and data processing
import warnings
import argparse
import base64
import csv
import hashlib
import json
import os
import queue
import re
import shutil
import socket
import ssl
import sys

EARLY_VERSION_ONLY_MODE = "--version" in sys.argv
if EARLY_VERSION_ONLY_MODE:
    warnings.simplefilter("ignore")
    os.environ["PYTHONWARNINGS"] = "ignore"

import tempfile
import textwrap
import threading
import time
import traceback
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import chardet
import geoip2.database
import magic
import numpy as np
import requests
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
except (ImportError, AttributeError):
    requests.packages.urllib3.disable_warnings()
import yaml
import ipaddress
from bs4 import BeautifulSoup
from scipy.stats import entropy
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import multiprocessing
from urllib.parse import parse_qs, quote, urlparse
from datetime import datetime
from decimal import Decimal
from functools import lru_cache
from cryptography.utils import CryptographyDeprecationWarning


if not EARLY_VERSION_ONLY_MODE:
    # Apply the legacy module-default behavior so any user code or third
    # party that triggers a DeprecationWarning surfaces it in the Snitch
    # log. ``simplefilter`` inserts a match-all entry at the FRONT of the
    # filter list; the targeted ``ignore`` rules we add immediately
    # below are also inserted at the front (so they win against the
    # catch-all default), which is why the order matters here.
    warnings.simplefilter("module")
    os.environ["PYTHONWARNINGS"] = "module"
    warnings.formatwarning = lambda msg, cat, fname, ln, file=None, line=None: (
        f"[Main] {cat.__name__} {msg}\n"
    )

    # Re-suppress urllib3's InsecureRequestWarning now that the
    # ``simplefilter`` reset would otherwise un-ignore it. The VirusTotal
    # upload path and several GeoIP / banner probes intentionally call
    # unverified HTTPS endpoints; surfacing the warning once per call
    # adds noise without value, and the trade-off is already explicit in
    # the corresponding ``requests.get(..., verify=False)`` / ``undici
    # dispatcher`` decision.
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)

    # Silence the third-party deprecation noise that fires at import
    # time from scapy / cryptography 49+. ``scapy.layers.ipsec`` imports
    # ``algorithms.TripleDES`` from the legacy location
    # (``cryptography.hazmat.primitives.ciphers.algorithms``) which is
    # deprecated in cryptography 43+ and will be removed in 48.0.0. The
    # warning is harmless and the algorithm still works; suppressing it
    # keeps the Snitch startup log focused on actionable diagnostics.
    # Other CryptographyDeprecationWarning categories (e.g. future
    # algorithm moves) are intentionally NOT silenced so we notice them.
    warnings.filterwarnings(
        "ignore",
        category=CryptographyDeprecationWarning,
        message=r"TripleDES has been moved to cryptography\.hazmat\.decrepit\.ciphers\.algorithms",
    )
    # Same story for ARC4 — scapy's WEP decrypt path imports ARC4 from
    # the legacy location until cryptography 48.0.0 removes it.
    warnings.filterwarnings(
        "ignore",
        category=CryptographyDeprecationWarning,
        message=r"ARC4 has been moved to cryptography\.hazmat\.decrepit\.ciphers\.algorithms",
    )
stopEvent = threading.Event()


def _loadPacketsnitchVersion():
    """
    Resolve the backend version from package.json so backend /version stays in
    sync with the Electron app version.

    Resolution order:
      1) PACKETSNITCH_VERSION env var (explicit override)
      2) nearest package.json discovered from likely runtime roots
      3) fallback default
    """
    envVersion = str(os.environ.get("PACKETSNITCH_VERSION", "")).strip()
    if envVersion:
        return envVersion, "env:PACKETSNITCH_VERSION"

    candidateRoots = []
    try:
        candidateRoots.append(os.path.dirname(os.path.realpath(__file__)))
    except Exception:
        pass

    try:
        candidateRoots.append(os.path.dirname(os.path.realpath(sys.argv[0])))
    except Exception:
        pass

    try:
        candidateRoots.append(os.getcwd())
    except Exception:
        pass

    checked = set()
    for root in candidateRoots:
        current = os.path.abspath(root)
        while True:
            packagePath = os.path.join(current, "package.json")
            if packagePath not in checked:
                checked.add(packagePath)
                if os.path.isfile(packagePath):
                    try:
                        with open(packagePath, "r", encoding="utf-8") as pkgFile:
                            packageJson = json.load(pkgFile)
                        packageVersion = str(packageJson.get("version", "")).strip()
                        if packageVersion:
                            return packageVersion, packagePath
                    except Exception:
                        pass

            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent

    return "0.0.0", "fallback"


PACKETSNITCH_VERSION, PACKETSNITCH_VERSION_SOURCE = _loadPacketsnitchVersion()
PACKETSNITCH_USER_AGENT = (
    f"Mozilla/5.0 (compatible; PacketSnitch/{PACKETSNITCH_VERSION}; +http://packetsnitch.com)"
)
backendRuntimeMode = "unknown"
backendShutdownReason = "normal"
backendStartedAtEpoch = time.time()
processingJobLock = threading.Lock()
processingJobs = {}
backendJobsProcessedSinceStart = 0


def packetSnitchRequestHeaders(accept=None, extraHeaders=None):
    headers = {
        "User-Agent": PACKETSNITCH_USER_AGENT,
    }
    if accept:
        headers["Accept"] = accept
    if extraHeaders:
        headers.update(extraHeaders)
    return headers


def logBackendStartup(mode):
    safeMode = str(mode or "unknown").strip() or "unknown"
    print(
        "[Main] Backend startup "
        + f"mode={safeMode} "
        + f"version={PACKETSNITCH_VERSION} "
        + f"version_source={PACKETSNITCH_VERSION_SOURCE}",
        file=sys.stderr,
    )


def logBackendShutdown(mode, reason, exitCode):
    safeMode = str(mode or "unknown").strip() or "unknown"
    safeReason = str(reason or "normal").strip() or "normal"
    try:
        safeExitCode = int(exitCode)
    except Exception:
        safeExitCode = 0

    print(
        "[Main] Backend shutdown "
        + f"mode={safeMode} "
        + f"reason={safeReason} "
        + f"exit_code={safeExitCode} "
        + f"version={PACKETSNITCH_VERSION}",
        file=sys.stderr,
    )

try:
    import scapy.all as scapy
except ImportError:
    import scapy

backendDir = os.path.dirname(os.path.realpath(__file__))
if backendDir not in sys.path:
    sys.path.insert(0, backendDir)

import decoders.address_resolution as dec_address_resolution
import decoders.bittorrent as dec_bittorrent
import decoders.bgp as dec_bgp
import decoders.cdp as dec_cdp
import decoders.mndp as dec_mndp
import decoders.dhcp as dec_dhcp
import decoders.dhcpv6 as dec_dhcpv6
import decoders.epmap as dec_epmap
import decoders.ftp as dec_ftp
import decoders.grpc as dec_grpc
import decoders.http as dec_http
import decoders.http2 as dec_http2
import decoders.hsrp as dec_hsrp
import decoders.igmp as dec_igmp
import decoders.imap as dec_imap
import decoders.irc as dec_irc
import decoders.iso8583 as dec_iso8583
import decoders.kerberos as dec_kerberos
import decoders.dnp3 as dec_dnp3
import decoders.lacp as dec_lacp
import decoders.ldap as dec_ldap
import decoders.llmnr as dec_llmnr
import decoders.mdns as dec_mdns
import decoders.modbus as dec_modbus
import decoders.mqtt as dec_mqtt
import decoders.mtp as dec_mtp
import decoders.mysql as dec_mysql
import decoders.nfs as dec_nfs
import decoders.nntp as dec_nntp
import decoders.ntp as dec_ntp
import decoders.ospf as dec_ospf
import decoders.pop3 as dec_pop3
import decoders.postgresql as dec_postgresql
import decoders.radius as dec_radius
import decoders.rtsp as dec_rtsp
import decoders.s7comm as dec_s7comm
import decoders.sctp as dec_sctp
import decoders.sip as dec_sip
import decoders.smb as dec_smb
import decoders.ssdp as dec_ssdp
import decoders.smpp as dec_smpp
import decoders.smtp as dec_smtp
import decoders.snmp as dec_snmp
import decoders.soulseek as dec_soulseek
import decoders.ssh as dec_ssh
import decoders.stp as dec_stp
import decoders.telnet as dec_telnet
import decoders.tftp as dec_tftp
import decoders.wan_link as dec_wan_link
import decoders.websocket as dec_websocket
import decoders.wireless_80211 as dec_wireless_80211
import decoders.xmpp as dec_xmpp

activeRecon = "False"
numWorkerThreads = (os.cpu_count() // 2 or 2)
isSSH = False
checkTor = True
verbose = 0
torJsonData = {}
torNetworkIps = {}
activeWifiKeys = []
activeWifiKeysLock = threading.Lock()
# Shared result lists, protected by their respective locks so that threads
# can safely append results concurrently without data corruption.
allPacketInfo = []
allPacketInfoLock = threading.Lock()

hostOutputFile = "hosts.json"
DEFAULT_HOST_CHUNK_SIZE = 2000
hostChunkSize = DEFAULT_HOST_CHUNK_SIZE
DEFAULT_EARLY_YIELD_PACKET_THRESHOLD = 5000
earlyYieldPacketThreshold = DEFAULT_EARLY_YIELD_PACKET_THRESHOLD
emitJsonSnapshots = False
progressLinePrefix = "[Bridge]"
progressEventCallback = None
currentDir = os.getcwd()
scriptDir = os.path.dirname(os.path.realpath(__file__)) + "/"
runtimeInitialized = False
processingLock = threading.Lock()
runtimeConfigLock = threading.Lock()

# --- Lookup tables loaded once at startup (see init_lookup_tables()) ---
# Keyed (port_int, "tcp"/"udp") -> description string
portDescriptionMap: dict = {}
portServiceNameMap: dict = {}
# Keyed by uppercase MAC macPrefix (e.g. "00:1A:2B") -> vendor name
macVendorMap: dict = {}

# --- GeoIP reader opened once and reused across all packets ---
# Protected by geoIpCacheLock for the cache; the Reader itself is thread-safe.
geoIpReader = None
geoIpCache: dict = {}
geoIpCacheLock = threading.Lock()
ipsumCacheLock = threading.Lock()
ipsumDatasetByIp: dict = {}
ipsumCacheDate = ""
PACKETSNITCH_USERDATA_PATH = str(os.environ.get("PACKETSNITCH_USERDATA_PATH", "")).strip()
IPSUM_SOURCE_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
IPSUM_PROJECT_URL = "https://github.com/stamparm/ipsum"
TOR_ONIONOO_URL = "https://onionoo.torproject.org/details?running=true&flag=Exit&fields=nickname,or_addresses,platform"
TOR_PROJECT_URL = "https://www.torproject.org/"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"
SHODAN_INTERNETDB_DOCS_URL = "https://internetdb.shodan.io"
VIRUSTOTAL_API_BASE_URL = "https://www.virustotal.com/api/v3"
VIRUSTOTAL_GUI_BASE_URL = "https://www.virustotal.com/gui"
torNetworkCacheLock = threading.Lock()
torNetworkNodesByIp: dict = {}
torNetworkIps: dict = {}
torNetworkCacheDate = ""

# --- Banner cache: (ip, port) -> banner dict, avoids redundant socket probes ---
cachedBanners: dict = {}
cachedBannersLock = threading.Lock()

# --- TCP stream protocol cache: canonical stream key -> initial packet dst port ---
tcpStreamInitialDstPortMap: dict = {}
# Streams positively identified as HTTP/2 via client connection preface.
http2DetectedStreams: set = set()
http2DetectedStreamsLock = threading.Lock()

TLS_SERVICE_PORTS = {443, 465, 636, 853, 8443, 9443, 5061}
HTTP2_PREFACE_BYTES = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _candidateCommonDirectories():
    """
    Return likely directories containing backend helper data files.

    This must support:
      - direct Python execution from src/backend
      - onefile PyInstaller execution (temp extraction for __file__)
      - packaged Electron resources layouts
    """

    candidates = []

    def addPath(pathValue):
        normalized = str(pathValue or "").strip()
        if not normalized:
            return
        absolutePath = os.path.abspath(normalized)
        if absolutePath not in candidates:
            candidates.append(absolutePath)

    # Existing script-relative location (works for plain python execution).
    addPath(os.path.join(scriptDir, "common"))

    # Executable-relative locations (works for onefile and packaged backend exe).
    executableDir = os.path.dirname(os.path.realpath(sys.executable or ""))
    addPath(os.path.join(executableDir, "common"))
    addPath(os.path.join(os.path.dirname(executableDir), "common"))

    # argv[0]-relative fallback.
    argv0Dir = os.path.dirname(os.path.realpath(sys.argv[0] if sys.argv else ""))
    addPath(os.path.join(argv0Dir, "common"))
    addPath(os.path.join(os.path.dirname(argv0Dir), "common"))

    # Environment-driven overrides for packaged runtimes.
    commonOverride = str(os.environ.get("PACKETSNITCH_COMMON_PATH", "")).strip()
    if commonOverride:
        addPath(commonOverride)

    resourcesPath = str(os.environ.get("PACKETSNITCH_RESOURCES_PATH", "")).strip()
    if resourcesPath:
        addPath(os.path.join(resourcesPath, "common"))

    # Development cwd fallback.
    addPath(os.path.join(os.getcwd(), "src", "backend", "common"))

    return candidates


def _resolveCommonResourcePath(resourceFileName):
    for commonDir in _candidateCommonDirectories():
        candidateFile = os.path.join(commonDir, resourceFileName)
        if os.path.exists(candidateFile):
            return candidateFile
    return ""


def _coercePositiveInt(value, defaultValue):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return defaultValue
    return max(1, parsed)


def _getRuntimeConfigSnapshot():
    with runtimeConfigLock:
        return {
            "hostChunkSize": int(hostChunkSize),
            "workerThreads": int(numWorkerThreads),
            "earlyYieldPacketThreshold": int(earlyYieldPacketThreshold),
        }


def _setActiveWifiKeys(entries):
    """Replace the active 802.11 key list (used by the wireless decoder)."""
    global activeWifiKeys
    if not isinstance(entries, list):
        return
    normalized = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        normalized.append(
            {
                "bssid": str(entry.get("bssid") or "").strip(),
                "ssid": str(entry.get("ssid") or "").strip(),
                "psk": str(entry.get("psk") or "").strip(),
                "pmkHex": str(entry.get("pmkHex") or "").strip(),
                "wepKeyHex": str(entry.get("wepKeyHex") or "").strip(),
            }
        )
    with activeWifiKeysLock:
        activeWifiKeys = normalized


def _applyRuntimeConfigUpdate(request):
    global hostChunkSize
    global numWorkerThreads
    global earlyYieldPacketThreshold

    updates = {}
    if "hostChunkSize" in request:
        updates["hostChunkSize"] = _coercePositiveInt(
            request.get("hostChunkSize"),
            hostChunkSize,
        )
    if "workerThreads" in request:
        updates["workerThreads"] = _coercePositiveInt(
            request.get("workerThreads"),
            numWorkerThreads,
        )
    if "earlyYieldPacketThreshold" in request:
        updates["earlyYieldPacketThreshold"] = _coercePositiveInt(
            request.get("earlyYieldPacketThreshold"),
            earlyYieldPacketThreshold,
        )
    if "wifiKeys" in request:
        _setActiveWifiKeys(request.get("wifiKeys"))
        updates["wifiKeys"] = len(activeWifiKeys)

    if not updates:
        return {
            "success": False,
            "error": "No runtime config values provided",
        }, 400

    with runtimeConfigLock:
        if "hostChunkSize" in updates:
            hostChunkSize = updates["hostChunkSize"]
        if "workerThreads" in updates:
            numWorkerThreads = updates["workerThreads"]
        if "earlyYieldPacketThreshold" in updates:
            earlyYieldPacketThreshold = updates["earlyYieldPacketThreshold"]

    return {
        "success": True,
        "action": "set-runtime-config",
        **_getRuntimeConfigSnapshot(),
    }, 200


def _setActiveProcessingJob(jobId, pcapPath):
    with processingJobLock:
        normalizedJobId = str(jobId)
        processingJobs[normalizedJobId] = {
            "jobId": normalizedJobId,
            "startedAtEpoch": float(time.time()),
            "pcapPath": str(pcapPath or ""),
            "processedPackets": 0,
            "totalPackets": 0,
        }


def _clearActiveProcessingJob(jobId):
    with processingJobLock:
        processingJobs.pop(str(jobId), None)


def _runCaptureInProcess(runArgs, progressQueue, resultQueue):
    """Run one capture in an isolated process for HTTP server requests."""
    global progressEventCallback

    def progressCallback(payload):
        try:
            progressQueue.put(payload)
        except Exception:
            pass

    try:
        progressEventCallback = progressCallback
        resultQueue.put({"result": runCaptureFromArgs(runArgs)})
    except Exception as runError:
        resultQueue.put({
            "error": str(runError),
            "traceback": traceback.format_exc(),
        })
    finally:
        progressEventCallback = None


def _buildBackendStatusPayload(server=None):
    nowEpoch = float(time.time())
    uptimeSeconds = max(0.0, nowEpoch - float(backendStartedAtEpoch))
    runtimeConfig = _getRuntimeConfigSnapshot()

    with processingJobLock:
        activeJobs = [dict(job) for job in processingJobs.values()]
        jobsProcessedSinceStart = int(backendJobsProcessedSinceStart)
    activeJobs.sort(key=lambda job: float(job.get("startedAtEpoch") or 0))
    currentJob = activeJobs[-1] if activeJobs else {}
    processedPacketsNow = int(currentJob.get("processedPackets") or 0)
    totalPacketsNow = int(currentJob.get("totalPackets") or 0)

    runningJobs = []
    for job in activeJobs:
        startedAtEpoch = job.get("startedAtEpoch")
        runningJobs.append(
            {
                "name": "process",
                "jobId": job.get("jobId"),
                "pcapPath": job.get("pcapPath"),
                "startedAt": datetime.utcfromtimestamp(startedAtEpoch).isoformat() + "Z"
                if isinstance(startedAtEpoch, (int, float))
                else None,
                "elapsedSeconds": round(max(0.0, nowEpoch - float(startedAtEpoch)), 3)
                if isinstance(startedAtEpoch, (int, float))
                else None,
                "processedPackets": int(job.get("processedPackets") or 0),
                "totalPackets": int(job.get("totalPackets") or 0),
            }
        )

    serverAddress = None
    if server is not None:
        try:
            serverAddress = f"{server.server_address[0]}:{int(server.server_address[1])}"
        except Exception:
            serverAddress = None

    statusLine = (
        "status=ok "
        + f"mode={backendRuntimeMode} "
        + f"version={PACKETSNITCH_VERSION} "
        + f"uptime_s={uptimeSeconds:.3f} "
        + f"workerThreads={runtimeConfig['workerThreads']} "
        + f"hostChunkSize={runtimeConfig['hostChunkSize']} "
        + f"earlyYieldPacketThreshold={runtimeConfig.get('earlyYieldPacketThreshold', DEFAULT_EARLY_YIELD_PACKET_THRESHOLD)} "
        + f"processedPackets={processedPacketsNow} "
        + f"totalPackets={totalPacketsNow} "
        + f"runningJobs={len(runningJobs)} "
        + f"jobsProcessed={jobsProcessedSinceStart}"
    )

    return {
        "type": "status",
        "status": "ok",
        "statusLine": statusLine,
        "service": "packetsnitch",
        "version": PACKETSNITCH_VERSION,
        "versionSource": PACKETSNITCH_VERSION_SOURCE,
        "mode": backendRuntimeMode,
        "pid": int(os.getpid()),
        "python": {
            "version": str(sys.version).split()[0],
            "executable": sys.executable,
        },
        "server": {
            "address": serverAddress,
            "shutdownReason": backendShutdownReason,
        },
        "uptimeSeconds": round(uptimeSeconds, 3),
        "runtime": {
            **runtimeConfig,
            "processing": bool(runningJobs),
            "stopRequested": bool(stopEvent.is_set()),
            "jobsProcessedSinceStart": jobsProcessedSinceStart,
            "processedPackets": processedPacketsNow,
            "totalPackets": totalPacketsNow,
        },
        "jobsProcessedSinceStart": jobsProcessedSinceStart,
        "runningJobs": runningJobs,
        "timestamp": datetime.utcfromtimestamp(nowEpoch).isoformat() + "Z",
    }


def configLoader(filename="conf.yaml"):
    """
    Load YAML configuration from the specified file.
    Exits if the file does not exist.
    """
    with open(filename, "r") as f:
        return yaml.safe_load(f)


@lru_cache(maxsize=2048)
def getPortDescription(port, protocol="tcp"):
    """
    Return the IANA description for a port/protocol pair.
    Uses the portDescriptionMap dict loaded once at startup for O(1) lookup.
    Also cached with LRU for additional layer of caching.
    """
    return portDescriptionMap.get((port, protocol), "No description available")

def getPortNameFromCSV(port, protocol="tcp"):
    """
    Return the port name from the CSV lookup table for a given port/protocol pair.
    Falls back to IANA Unknown if not found in the CSV.
    """

    return portServiceNameMap.get((port, protocol), "Unknown")


def getIcmpApplicationProtocol(data):
    """
    Infer a human-friendly ICMP application label from the ICMP header.
    """

    if not data:
        return "ICMP"

    icmpType = int(data[0]) if len(data) > 0 else -1
    icmpCode = int(data[1]) if len(data) > 1 else -1

    if icmpType in (0, 8):
        return "Ping"

    if icmpType in (3, 11):
        return "Traceroute"

    if icmpType == 12 and icmpCode == 0:
        return "Traceroute"

    return "ICMP"

@lru_cache(maxsize=4096)
def reverseDnsLookup(ip):
    """
    Perform a reverse DNS lookup for the given IP address.
    Returns a dictionary with resolution status and hostnames or error.
    """

    try:
        dnsResult = socket.gethostbyaddr(ip)
        return (
            {"Resolved": True, "Hostnames": dnsResult}
            if dnsResult and len(dnsResult) > 0
            else {"Resolved": False, "Error": "No PTR record found"}
        )
    except Exception as e:
        return {
            "Resolved": False,
            "Error": "Address resolution error: " + str(e),
        }

def getServBanner(ip, port, timeout, hostname, serviceName=None):
    """
    Retrieve the service banner, SSL certificate, and page title for a given IP and port.
    Uses a dict cache keyed by (ip, port) to avoid redundant network probes.
    Handles both HTTP and HTTPS. Returns a dict with banner, page title, and encryption data.
    The optional serviceName helps choose the correct URL scheme for non-standard ports.
    """

    ipPortKey = (ip, port)
    # Fast O(1) cache hit check before doing any network work
    with cachedBannersLock:
        if ipPortKey in cachedBanners:
            return cachedBanners[ipPortKey]

    sslCert = "Unavailable"
    cipherInfo = "N/A"
    sslVersion = "N/A"
    pageTitle = "N/A"
    bannerInfo = {}
    # Get page title for HTTP/HTTPS ports
    try:
        serviceNameNormalized = (
            serviceName.lower() if isinstance(serviceName, str) and serviceName else ""
        )
        isLikelyTlsService = (
            port in TLS_SERVICE_PORTS
            or "https" in serviceNameNormalized
            or "ssl" in serviceNameNormalized
            or "tls" in serviceNameNormalized
            or "wss" in serviceNameNormalized
        )
        if isLikelyTlsService:
            pageTitle = getPageTitle("https://" + hostname + ":" + str(port), timeout)
        else:
            pageTitle = getPageTitle("http://" + hostname + ":" + str(port), timeout)
    except Exception:
        pageTitle = "N/A"
    # Try to fetch SSL certificate info (ignore errors; port may not support TLS)
    sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    if hasattr(ssl, "OP_NO_TLSv1"):
        sslContext.options |= ssl.OP_NO_TLSv1
    if hasattr(ssl, "OP_NO_TLSv1_1"):
        sslContext.options |= ssl.OP_NO_TLSv1_1
    sslContext.check_hostname = False
    sslContext.verify_mode = ssl.CERT_NONE

    serverHostnamesToTry = [None]
    if isinstance(hostname, str) and hostname:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            # Only use SNI when the provided host is a domain, not a literal IP.
            serverHostnamesToTry.insert(0, hostname)

    for serverHostname in serverHostnamesToTry:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as tcpSocket:
                with sslContext.wrap_socket(
                    tcpSocket, server_hostname=serverHostname
                ) as sslSocket:
                    peerCert = sslSocket.getpeercert()
                    if peerCert:
                        sslCert = peerCert
                    cipherInfo = sslSocket.cipher() or "N/A"
                    sslVersion = sslSocket.version() or "N/A"
                    break
        except Exception:
            continue
    # Try to fetch banner from server
    try:
        tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpSocket.settimeout(timeout)
        tcpSocket.connect((ip, port))
        banner = tcpSocket.recv(1024).decode(errors="ignore").strip()
        if len(banner) > 0:
            bannerInfo = {
                "Banner": banner,
                "Page Title": pageTitle,
                "Encryption Data": {
                    "SSL Cert": sslCert,
                    "SSL Version": sslVersion,
                    "Encrypted With": cipherInfo,
                }
                if sslVersion != "N/A"
                else "N/A",
            }
            tcpSocket.close()
        else:
            # No passive banner; try an HTTP HEAD request as a fallback
            tcpSocket.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = tcpSocket.recv(1024).decode(errors="ignore").strip()
            tcpSocket.close()
            if len(banner) > 0:
                bannerInfo = {
                    "Banner": banner,
                    "Page Title": pageTitle,
                    "Encryption Data": {
                        "SSL Cert": sslCert,
                        "SSL Version": sslVersion,
                        "Encrypted With": cipherInfo,
                    }
                    if sslVersion != "N/A"
                    else "N/A",
                }
            else:
                bannerInfo = {
                    "Page Title": pageTitle,
                    "Encryption Data": {
                        "SSL Cert": sslCert,
                        "SSL Version": sslVersion,
                        "Encrypted With": cipherInfo,
                    }
                    if sslVersion != "N/A"
                    else "N/A",
                }
    except Exception:
        bannerInfo = {
            "Page Title": pageTitle,
            "Encryption Data": {
                "SSL Cert": sslCert,
                "SSL Version": sslVersion,
                "Encrypted With": cipherInfo,
            }
            if sslVersion != "N/A"
            else "N/A",
        }
        # Store in cache so repeated calls for the same (ip, port) are free
    if tcpSocket:
        tcpSocket.close()
    with cachedBannersLock:
        cachedBanners[ipPortKey] = bannerInfo
    return bannerInfo


def getPageTitle(url, timeout):
    """
    Fetch the HTML page title from the given URL with a timeout.
    Returns the title string or "N/A" if unavailable.
    """

    try:
        requests.packages.urllib3.disable_warnings(  # ignore
            category=InsecureRequestWarning  # ignore request warning
        )  # ignore
        httpResponse = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers=packetSnitchRequestHeaders(),
        )
        httpResponse.raise_for_status()
        responseContent = httpResponse.content
        htmlParser = BeautifulSoup(responseContent, "html.parser")
        return htmlParser.title.string if htmlParser.title else "N/A"
    except Exception:
        return "N/A"


def writeTestcase(data, outputDirPath, portDir, index):
    """
    Write raw packet payload bytes to a testcase file.
    Creates the per-port sub-directory on first use; errors there are non-fatal.
    Uses a context manager so the file descriptor is always released.
    """
    import pathlib
    safePortDir = os.path.basename(portDir)
    basePath = pathlib.Path(outputDirPath).resolve()
    destPath = (basePath / safePortDir).resolve()
    if not str(destPath).startswith(str(basePath) + os.sep):
        raise ValueError("Path traversal detected in portDir")
    destPath.mkdir(exist_ok=True)
    filePath = destPath / ("pcap.data_packet." + str(int(index)) + ".dat")
    with open(filePath, "wb") as out:
        out.write(data)


def _jsonValuesEquivalent(leftValue, rightValue):
    """
    Compare JSON-like values for semantic equality.
    Falls back to direct equality when JSON serialisation fails.
    """
    try:
        return json.dumps(
            leftValue,
            sort_keys=True,
            default=_jsonDefaultSerializer,
        ) == json.dumps(
            rightValue,
            sort_keys=True,
            default=_jsonDefaultSerializer,
        )
    except Exception:
        return leftValue == rightValue


def _jsonDefaultSerializer(value):
    """
    Convert non-JSON-native values into safe serializable primitives.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, Decimal):
        return float(value)
    return str(value)


def _jsonDumpEncoded(value):
    return json.dumps(value, default=_jsonDefaultSerializer).encode()


def _normaliseJsonKeyName(key):
    if not isinstance(key, str):
        return key
    return re.sub(r"\s+", ".", key.strip().lower())


def _normaliseJsonKeys(value):
    """
    Recursively normalise all JSON object keys to lowercase dot notation.
    Spaces become periods, and uppercase characters are lowercased.
    """
    if isinstance(value, list):
        return [_normaliseJsonKeys(item) for item in value]
    if not isinstance(value, dict):
        return value

    normalised = {}
    for rawKey, rawValue in value.items():
        key = _normaliseJsonKeyName(rawKey)
        childValue = _normaliseJsonKeys(rawValue)
        if key in normalised:
            existing = normalised[key]
            if _jsonValuesEquivalent(existing, childValue):
                continue
            if isinstance(existing, dict) and isinstance(childValue, dict):
                merged = dict(existing)
                merged.update(childValue)
                normalised[key] = merged
                continue
        normalised[key] = childValue
    return normalised


def joinInfo(outputDirPath, portDir, index, dataTypeJson, packetInfoJson, host):
    """
    Merge packet-level info with extra analysis info and write as a JSON file.
    Thread-safe: uses allPacketInfoLock when appending to the shared allPacketInfo list.
    """
    mergedJson = {
        "packet.info": json.loads(packetInfoJson),
        "extra.info": json.loads(dataTypeJson),
    }
    # the following is commented out because on large captures it can exceed the filesystem's
    # maximum inode limit for temporary files.  It's not strictly necessary anyway.
    ###path = outputDirPath + "/" + portDir + "/pcap.info_packet." + str(index) + ".json"
    ###with open(path, "wb+") as out:
    ###    out.write(json.dumps(mergedJson).encode())
    if verbose >= 2:
        print(json.dumps(mergedJson, indent=2))
    # Protect the shared list from concurrent thread writes
    with allPacketInfoLock:
        allPacketInfo.append({"host": host, "packet": mergedJson})
    return mergedJson


def buildEmptyPayloadDataTypeInfo():
    return {
        "MIME Type": "application/octet-stream",
        "payload.mime": "application/octet-stream",
        "Decompressed": {"Decompressed": False},
        "payload.decompressed": {"Decompressed": False},
        "Data Types": ["Empty payload"],
        "Traits": {"Length": 0},
    }


def buildGenericPayloadDataTypeInfo(rawPayload, errorMessage=None):
    payloadBytes = rawPayload if isinstance(rawPayload, (bytes, bytearray)) else b""
    if len(payloadBytes) == 0:
        dataTypeInfo = buildEmptyPayloadDataTypeInfo()
    else:
        try:
            mimeType = magic.from_buffer(payloadBytes, mime=True)
        except Exception:
            mimeType = "application/octet-stream"
        dataTypeInfo = {
            "MIME Type": mimeType,
            "payload.mime": mimeType,
            "Decompressed": {"Decompressed": False},
            "payload.decompressed": {"Decompressed": False},
            "Data Types": ["Unknown data type"],
            "Traits": {"Length": len(payloadBytes)},
        }

    if errorMessage:
        dataTypeInfo["Processing Error"] = str(errorMessage)
        dataTypeInfo["processing.error"] = str(errorMessage)
    return dataTypeInfo


def buildFallbackPacketEntry(p, packetIndex, errorMessage=""):
    linkLayerInfo = extractLinkLayerInfo(p)
    linkProto = linkLayerInfo["linkProto"]
    srcMacAddr = linkLayerInfo["srcAddr"]
    dstMacAddr = linkLayerInfo["dstAddr"]
    linuxCookedSection = linkLayerInfo["linuxCooked"]
    srcMacVendor = macAddrToVendor(srcMacAddr) if srcMacAddr != "N/A" else "N/A"
    dstMacVendor = macAddrToVendor(dstMacAddr) if dstMacAddr != "N/A" else "N/A"

    timestampValue = getattr(p, "time", 0)
    try:
        timestamp = datetime.fromtimestamp(float(Decimal(timestampValue))).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )
    except Exception:
        timestamp = "1970-01-01 00:00:00.000000"

    protocolKey = "FRAME"
    dstPortStr = "frame"
    hostKey = "0.0.0.0"
    transportSection = None
    ipSection = "N/A"
    networkLayer = getPacketNetworkLayer(p)

    if p.haslayer("TCP") and networkLayer is not None:
        tcpLayer = p["TCP"]
        rawPayload = bytes(tcpLayer.payload) if bytes(tcpLayer.payload) else b""
        tcpFlags = []
        if tcpLayer.flags.S:
            tcpFlags.append("SYN")
        if tcpLayer.flags.A:
            tcpFlags.append("ACK")
        if tcpLayer.flags.F:
            tcpFlags.append("FIN")
        if tcpLayer.flags.R:
            tcpFlags.append("RST")
        if tcpLayer.flags.P:
            tcpFlags.append("PSH")
        if tcpLayer.flags.U:
            tcpFlags.append("URG")
        if tcpLayer.flags.ECE:
            tcpFlags.append("ECE")
        if tcpLayer.flags.CWR:
            tcpFlags.append("CWR")
        protocolKey = "TCP"
        dstPortStr = str(int(getattr(tcpLayer, "dport", 0) or 0))
        hostKey = str(getattr(networkLayer, "dst", "0.0.0.0") or "0.0.0.0")
        transportSection = {
            "tcp.src.port": int(getattr(tcpLayer, "sport", 0) or 0),
            "transport.tcp.src.port": int(getattr(tcpLayer, "sport", 0) or 0),
            "tcp.dst.port": int(getattr(tcpLayer, "dport", 0) or 0),
            "transport.tcp.dst.port": int(getattr(tcpLayer, "dport", 0) or 0),
            "TCP Flag Data": {
                "Flags": "|".join(tcpFlags) if tcpFlags else "None",
                "tcp.flags": "|".join(tcpFlags) if tcpFlags else "None",
                "transport.tcp.flags": "|".join(tcpFlags) if tcpFlags else "None",
            },
            "TCP Payload Length": int(len(rawPayload)),
            "tcp.payload.len": int(len(rawPayload)),
            "transport.tcp.payload.len": int(len(rawPayload)),
            "transport.proto": "TCP",
        }
        ipSection = {
            "ip.src.addr": str(getattr(networkLayer, "src", "N/A")),
            "network.ip.src.addr": str(getattr(networkLayer, "src", "N/A")),
            "ip.dst.addr": str(getattr(networkLayer, "dst", "N/A")),
            "network.ip.dst.addr": str(getattr(networkLayer, "dst", "N/A")),
            "ip.chksum": getPacketNetworkChecksumHex(networkLayer),
            "network.ip.chksum": getPacketNetworkChecksumHex(networkLayer),
            "ip.len": getPacketNetworkLength(networkLayer),
            "network.ip.len": getPacketNetworkLength(networkLayer),
            "network.proto": getPacketNetworkProtocolLabel(networkLayer),
        }
    elif p.haslayer("UDP") and networkLayer is not None:
        udpLayer = p["UDP"]
        rawPayload = bytes(udpLayer.payload) if bytes(udpLayer.payload) else b""
        protocolKey = "UDP"
        dstPortStr = str(int(getattr(udpLayer, "dport", 0) or 0))
        hostKey = str(getattr(networkLayer, "dst", "0.0.0.0") or "0.0.0.0")
        transportSection = {
            "udp.src.port": int(getattr(udpLayer, "sport", 0) or 0),
            "transport.udp.src.port": int(getattr(udpLayer, "sport", 0) or 0),
            "udp.dst.port": int(getattr(udpLayer, "dport", 0) or 0),
            "transport.udp.dst.port": int(getattr(udpLayer, "dport", 0) or 0),
            "UDP length": int(getattr(udpLayer, "len", len(rawPayload)) or len(rawPayload)),
            "udp.len": int(getattr(udpLayer, "len", len(rawPayload)) or len(rawPayload)),
            "transport.proto": "UDP",
        }
        ipSection = {
            "ip.src.addr": str(getattr(networkLayer, "src", "N/A")),
            "network.ip.src.addr": str(getattr(networkLayer, "src", "N/A")),
            "ip.dst.addr": str(getattr(networkLayer, "dst", "N/A")),
            "network.ip.dst.addr": str(getattr(networkLayer, "dst", "N/A")),
            "ip.chksum": getPacketNetworkChecksumHex(networkLayer),
            "network.ip.chksum": getPacketNetworkChecksumHex(networkLayer),
            "ip.len": getPacketNetworkLength(networkLayer),
            "network.ip.len": getPacketNetworkLength(networkLayer),
            "network.proto": getPacketNetworkProtocolLabel(networkLayer),
        }
    elif (p.haslayer("ICMP") or getPacketNetworkProtocolNumber(networkLayer) == 58) and networkLayer is not None:
        # Guard the layer access: ICMPv6 can report haslayer("ICMP") True
        # yet raise on p["ICMP"] (see the main packetLoop ICMP branch).
        try:
            if p.haslayer("ICMP"):
                icmpLayer = p["ICMP"]
            else:
                icmpLayer = networkLayer.payload
        except Exception:
            icmpLayer = networkLayer.payload
        rawPayload = bytes(icmpLayer)
        protocolKey = "ICMP"
        dstPortStr = "icmp"
        hostKey = str(getattr(networkLayer, "dst", "0.0.0.0") or "0.0.0.0")
        transportSection = {
            "Type": int(getattr(icmpLayer, "type", 0) or 0),
            "icmp.type": int(getattr(icmpLayer, "type", 0) or 0),
            "Code": int(getattr(icmpLayer, "code", 0) or 0),
            "icmp.code": int(getattr(icmpLayer, "code", 0) or 0),
            "transport.proto": "ICMP",
        }
        ipSection = {
            "ip.src.addr": str(getattr(networkLayer, "src", "N/A")),
            "network.ip.src.addr": str(getattr(networkLayer, "src", "N/A")),
            "ip.dst.addr": str(getattr(networkLayer, "dst", "N/A")),
            "network.ip.dst.addr": str(getattr(networkLayer, "dst", "N/A")),
            "ip.chksum": getPacketNetworkChecksumHex(networkLayer),
            "network.ip.chksum": getPacketNetworkChecksumHex(networkLayer),
            "ip.len": getPacketNetworkLength(networkLayer),
            "network.ip.len": getPacketNetworkLength(networkLayer),
            "network.proto": getPacketNetworkProtocolLabel(networkLayer),
        }
    elif networkLayer is not None:
        rawPayload = bytes(networkLayer.payload) if bytes(networkLayer.payload) else bytes(networkLayer)
        protocolKey = "Undecodable"
        dstPortStr = "undecodable"
        hostKey = str(getattr(networkLayer, "dst", "0.0.0.0") or "0.0.0.0")
        transportSection = {
            "IP Protocol Number": getPacketNetworkProtocolNumber(networkLayer),
            "ip.proto.num": getPacketNetworkProtocolNumber(networkLayer),
            "transport.proto": "Unknown protocol",
        }
        ipSection = {
            "ip.src.addr": str(getattr(networkLayer, "src", "N/A")),
            "network.ip.src.addr": str(getattr(networkLayer, "src", "N/A")),
            "ip.dst.addr": str(getattr(networkLayer, "dst", "N/A")),
            "network.ip.dst.addr": str(getattr(networkLayer, "dst", "N/A")),
            "ip.chksum": getPacketNetworkChecksumHex(networkLayer),
            "network.ip.chksum": getPacketNetworkChecksumHex(networkLayer),
            "ip.len": getPacketNetworkLength(networkLayer),
            "network.ip.len": getPacketNetworkLength(networkLayer),
            "network.proto": getPacketNetworkProtocolLabel(networkLayer),
        }
    else:
        rawPayload = bytes(p.payload) if bytes(p.payload) else bytes(p)
        protocolKey = "FRAME"
        dstPortStr = "frame"

    dataTypeInfo = buildGenericPayloadDataTypeInfo(rawPayload, errorMessage)
    packetInfo = {
        "packet.processed": int(packetIndex),
        "packet.timestamp": timestamp,
        "packet.proto": protocolKey,
        "link.proto": linkProto if linkProto else protocolKey,
        "packet.decoded_protocols": [protocolKey],
        "Ethernet Frame": {
            "ether.src.mac.addr": srcMacAddr,
            "link.src.mac.addr": srcMacAddr,
            "ether.dst.mac.addr": dstMacAddr,
            "link.dst.mac.addr": dstMacAddr,
            "ether.src.mac.vendor": srcMacVendor,
            "link.src.mac.vendor": srcMacVendor,
            "ether.dst.mac.vendor": dstMacVendor,
            "link.dst.mac.vendor": dstMacVendor,
        }
        if (srcMacAddr != "N/A" or dstMacAddr != "N/A")
        else "N/A",
        "IP": ipSection,
        protocolKey: transportSection if transportSection is not None else {},
        "Raw data": {
            "Payload": {
                "payload.hex": rawPayload.hex(),
                "payload.ascii": rawPayload.decode(errors="ignore"),
            },
            "Packet": bytes(p).hex(),
            "packet.hex": bytes(p).hex(),
            "payload.len": len(rawPayload),
        },
    }
    if linuxCookedSection is not None:
        packetInfo["Linux Cooked"] = linuxCookedSection

    return joinInfo(
        outputDir,
        dstPortStr,
        packetIndex,
        _jsonDumpEncoded(dataTypeInfo),
        _jsonDumpEncoded(packetInfo),
        hostKey,
    )


def sortAndIndexPackets(hostPacketMap):
    for host, packets in hostPacketMap.items():
        # Skip empty or invalid entries
        if not packets:
            continue

        # Sort packets by timestamp
        packets.sort(
            key=lambda p: datetime.strptime(
                p.get("packet.info", {}).get(
                    "packet.timestamp", "1970-01-01 00:00:00.000000"
                ),
                "%Y-%m-%d %H:%M:%S.%f",
            )
        )

        # Add chronological index
        for i, pkt in enumerate(packets, start=1):
            packetInfo = pkt.get("packet.info")
            if isinstance(packetInfo, dict):
                packetInfo["Index"] = i
                packetInfo["index"] = i

    return hostPacketMap


def _normaliseAppProtocolLabel(value):
    textValue = str(value or "").strip().lower()
    if textValue in {"", "unknown", "n/a", "null", "none", "undecodable"}:
        return ""
    return textValue


def _packetSortKeyForStream(packetWrapper):
    packetInfo = packetWrapper.get("packet.info", {}) if isinstance(packetWrapper, dict) else {}
    processedValue = packetInfo.get("packet.processed")
    try:
        processedOrder = int(processedValue)
    except (TypeError, ValueError):
        processedOrder = 1 << 60
    timestampValue = str(packetInfo.get("packet.timestamp", ""))
    return (processedOrder, timestampValue)


def _extractStreamIdentity(packetWrapper):
    if not isinstance(packetWrapper, dict):
        return None
    packetInfo = packetWrapper.get("packet.info")
    if not isinstance(packetInfo, dict):
        return None

    transportName = str(packetInfo.get("packet.proto", "")).strip().upper()
    if transportName not in {"TCP", "UDP", "SCTP"}:
        return None

    ipSection = packetInfo.get("IP")
    if not isinstance(ipSection, dict):
        return None
    srcIp = str(ipSection.get("ip.src.addr", "")).strip()
    dstIp = str(ipSection.get("ip.dst.addr", "")).strip()
    if not srcIp or not dstIp:
        return None

    transportSection = packetInfo.get(transportName)
    if not isinstance(transportSection, dict):
        return None

    protocolPrefix = transportName.lower()
    srcPortValue = transportSection.get(f"{protocolPrefix}.src.port")
    dstPortValue = transportSection.get(f"{protocolPrefix}.dst.port")
    try:
        srcPort = int(srcPortValue)
        dstPort = int(dstPortValue)
    except (TypeError, ValueError):
        return None

    endpointA = f"{srcIp}:{srcPort}"
    endpointB = f"{dstIp}:{dstPort}"
    orderedEndpoints = sorted([endpointA, endpointB])
    streamKey = f"{protocolPrefix}|{orderedEndpoints[0]}|{orderedEndpoints[1]}"
    return {
        "transport": protocolPrefix,
        "streamKey": streamKey,
    }


def _getPacketNetworkData(packetWrapper):
    if not isinstance(packetWrapper, dict):
        return None
    extraInfo = packetWrapper.get("extra.info")
    if not isinstance(extraInfo, dict):
        return None
    traitsInfo = extraInfo.get("Traits")
    if not isinstance(traitsInfo, dict):
        return None
    networkData = traitsInfo.get("Network Data")
    if not isinstance(networkData, dict):
        return None
    return networkData


def _getPacketAppProtocol(packetWrapper, transportPrefix):
    networkData = _getPacketNetworkData(packetWrapper)
    if not isinstance(networkData, dict):
        return ""

    candidateValues = [
        networkData.get(f"{transportPrefix}.proto"),
        networkData.get("application.proto"),
        networkData.get("app.proto"),
        networkData.get("Port Protocol"),
        networkData.get("Port Protcol"),
    ]
    for candidate in candidateValues:
        normalised = _normaliseAppProtocolLabel(candidate)
        if normalised:
            return normalised
    return ""


def normalizeStreamApplicationProtocols(packetEntries):
    streamPackets = {}

    for entry in packetEntries:
        if not isinstance(entry, dict):
            continue
        packetWrapper = entry.get("packet")
        streamIdentity = _extractStreamIdentity(packetWrapper)
        if not streamIdentity:
            continue
        streamKey = streamIdentity["streamKey"]
        if streamKey not in streamPackets:
            streamPackets[streamKey] = {
                "transport": streamIdentity["transport"],
                "packets": [],
            }
        streamPackets[streamKey]["packets"].append(packetWrapper)

    for streamData in streamPackets.values():
        streamPacketList = streamData.get("packets", [])
        if not streamPacketList:
            continue

        streamPacketList.sort(key=_packetSortKeyForStream)
        transportPrefix = streamData.get("transport", "")
        if not transportPrefix:
            continue

        # Prefer the first packet's destination-port protocol label.
        chosenProtocol = _getPacketAppProtocol(streamPacketList[0], transportPrefix)
        if not chosenProtocol:
            # If the first packet is undecodable, fall back to the last decodable
            # packet label in the stream.
            for packetWrapper in reversed(streamPacketList):
                chosenProtocol = _getPacketAppProtocol(packetWrapper, transportPrefix)
                if chosenProtocol:
                    break

        if not chosenProtocol:
            continue

        for packetWrapper in streamPacketList:
            networkData = _getPacketNetworkData(packetWrapper)
            if not isinstance(networkData, dict):
                continue
            networkData[f"{transportPrefix}.proto"] = chosenProtocol
            networkData["app.proto"] = chosenProtocol
            networkData["application.proto"] = chosenProtocol
            networkData["Port Protocol"] = chosenProtocol
            networkData["Port Protcol"] = chosenProtocol


def buildHostsPayload(packetEntries, finalSummary=""):
    """
    Build a frontend-compatible hosts payload from packet entries.
    """
    normalizeStreamApplicationProtocols(packetEntries)

    packetMapByHost = {}
    for entry in packetEntries:
        host = entry.get("host")
        if host not in packetMapByHost:
            packetMapByHost[host] = []
        packetMapByHost[host].append(entry.get("packet"))

    packetMapByHost = sortAndIndexPackets(packetMapByHost)
    return {"host": packetMapByHost, "final.summary": finalSummary}


def writeHostsSnapshot(
    outputDirPath,
    packetEntries,
    finalSummary="",
    outputFilename=hostOutputFile,
):
    """
    Build and write a complete hosts snapshot file from the supplied packet entries.
    Each snapshot remains frontend-compatible and self-contained.
    """
    payload = buildHostsPayload(packetEntries, finalSummary)
    snapshotPath = outputDirPath + "/" + outputFilename
    with open(snapshotPath, "w+", encoding="utf-8") as snapshotFile:
        snapshotFile.write(json.dumps(payload, indent=2))
    return snapshotPath

def emitBridgeProgress(
    pathValue,
    processedPackets,
    totalPackets,
    isFinal,
    captureData=None,
    jobId=None,
):
    """
    Emit backend progress in the legacy stderr format and, when configured,
    forward a structured payload to the TCP bridge callback.
    """

    finalFlag = 1 if isFinal else 0
    line = (
        f"{progressLinePrefix} path={pathValue} processed={processedPackets} "
        + f"total={totalPackets} final={finalFlag}"
    )
    normalizedJobId = str(jobId or "").strip()
    if normalizedJobId:
        line += f" jobId={normalizedJobId}"
    print(line, file=sys.stderr)

    if callable(progressEventCallback):
        try:
            payload = {
                "path": pathValue,
                "processedPackets": int(processedPackets),
                "totalPackets": int(totalPackets),
                "complete": bool(isFinal),
            }
            if normalizedJobId:
                payload["jobId"] = normalizedJobId
            if isinstance(captureData, dict):
                payload["captureData"] = captureData
            progressEventCallback(payload)
        except Exception:
            # Progress callback failures should not interrupt capture processing.
            pass


def emitBridgeProgressOnly(processedPackets, totalPackets, jobId=None):
    """
    Emit a lightweight progress-only update (no capture data, no snapshot
    path) so the frontend can keep the processing-warning banner ticking
    after the early-yield threshold has been reached and full snapshot
    emission is suspended.

    The stderr line uses the same ``[Bridge]`` prefix as
    :func:`emitBridgeProgress` but omits ``path=`` so the legacy
    file-based bridge (which only forwards events that carry a path)
    will skip it while the HTTP/NDJSON bridge forwards the structured
    payload to the renderer.
    """

    line = (
        f"{progressLinePrefix} processed={processedPackets} "
        + f"total={totalPackets} final=0 progressOnly=1"
    )
    normalizedJobId = str(jobId or "").strip()
    if normalizedJobId:
        line += f" jobId={normalizedJobId}"
    print(line, file=sys.stderr)

    if callable(progressEventCallback):
        try:
            payload = {
                "processedPackets": int(processedPackets),
                "totalPackets": int(totalPackets),
                "complete": False,
                "progressOnly": True,
            }
            if normalizedJobId:
                payload["jobId"] = normalizedJobId
            progressEventCallback(payload)
        except Exception:
            # Progress callback failures should not interrupt capture processing.
            pass


@lru_cache(maxsize=4096)
def getNetclass(ip):
    """
    Determine the network class (A, B, C, or Unknown) of an IPv4 address.
    Cached to avoid repeated parsing of the same IP addresses.
    """
    try:
        ipAddressObj = ipaddress.ip_address(ip)
    except Exception:
        return "Invalid IP"

    # IPv6 addresses do not map to legacy IPv4 classes.
    if isinstance(ipAddressObj, ipaddress.IPv6Address):
        return "IPv6"

    # Get the first octet
    firstOctet = int(str(ipAddressObj).split(".")[0])
    # Determine the class
    if 1 <= firstOctet <= 127:
        return "A"
    elif 128 <= firstOctet <= 191:
        return "B"
    elif 192 <= firstOctet <= 223:
        return "C"
    elif 224 <= firstOctet <= 239:
        return "D"
    elif 240 <= firstOctet <= 255:
        return "E"
    else:
        return "Invalid IP"


def safeDecompress(compressedData):
    """
    Safely decompress gzip or zlib-compressed data.
    Returns the decompressed bytes, or empty bytes on error.
    """

    # Initialize decompressor
    # Handle gzip and zlib formats
    decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
    result = b""
    try:
        result = decompressor.decompress(compressedData)
        result += decompressor.flush()
    except zlib.error:
        pass
    return result


def getGeoipInfo(ip, srcOrDst):
    """
    Look up GeoIP information (country, city, postal code, timezone) for an IP address.
    Uses geoIpReader opened once at startup and a per-session cache dict so that
    repeated lookups for the same IP cost nothing beyond a dict read.
    Returns a dictionary with location data or error message.
    """
    if geoIpReader is None:
        return {"Location": "Error: GeoIP database not found!"}

    # Check cache first (lock only for the brief check/insert, not for the DB query)
    geoIpCacheKey = (ip, srcOrDst)
    with geoIpCacheLock:
        if geoIpCacheKey in geoIpCache:
            return geoIpCache[geoIpCacheKey]

    try:
        geoIpResponse = geoIpReader.city(ip)
        if srcOrDst == "src":
            geoIpResult = {
                "Country": geoIpResponse.country.name,
                "loc.src.country": geoIpResponse.country.name,
                "City": geoIpResponse.city.name,
                "loc.src.city": geoIpResponse.city.name,
                "Latitude": geoIpResponse.location.latitude,  # type: ignore
                "loc.src.lat": geoIpResponse.location.latitude,  # type: ignore
                "Longitude": geoIpResponse.location.longitude,  # type: ignore
                "loc.src.lon": geoIpResponse.location.longitude,  # type: ignore
                "Postal Code": geoIpResponse.postal.code,  # type: ignore
                "loc.src.postal": geoIpResponse.postal.code,  # type: ignore
                "Time Zone": geoIpResponse.location.time_zone,  # type: ignore
                "loc.src.tz": geoIpResponse.location.time_zone,  # type: ignore
                "loc.src.timezone": geoIpResponse.location.time_zone,  # type: ignore
            }
        else:  # srcOrDst == "dst"
            geoIpResult = {
                "Country": geoIpResponse.country.name,
                "loc.dst.country": geoIpResponse.country.name,
                "City": geoIpResponse.city.name,
                "loc.dst.city": geoIpResponse.city.name,
                "Latitude": geoIpResponse.location.latitude,  # type: ignore
                "loc.dst.lat": geoIpResponse.location.latitude,  # type: ignore
                "Longitude": geoIpResponse.location.longitude,  # type: ignore
                "loc.dst.lon": geoIpResponse.location.longitude,  # type: ignore
                "Postal Code": geoIpResponse.postal.code,  # type: ignore
                "loc.dst.postal": geoIpResponse.postal.code,  # type: ignore
                "Time Zone": geoIpResponse.location.time_zone,  # type: ignore
                "loc.dst.tz": geoIpResponse.location.time_zone,  # type: ignore
                "loc.dst.timezone": geoIpResponse.location.time_zone,  # type: ignore
            }
    except geoip2.errors.AddressNotFoundError:  # type: ignore
        geoIpResult = {"Location": "Localnet"}
    except Exception as e:
        geoIpResult = {"Location": "Error: " + str(e)}

    # Store in cache so subsequent calls for this IP are instant
    with geoIpCacheLock:
        geoIpCache[geoIpCacheKey] = geoIpResult
    return geoIpResult


def buildGeoipLookupResponse(ip, srcOrDst="src"):
    """
    Return a normalized GeoIP lookup payload for ad-hoc frontend queries.
    """
    normalizedIp = str(ipaddress.ip_address(str(ip).strip()))
    normalizedSide = "dst" if str(srcOrDst).strip().lower() == "dst" else "src"
    locationData = getGeoipInfo(normalizedIp, normalizedSide)
    locationStatus = ""
    if isinstance(locationData, dict):
        locationStatus = str(locationData.get("Location") or "").strip()

    latitude = None
    longitude = None
    if isinstance(locationData, dict):
        rawLatitude = locationData.get("Latitude")
        rawLongitude = locationData.get("Longitude")
        try:
            latitude = float(rawLatitude) if rawLatitude is not None else None
        except Exception:
            latitude = None
        try:
            longitude = float(rawLongitude) if rawLongitude is not None else None
        except Exception:
            longitude = None

    isLocalnet = locationStatus.lower() == "localnet"
    isError = locationStatus.lower().startswith("error:")
    return {
        "success": not isError,
        "ip": normalizedIp,
        "version": 6 if ":" in normalizedIp else 4,
        "side": normalizedSide,
        "isLocalnet": isLocalnet,
        "isError": isError,
        "location": locationData,
        "mapPoint": {
            "latitude": latitude,
            "longitude": longitude,
        }
        if latitude is not None and longitude is not None
        else None,
    }


def _extractRdapVcardField(vcardEntries, fieldName):
    if not isinstance(vcardEntries, list):
        return ""
    targetKey = str(fieldName or "").strip().lower()
    for entry in vcardEntries:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        key = str(entry[0] or "").strip().lower()
        if key != targetKey:
            continue
        value = entry[3]
        if isinstance(value, list):
            value = " ".join(str(item) for item in value if item is not None)
        return str(value or "").strip()
    return ""


def _extractRdapEntityDisplayName(entity):
    if not isinstance(entity, dict):
        return ""
    vcardArray = entity.get("vcardArray")
    vcardEntries = vcardArray[1] if isinstance(vcardArray, list) and len(vcardArray) > 1 else []
    for fieldName in ("fn", "org", "name"):
        value = _extractRdapVcardField(vcardEntries, fieldName)
        if value:
            return value
    handle = str(entity.get("handle") or "").strip()
    return handle


def _extractRdapBestIspName(entities):
    if not isinstance(entities, list):
        return ""

    preferredRoles = [
        "registrant",
        "technical",
        "administrative",
        "abuse",
    ]

    bestName = ""
    bestScore = 10**9
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = [str(role or "").strip().lower() for role in entity.get("roles") or []]
        roleScore = len(preferredRoles)
        for idx, preferredRole in enumerate(preferredRoles):
            if preferredRole in roles:
                roleScore = idx
                break
        displayName = _extractRdapEntityDisplayName(entity)
        if not displayName:
            continue
        if roleScore < bestScore:
            bestScore = roleScore
            bestName = displayName

    return bestName


def _extractRdapEventDate(events, actionTokens):
    if not isinstance(events, list):
        return ""
    normalizedTokens = [str(token or "").strip().lower() for token in actionTokens]
    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction") or "").strip().lower()
        if not action:
            continue
        if not any(token in action for token in normalizedTokens):
            continue
        eventDate = str(event.get("eventDate") or "").strip()
        if eventDate:
            return eventDate
    return ""


def buildWhoisLookupResponse(ip):
    """
    Return WHOIS-like ownership metadata by querying RDAP.
    """
    normalizedIp = str(ipaddress.ip_address(str(ip).strip()))
    ipObj = ipaddress.ip_address(normalizedIp)

    if (
        ipObj.is_private
        or ipObj.is_loopback
        or ipObj.is_link_local
        or ipObj.is_multicast
        or ipObj.is_reserved
        or ipObj.is_unspecified
    ):
        return {
            "success": True,
            "ip": normalizedIp,
            "version": 6 if ipObj.version == 6 else 4,
            "isLocalnet": True,
            "whois": {
                "isp": "Local / special-use",
                "netName": "N/A",
                "netType": "N/A",
                "parent": "N/A",
                "registrationDate": "N/A",
                "updatedDate": "N/A",
                "rangeStart": normalizedIp,
                "rangeEnd": normalizedIp,
                "cidr": "N/A",
                "rirHost": "N/A",
                "rdapUrl": "",
            },
        }

    rdapUrls = [
        f"https://rdap.arin.net/registry/ip/{normalizedIp}",
        f"https://rdap.db.ripe.net/ip/{normalizedIp}",
        f"https://rdap.apnic.net/ip/{normalizedIp}",
        f"https://rdap.lacnic.net/rdap/ip/{normalizedIp}",
        f"https://rdap.afrinic.net/rdap/ip/{normalizedIp}",
    ]

    lastError = "RDAP lookup failed"
    rdapPayload = None
    finalUrl = ""
    for rdapUrl in rdapUrls:
        try:
            response = requests.get(
                rdapUrl,
                timeout=6,
                verify=False,
                headers=packetSnitchRequestHeaders(
                    "application/rdap+json, application/json"
                ),
            )
            if response.status_code >= 400:
                lastError = f"RDAP HTTP {response.status_code}"
                continue
            rdapPayload = response.json()
            finalUrl = str(response.url or rdapUrl)
            break
        except Exception as rdapError:
            lastError = str(rdapError)

    if not isinstance(rdapPayload, dict):
        return {
            "success": False,
            "ip": normalizedIp,
            "version": 6 if ipObj.version == 6 else 4,
            "error": lastError,
        }

    rangeStart = str(rdapPayload.get("startAddress") or normalizedIp).strip()
    rangeEnd = str(rdapPayload.get("endAddress") or rangeStart).strip()
    netName = str(rdapPayload.get("name") or rdapPayload.get("handle") or "Unknown").strip()
    netType = str(rdapPayload.get("type") or rdapPayload.get("objectClassName") or "Unknown").strip()
    parent = str(rdapPayload.get("parentHandle") or rdapPayload.get("port43") or "Unknown").strip()
    events = rdapPayload.get("events") or []
    registrationDate = _extractRdapEventDate(events, ["registration", "allocated", "assignment"])
    updatedDate = _extractRdapEventDate(events, ["last changed", "last update", "updated", "changed"])

    isp = _extractRdapBestIspName(rdapPayload.get("entities") or [])
    if not isp:
        isp = str(rdapPayload.get("country") or netName or "Unknown").strip()

    cidr = ""
    cidrEntries = rdapPayload.get("cidr0_cidrs")
    if isinstance(cidrEntries, list) and len(cidrEntries) > 0 and isinstance(cidrEntries[0], dict):
        firstCidr = cidrEntries[0]
        prefixKey = "v6prefix" if "v6prefix" in firstCidr else "v4prefix"
        prefixVal = str(firstCidr.get(prefixKey) or "").strip()
        lengthVal = firstCidr.get("length")
        if prefixVal and lengthVal is not None:
            cidr = f"{prefixVal}/{lengthVal}"

    return {
        "success": True,
        "ip": normalizedIp,
        "version": 6 if ipObj.version == 6 else 4,
        "isLocalnet": False,
        "whois": {
            "isp": isp or "Unknown",
            "netName": netName or "Unknown",
            "netType": netType or "Unknown",
            "parent": parent or "Unknown",
            "registrationDate": registrationDate or "Unknown",
            "updatedDate": updatedDate or "Unknown",
            "rangeStart": rangeStart or normalizedIp,
            "rangeEnd": rangeEnd or normalizedIp,
            "cidr": cidr or "Unknown",
            "rirHost": str(urlparse(finalUrl).hostname or "Unknown").strip(),
            "rdapUrl": finalUrl,
        },
    }


def getIpsumCacheDirectory():
    basePath = PACKETSNITCH_USERDATA_PATH or os.path.join(
        tempfile.gettempdir(), "packetsnitch-cache"
    )
    cacheDir = os.path.join(basePath, "cache", "ipsum")
    os.makedirs(cacheDir, exist_ok=True)
    return cacheDir


def getIpsumCachePaths():
    cacheDir = getIpsumCacheDirectory()
    return {
        "dir": cacheDir,
        "data": os.path.join(cacheDir, "ipsum.txt"),
        "meta": os.path.join(cacheDir, "ipsum-meta.json"),
    }


def parseIpsumDataset(rawText):
    parsed = {}
    if not isinstance(rawText, str):
        return parsed
    for rawLine in rawText.splitlines():
        line = rawLine.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        ipText = str(parts[0] or "").strip()
        countText = str(parts[1] or "").strip()
        try:
            normalizedIp = str(ipaddress.ip_address(ipText))
            parsed[normalizedIp] = max(0, int(countText))
        except Exception:
            continue
    return parsed


def getIpsumDailyCache():
    global ipsumDatasetByIp
    global ipsumCacheDate

    todayStr = datetime.utcnow().strftime("%Y-%m-%d")
    with ipsumCacheLock:
        if (
            ipsumCacheDate == todayStr
            and isinstance(ipsumDatasetByIp, dict)
            and ipsumDatasetByIp
        ):
            return {
                "dataset": ipsumDatasetByIp,
                "fetchedDate": ipsumCacheDate,
                "sourceUrl": IPSUM_SOURCE_URL,
            }

        cachePaths = getIpsumCachePaths()
        meta = {}
        if os.path.isfile(cachePaths["meta"]):
            try:
                with open(cachePaths["meta"], "r", encoding="utf-8") as metaFile:
                    meta = json.load(metaFile)
            except Exception:
                meta = {}

        cachedDate = str(meta.get("fetched_date") or "").strip()
        if cachedDate == todayStr and os.path.isfile(cachePaths["data"]):
            with open(cachePaths["data"], "r", encoding="utf-8") as dataFile:
                rawText = dataFile.read()
            ipsumDatasetByIp = parseIpsumDataset(rawText)
            ipsumCacheDate = todayStr
            return {
                "dataset": ipsumDatasetByIp,
                "fetchedDate": ipsumCacheDate,
                "sourceUrl": IPSUM_SOURCE_URL,
            }

        response = requests.get(
            IPSUM_SOURCE_URL,
            timeout=20,
            verify=False,
            headers=packetSnitchRequestHeaders("text/plain"),
        )
        response.raise_for_status()
        rawText = response.text
        parsedDataset = parseIpsumDataset(rawText)

        tempDataPath = cachePaths["data"] + ".tmp"
        tempMetaPath = cachePaths["meta"] + ".tmp"
        with open(tempDataPath, "w", encoding="utf-8") as dataFile:
            dataFile.write(rawText)
        with open(tempMetaPath, "w", encoding="utf-8") as metaFile:
            json.dump(
                {
                    "source_url": IPSUM_SOURCE_URL,
                    "project_url": IPSUM_PROJECT_URL,
                    "fetched_at": datetime.utcnow().isoformat() + "Z",
                    "fetched_date": todayStr,
                    "entry_count": len(parsedDataset),
                },
                metaFile,
                indent=2,
            )
        os.replace(tempDataPath, cachePaths["data"])
        os.replace(tempMetaPath, cachePaths["meta"])

        ipsumDatasetByIp = parsedDataset
        ipsumCacheDate = todayStr
        return {
            "dataset": ipsumDatasetByIp,
            "fetchedDate": ipsumCacheDate,
            "sourceUrl": IPSUM_SOURCE_URL,
        }


def getIpsumGrade(hitCount):
    hits = max(0, int(hitCount or 0))
    if hits <= 0:
        return {"grade": "A", "label": "Clean"}
    if hits <= 2:
        return {"grade": "B", "label": "Low"}
    if hits <= 5:
        return {"grade": "C", "label": "Elevated"}
    if hits <= 10:
        return {"grade": "D", "label": "High"}
    return {"grade": "F", "label": "Severe"}


def buildIpsumLookupResponse(ip):
    normalizedIp = str(ipaddress.ip_address(str(ip).strip()))
    ipObj = ipaddress.ip_address(normalizedIp)

    if ipObj.version != 4:
        return {
            "success": True,
            "ip": normalizedIp,
            "version": ipObj.version,
            "supported": False,
            "message": "IPSum currently provides IPv4 reputation data only.",
            "projectUrl": IPSUM_PROJECT_URL,
            "sourceUrl": IPSUM_SOURCE_URL,
        }

    if (
        ipObj.is_private
        or ipObj.is_loopback
        or ipObj.is_link_local
        or ipObj.is_multicast
        or ipObj.is_reserved
        or ipObj.is_unspecified
    ):
        return {
            "success": True,
            "ip": normalizedIp,
            "version": 4,
            "supported": True,
            "listed": False,
            "isLocalnet": True,
            "grade": "A",
            "gradeLabel": "Local / special-use",
            "hitCount": 0,
            "projectUrl": IPSUM_PROJECT_URL,
            "sourceUrl": IPSUM_SOURCE_URL,
            "fetchedDate": datetime.utcnow().strftime("%Y-%m-%d"),
        }

    cacheData = getIpsumDailyCache()
    dataset = cacheData.get("dataset") or {}
    hitCount = max(0, int(dataset.get(normalizedIp, 0)))
    gradeInfo = getIpsumGrade(hitCount)
    return {
        "success": True,
        "ip": normalizedIp,
        "version": 4,
        "supported": True,
        "listed": hitCount > 0,
        "isLocalnet": False,
        "grade": gradeInfo["grade"],
        "gradeLabel": gradeInfo["label"],
        "hitCount": hitCount,
        "projectUrl": IPSUM_PROJECT_URL,
        "sourceUrl": cacheData.get("sourceUrl") or IPSUM_SOURCE_URL,
        "fetchedDate": cacheData.get("fetchedDate") or "",
    }


def _extractTorIpFromAddress(addressText):
    rawAddress = str(addressText or "").strip()
    if not rawAddress:
        return ""
    if rawAddress.startswith("[") and "]" in rawAddress:
        return rawAddress[1:rawAddress.index("]")].strip()
    if rawAddress.count(":") == 1:
        return rawAddress.rsplit(":", 1)[0].strip()
    return rawAddress


def getTorExitNodeCache():
    global torNetworkNodesByIp
    global torNetworkIps
    global torNetworkCacheDate

    todayStr = datetime.utcnow().strftime("%Y-%m-%d")
    with torNetworkCacheLock:
        if torNetworkCacheDate == todayStr and torNetworkNodesByIp:
            return {
                "nodesByIp": torNetworkNodesByIp,
                "primaryByIp": torNetworkIps,
                "fetchedDate": torNetworkCacheDate,
                "sourceUrl": TOR_ONIONOO_URL,
            }

    response = requests.get(
        TOR_ONIONOO_URL,
        timeout=25,
        verify=False,
        headers=packetSnitchRequestHeaders("application/json"),
    )
    response.raise_for_status()
    payload = response.json()

    nodesByIp = {}
    primaryByIp = {}
    relays = payload.get("relays", []) if isinstance(payload, dict) else []
    for relay in relays:
        if not isinstance(relay, dict):
            continue
        nodeInfo = {
            "nickname": str(relay.get("nickname") or "Unknown"),
            "platform": str(relay.get("platform") or "Unknown"),
            "fingerprint": str(relay.get("fingerprint") or ""),
            "orAddresses": list(relay.get("or_addresses") or []),
        }
        for address in nodeInfo["orAddresses"]:
            torIp = _extractTorIpFromAddress(address)
            if not torIp:
                continue
            try:
                torIp = str(ipaddress.ip_address(torIp))
            except Exception:
                continue
            nodesByIp.setdefault(torIp, []).append(nodeInfo)
            primaryByIp.setdefault(torIp, nodeInfo)

    with torNetworkCacheLock:
        torNetworkNodesByIp = nodesByIp
        torNetworkIps = primaryByIp
        torNetworkCacheDate = todayStr

    return {
        "nodesByIp": torNetworkNodesByIp,
        "primaryByIp": torNetworkIps,
        "fetchedDate": torNetworkCacheDate,
        "sourceUrl": TOR_ONIONOO_URL,
    }


def buildTorLookupResponse(ip):
    normalizedIp = str(ipaddress.ip_address(str(ip).strip()))
    try:
        cacheData = getTorExitNodeCache()
    except Exception as torLookupError:
        return {
            "success": False,
            "ip": normalizedIp,
            "error": str(torLookupError),
            "sourceUrl": TOR_PROJECT_URL,
        }

    nodesByIp = cacheData.get("nodesByIp") or {}
    matchedNodes = nodesByIp.get(normalizedIp, [])
    return {
        "success": True,
        "ip": normalizedIp,
        "version": 6 if ":" in normalizedIp else 4,
        "listed": bool(matchedNodes),
        "isExitNode": bool(matchedNodes),
        "nodeCount": len(matchedNodes),
        "nodes": matchedNodes,
        "fetchedDate": cacheData.get("fetchedDate") or "",
        "sourceUrl": cacheData.get("sourceUrl") or TOR_ONIONOO_URL,
        "projectUrl": TOR_PROJECT_URL,
    }


def buildShodanInternetDbLookupResponse(ip):
    normalizedIp = str(ipaddress.ip_address(str(ip).strip()))
    ipObj = ipaddress.ip_address(normalizedIp)

    if (
        ipObj.is_private
        or ipObj.is_loopback
        or ipObj.is_link_local
        or ipObj.is_multicast
        or ipObj.is_reserved
        or ipObj.is_unspecified
    ):
        return {
            "success": True,
            "ip": normalizedIp,
            "version": ipObj.version,
            "supported": False,
            "message": "Local / special-use IPs are not indexed by Shodan InternetDB.",
            "sourceUrl": SHODAN_INTERNETDB_URL,
            "projectUrl": SHODAN_INTERNETDB_DOCS_URL,
            "cpes": [],
            "hostnames": [],
            "ports": [],
            "tags": [],
            "vulns": [],
        }

    try:
        response = requests.get(
            f"{SHODAN_INTERNETDB_URL}/{normalizedIp}",
            timeout=8,
            verify=False,
            headers=packetSnitchRequestHeaders("application/json"),
        )
    except Exception as lookupError:
        return {
            "success": False,
            "ip": normalizedIp,
            "version": ipObj.version,
            "error": str(lookupError),
            "sourceUrl": SHODAN_INTERNETDB_URL,
            "projectUrl": SHODAN_INTERNETDB_DOCS_URL,
        }

    if response.status_code >= 400:
        errorDetail = ""
        try:
            errorPayload = response.json()
            if isinstance(errorPayload, dict):
                errorDetail = str(
                    errorPayload.get("detail")
                    or errorPayload.get("error")
                    or errorPayload.get("message")
                    or ""
                ).strip()
        except Exception:
            errorDetail = str(response.text or "").strip()

        if not errorDetail:
            errorDetail = "No Shodan InternetDB data found for this IP."

        return {
            "success": False,
            "ip": normalizedIp,
            "version": ipObj.version,
            "error": f"HTTP {response.status_code}: {errorDetail}",
            "sourceUrl": SHODAN_INTERNETDB_URL,
            "projectUrl": SHODAN_INTERNETDB_DOCS_URL,
        }

    try:
        payload = response.json()
    except Exception:
        return {
            "success": False,
            "ip": normalizedIp,
            "version": ipObj.version,
            "error": "Invalid JSON received from Shodan InternetDB.",
            "sourceUrl": SHODAN_INTERNETDB_URL,
            "projectUrl": SHODAN_INTERNETDB_DOCS_URL,
        }

    if not isinstance(payload, dict):
        return {
            "success": False,
            "ip": normalizedIp,
            "version": ipObj.version,
            "error": "Unexpected response payload from Shodan InternetDB.",
            "sourceUrl": SHODAN_INTERNETDB_URL,
            "projectUrl": SHODAN_INTERNETDB_DOCS_URL,
        }

    return {
        "success": True,
        "ip": str(payload.get("ip") or normalizedIp),
        "version": ipObj.version,
        "supported": True,
        "cpes": payload.get("cpes") if isinstance(payload.get("cpes"), list) else [],
        "hostnames": payload.get("hostnames") if isinstance(payload.get("hostnames"), list) else [],
        "ports": payload.get("ports") if isinstance(payload.get("ports"), list) else [],
        "tags": payload.get("tags") if isinstance(payload.get("tags"), list) else [],
        "vulns": payload.get("vulns") if isinstance(payload.get("vulns"), list) else [],
        "sourceUrl": SHODAN_INTERNETDB_URL,
        "projectUrl": SHODAN_INTERNETDB_DOCS_URL,
    }


def _detectVirusTotalLookupType(lookupValue):
    value = str(lookupValue or "").strip()
    if not value:
        return None

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", value, re.IGNORECASE):
        return "hash"

    # Loose URL detection: scheme://host or host.tld/path. Reject plain IPs/hex hashes already handled.
    if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        return "url"
    if re.match(r"^[^\s/]+\.[a-z]{2,}(?:[/:].*)?$", value, re.IGNORECASE):
        return "url"

    return None


def _normalizeVirusTotalLookupType(rawLookupType):
    lookupType = str(rawLookupType or "").strip().lower()
    if lookupType in {"auto", "autodetect", "detect", "", "ip", "ip-address", "ip_address", "ipaddress"}:
        return "ip"
    if lookupType in {"url", "uri"}:
        return "url"
    if lookupType in {"hash", "file", "file-hash", "file_hash"}:
        return "hash"
    if lookupType in {"analysis", "file-analysis", "file_analysis"}:
        return "analysis"
    raise ValueError("Unsupported VirusTotal lookup type. Use ip, url, or hash.")


def _buildVirusTotalTargetPath(lookupType, lookupValue):
    normalizedValue = str(lookupValue or "").strip()
    if not normalizedValue:
        raise ValueError("Missing lookup value")

    normalizedType = _normalizeVirusTotalLookupType(lookupType)

    if normalizedType == "ip":
        normalizedIp = str(ipaddress.ip_address(normalizedValue))
        return f"/ip_addresses/{quote(normalizedIp)}", normalizedIp

    if normalizedType == "url":
        # VirusTotal URL lookups use URL-safe base64 without trailing '=' padding.
        urlId = base64.urlsafe_b64encode(normalizedValue.encode("utf-8")).decode("ascii").rstrip("=")
        if not urlId:
            raise ValueError("Invalid URL value")
        return f"/urls/{quote(urlId)}", normalizedValue

    if normalizedType == "analysis":
        if not re.fullmatch(r"[A-Za-z0-9_-]+", normalizedValue):
            raise ValueError("Analysis ID contains invalid characters.")
        return f"/analyses/{quote(normalizedValue)}", normalizedValue

    normalizedHash = normalizedValue.lower()
    if not re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", normalizedHash):
        raise ValueError("Hash lookup must be a valid MD5, SHA-1, or SHA-256 hex digest.")
    return f"/files/{quote(normalizedHash)}", normalizedHash


def buildVirusTotalLookupResponse(lookupType, lookupValue, apiKey, diagnosticOnly=False):
    normalizedApiKey = str(apiKey or "").strip()

    # Normalize lookup type; fall back to value-based auto-detection if not explicitly provided.
    try:
        normalizedType = _normalizeVirusTotalLookupType(lookupType)
    except ValueError:
        normalizedType = None
    if normalizedType in {None, "ip"}:
        detectedType = _detectVirusTotalLookupType(lookupValue)
        if detectedType:
            normalizedType = detectedType
    if not normalizedType:
        normalizedType = "ip"

    if diagnosticOnly:
        endpointUrl = f"{VIRUSTOTAL_API_BASE_URL}/ip_addresses/8.8.8.8"
        headers = packetSnitchRequestHeaders("application/json")
        if normalizedApiKey:
            headers["x-apikey"] = normalizedApiKey

        try:
            response = requests.get(
                endpointUrl,
                timeout=10,
                verify=False,
                headers=headers,
            )
        except Exception as diagnosticError:
            return {
                "success": False,
                "endpointReachable": False,
                "keyConfigured": bool(normalizedApiKey),
                "keyValid": False if normalizedApiKey else None,
                "error": str(diagnosticError),
                "sourceUrl": VIRUSTOTAL_API_BASE_URL,
            }

        keyValid = None
        if normalizedApiKey:
            keyValid = response.status_code not in {401, 403}

        return {
            "success": True,
            "endpointReachable": True,
            "keyConfigured": bool(normalizedApiKey),
            "keyValid": keyValid,
            "httpStatus": int(response.status_code),
            "sourceUrl": VIRUSTOTAL_API_BASE_URL,
        }

    if not normalizedApiKey:
        return {
            "success": False,
            "error": "Missing VirusTotal API key",
            "sourceUrl": VIRUSTOTAL_API_BASE_URL,
        }

    targetPath, normalizedValue = _buildVirusTotalTargetPath(normalizedType, lookupValue)

    headers = packetSnitchRequestHeaders("application/json")
    headers["x-apikey"] = normalizedApiKey

    response = requests.get(
        f"{VIRUSTOTAL_API_BASE_URL}{targetPath}",
        timeout=12,
        verify=False,
        headers=headers,
    )

    if response.status_code in {401, 403}:
        return {
            "success": False,
            "lookupType": normalizedType,
            "lookupValue": normalizedValue,
            "error": "VirusTotal API key is invalid or unauthorized.",
            "httpStatus": int(response.status_code),
            "sourceUrl": VIRUSTOTAL_API_BASE_URL,
        }

    if response.status_code == 404:
        return {
            "success": False,
            "lookupType": normalizedType,
            "lookupValue": normalizedValue,
            "error": "No VirusTotal record found for this query.",
            "httpStatus": int(response.status_code),
            "sourceUrl": VIRUSTOTAL_API_BASE_URL,
        }

    if response.status_code >= 400:
        return {
            "success": False,
            "lookupType": normalizedType,
            "lookupValue": normalizedValue,
            "error": f"VirusTotal request failed with HTTP {response.status_code}.",
            "httpStatus": int(response.status_code),
            "sourceUrl": VIRUSTOTAL_API_BASE_URL,
        }

    payload = response.json() if response.content else {}
    dataSection = payload.get("data") if isinstance(payload, dict) else {}
    if not isinstance(dataSection, dict):
        dataSection = {}
    attributes = dataSection.get("attributes") if isinstance(dataSection.get("attributes"), dict) else {}
    stats = attributes.get("last_analysis_stats") or attributes.get("stats")
    stats = stats if isinstance(stats, dict) else {}
    maliciousCount = int(stats.get("malicious") or 0)
    suspiciousCount = int(stats.get("suspicious") or 0)
    harmlessCount = int(stats.get("harmless") or 0)
    undetectedCount = int(stats.get("undetected") or 0)

    guiPath = (
        f"/ip-address/{quote(normalizedValue)}"
        if normalizedType == "ip"
        else f"/url/{quote(str(dataSection.get('id') or ''))}"
        if normalizedType == "url"
        else f"/file-analysis/{quote(normalizedValue)}"
        if normalizedType == "analysis"
        else f"/file/{quote(normalizedValue)}"
    )

    return {
        "success": True,
        "lookupType": "hash" if normalizedType == "analysis" else normalizedType,
        "lookupValue": normalizedValue,
        "recordId": str(dataSection.get("id") or ""),
        "analysis": {
            "malicious": maliciousCount,
            "suspicious": suspiciousCount,
            "harmless": harmlessCount,
            "undetected": undetectedCount,
            "timeout": int(stats.get("timeout") or 0),
            "confirmed_timeout": int(stats.get("confirmed-timeout") or 0),
            "failure": int(stats.get("failure") or 0),
            "type_unsupported": int(stats.get("type-unsupported") or 0),
        },
        "attributes": {
            "meaningful_name": attributes.get("meaningful_name"),
            # The UI only needs a small representative sample. Keeping the
            # complete names array here made older renderers show hundreds of
            # aliases as if they were separate technical findings.
            "names": attributes.get("names")[:3] if isinstance(attributes.get("names"), list) else [],
            "size": attributes.get("size"),
            "type_description": attributes.get("type_description"),
            "type_extension": attributes.get("type_extension"),
            "type_tag": attributes.get("type_tag"),
            "magic": attributes.get("magic"),
            "tags": attributes.get("tags") if isinstance(attributes.get("tags"), list) else [],
            "type_tags": attributes.get("type_tags") if isinstance(attributes.get("type_tags"), list) else [],
            "magika": attributes.get("magika"),
            "filecondis": attributes.get("filecondis") if isinstance(attributes.get("filecondis"), dict) else {},
            "times_submitted": attributes.get("times_submitted"),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_submission_date": attributes.get("last_submission_date"),
            "last_modification_date": attributes.get("last_modification_date"),
            "last_analysis_results": attributes.get("last_analysis_results")
                if isinstance(attributes.get("last_analysis_results"), dict) else {},
            "sigma_analysis_results": attributes.get("sigma_analysis_results")
                if isinstance(attributes.get("sigma_analysis_results"), list) else [],
            "sigma_analysis_stats": attributes.get("sigma_analysis_stats")
                if isinstance(attributes.get("sigma_analysis_stats"), dict) else {},
        },
        "reputation": attributes.get("reputation"),
        "lastAnalysisDate": attributes.get("last_analysis_date"),
        "raw": payload,
        "sourceUrl": VIRUSTOTAL_API_BASE_URL,
        "guiUrl": f"{VIRUSTOTAL_GUI_BASE_URL}{guiPath}",
    }


def buildVirusTotalUploadResponseSummary(payload):
    dataSection = payload.get("data") if isinstance(payload, dict) else {}
    if not isinstance(dataSection, dict):
        dataSection = {}
    attributes = dataSection.get("attributes") if isinstance(dataSection.get("attributes"), dict) else {}
    stats = attributes.get("stats") or attributes.get("last_analysis_stats") or {}
    fileInfo = payload.get("meta", {}).get("file_info", {}) if isinstance(payload, dict) else {}
    analysisId = str(dataSection.get("id") or "")
    sha256 = str(fileInfo.get("sha256") or "")
    return {
        "success": True,
        "lookupType": "hash",
        "lookupValue": sha256,
        "analysisId": analysisId,
        "analysis": {
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
            "harmless": int(stats.get("harmless") or 0),
            "undetected": int(stats.get("undetected") or 0),
            "timeout": int(stats.get("timeout") or 0),
        },
        "attributes": attributes,
        "recordId": analysisId,
        "raw": payload,
        "sourceUrl": VIRUSTOTAL_API_BASE_URL,
        "guiUrl": f"{VIRUSTOTAL_GUI_BASE_URL}/file-analysis/{quote(analysisId)}" if analysisId else None,
        "raw": payload,
    }


def uploadFileToVirusTotal(fileBuffer, fileName, apiKey):
    import hashlib
    import io

    headers = packetSnitchRequestHeaders("application/json")
    headers["x-apikey"] = str(apiKey or "").strip()
    files = {
        "file": (str(fileName), io.BytesIO(fileBuffer), "application/octet-stream"),
    }
    response = requests.post(
        f"{VIRUSTOTAL_API_BASE_URL}/files",
        files=files,
        headers=headers,
        timeout=30,
        verify=False,
    )
    if response.status_code in {401, 403}:
        raise Exception("VirusTotal API key is invalid or unauthorized.")
    if response.status_code == 429:
        raise Exception("VirusTotal rate limit exceeded. Wait before uploading again.")
    if response.status_code == 409:
        payload = response.json() if response.content else {}
        summary = buildVirusTotalUploadResponseSummary(payload)
        summary["alreadySubmitted"] = True
        return summary
    if response.status_code not in {200, 201}:
        raise Exception(f"VirusTotal upload failed with HTTP {response.status_code}: {response.text[:500]}")
    payload = response.json() if response.content else {}
    return buildVirusTotalUploadResponseSummary(payload)

def getTcpStreamKey(srcIp, srcPort, dstIp, dstPort):
    """
    Return a direction-agnostic key for a TCP stream.
    """
    endpointA = (str(srcIp), int(srcPort))
    endpointB = (str(dstIp), int(dstPort))
    return tuple(sorted((endpointA, endpointB)))


def getPacketNetworkLayer(packet):
    if packet is None:
        return None
    if packet.haslayer("IP"):
        return packet["IP"]
    if packet.haslayer("IPv6"):
        return packet["IPv6"]
    return None


def getPacketNetworkProtocolNumber(networkLayer):
    if networkLayer is None:
        return -1
    if hasattr(networkLayer, "proto"):
        return int(getattr(networkLayer, "proto", -1) or -1)
    if hasattr(networkLayer, "nh"):
        return int(getattr(networkLayer, "nh", -1) or -1)
    return -1


def getPacketNetworkChecksumHex(networkLayer):
    if networkLayer is None:
        return "N/A"
    try:
        return hex(int(getattr(networkLayer, "chksum")))
    except Exception:
        return "N/A"


def getPacketNetworkLength(networkLayer):
    if networkLayer is None:
        return 0
    try:
        return int(getattr(networkLayer, "len"))
    except Exception:
        try:
            return len(networkLayer)
        except Exception:
            return len(bytes(networkLayer))


def getPacketNetworkProtocolLabel(networkLayer):
    if networkLayer is None:
        return "IP"
    try:
        if int(getattr(networkLayer, "version", 4) or 4) == 6:
            return "IPv6"
    except Exception:
        pass
    return "IP"


def getOptionalHexInt(value, default="N/A"):
    try:
        return hex(int(value))
    except Exception:
        return default


def buildTcpStreamInitialDstPortMap(packetList):
    """
    Build a map of TCP stream key -> destination port from the stream's first packet
    in capture order.
    """
    streamMap = {}
    for p in packetList:
        networkLayer = getPacketNetworkLayer(p)
        if networkLayer is None or not p.haslayer("TCP"):
            continue
        streamKey = getTcpStreamKey(
            networkLayer.src, p["TCP"].sport, networkLayer.dst, p["TCP"].dport
        )
        if streamKey not in streamMap:
            streamMap[streamKey] = p["TCP"].dport
    return streamMap


def getDatatypes(data, srcPort, dstPort, sourceIp, destIp, timeout, protocol="tcp", initialDstPort=None, activeRecon=False):
    """
    Analyze data to determine MIME type, decompress if possible, and extract traits.
    Returns a dictionary with MIME type, decompression info, data types, and traits.
    The protocol parameter ("tcp" or "udp") is forwarded to getTraits for accurate
    port-description lookups.
    """
    mimeType = magic.from_buffer(data, mime=True)
    lineDescs = []
    decompData = ""
    decomprInfo = {"Decompressed": False}
    for ln in data.splitlines():
        lineDescs.append(magic.from_buffer(ln))
        decompData = safeDecompress(ln)
        if decompData and len(decompData) > 0:
            decomprInfo = {
                "Decompressed data": {
                    "Decompressed Hex Encoded": decompData.hex(),
                    "payload.decompressed.hex": decompData.hex(),
                    "Decompressed ASCII Encoded": decompData.decode(errors="ignore"),
                    "payload.decompressed.ascii": decompData.decode(errors="ignore"),
                },
            }
    uniqueDescs = list(set(lineDescs))
    if "empty" in uniqueDescs:
        uniqueDescs.remove("empty")
    if "data" in uniqueDescs:
        uniqueDescs.remove("data")
    if uniqueDescs == []:
        uniqueDescs = ["Unknown data type"]
    traitData = getTraits(data, srcPort,dstPort, sourceIp, destIp, timeout, protocol, initialDstPort=initialDstPort, activeRecon=activeRecon)
    dataTypeResult = {
        "MIME Type": mimeType,
        "payload.mime": mimeType,
        "Decompressed": decomprInfo,
        "payload.decompressed": decomprInfo,
        "Data Types": uniqueDescs,
        "Traits": traitData,
    }
    return dataTypeResult


@lru_cache(maxsize=1024)
def getServ(port, protocol="tcp"):
    """
    Return the service name for a given port and protocol using the system's services database.
    Cached with LRU to avoid repeated system calls for the same port/protocol.
    """

    try:
        serviceName = socket.getservbyport(port, protocol)
    except OSError:
        serviceName = "Unknown"
    if not serviceName:
        serviceName = "Unknown"
    return serviceName
    
def getTraits(data, srcPort, dstPort, sourceIp, destIp, timeout, protocol="tcp", initialDstPort=None, activeRecon=False):
    """
    Analyze data for entropy, charsetType, encoding, and network/server traits.
    Returns a dictionary with entropy, network data, length, server info, and character info.
    The protocol parameter ("tcp", "udp", or "sctp") is used for port-description lookups so that
    transport-specific service names and descriptions are resolved correctly.
    """

    protocol = str(protocol or "tcp").lower()
    protocolPrefix = protocol if protocol in ("tcp", "udp", "sctp") else "udp"
    protoName = ""
    byteCounts = np.bincount(list(data))
    shannonEntropy = entropy(byteCounts, base=2)
    dataLength = len(data)
    if protocol == "icmp":
        protoName = getIcmpApplicationProtocol(data)
    else:
        srcProtoName = getPortNameFromCSV(srcPort, protocol)
        dstProtoName = getPortNameFromCSV(initialDstPort if initialDstPort is not None else dstPort, protocol)

        if protocolPrefix == "sctp":
            inferredSctpProto = _inferSctpApplicationProtocol(
                data,
                srcPort,
                initialDstPort if initialDstPort is not None else dstPort,
            )
            if inferredSctpProto != "SCTP":
                protoName = inferredSctpProto

        if srcProtoName and dstProtoName:
            if srcPort >= 1024 and dstPort < 1024:
                protoName = dstProtoName
            elif dstPort >= 1024 and srcPort < 1024:
                protoName = srcProtoName
            else:
                protoName = srcProtoName if len(srcProtoName) < len(dstProtoName) else dstProtoName
        elif srcProtoName != "Unknown":
            protoName = srcProtoName
        elif dstProtoName != "Unknown":
            protoName = dstProtoName
        else:
            protoName = getServ(srcPort, protocol) or getServ(dstPort, protocol)
            if not protoName:
                protoName = "SCTP" if protocolPrefix == "sctp" else "Unknown"

    # normalize the protocol responses and remove anything after a space or slash (e.g., "http / ssl" -> "http")
    protoName = protoName.split(" ")[0].split("/")[0].lower()

    charsetType = "ascii" if all(32 <= b <= 126 for b in data) else "binary"
    uniqueCharCount = len(set(data))
    uniqueCharsSet = set(data)
    if activeRecon and protocolPrefix in ("tcp", "udp"):
        dnsHostnames = reverseDnsLookup(destIp)
    else:
        dnsHostnames = {
            "Resolved": False,
            "Error": "Active recon not performed",
            "Hostnames": [],
        }
    if activeRecon and dnsHostnames.get("Hostnames") is not None:
        banner = getServBanner(
            destIp,
            dstPort,
            timeout,
            dnsHostnames.get("Hostnames")[0]
            if dnsHostnames.get("Resolved")
            else destIp,  # ignore subscript warning, it checks for resolution first
            protoName,
        )
    else:
        banner = "Active recon not performed"
    encoding = chardet.detect(data)
    srcGeoInfo = getGeoipInfo(sourceIp, "src")
    dstGeoInfo = getGeoipInfo(destIp, "dst")
    srcNetClass = getNetclass(sourceIp)
    dstNetClass = getNetclass(destIp)
    portDesc = getPortDescription(dstPort, protocol)

    return {
        "Shannon Entropy": shannonEntropy,
        "payload.entropy": shannonEntropy,
        "Network Data": {
            "ip.src": {
                "Class": srcNetClass,
                "ip.src.class": srcNetClass,
                "network.src.class": srcNetClass,
                "Location": srcGeoInfo,
                "ip.src.location": srcGeoInfo,
                "network.src.location": srcGeoInfo,
            },
            "ip.dst": {
                "Class": dstNetClass,
                "ip.dst.class": dstNetClass,
                "network.dst.class": dstNetClass,   
                "Location": dstGeoInfo,
                "ip.dst.location": dstGeoInfo,
                "network.dst.location": dstGeoInfo,
            },
            "Port Protcol": protoName,
            f"{protocolPrefix}.proto": protoName,
            "app.proto": protoName,
            "application.proto": protoName,
            "Port Description": portDesc,
            f"{protocolPrefix}.desc": portDesc,
            "Hostnames": dnsHostnames,
            "dns.hostnames": dnsHostnames,
        },
        "Length": dataLength,
        "Server Info": banner,
        "host.banner": banner,
        "Characters": {
            "Charset": charsetType,
            "payload.charset": charsetType,
            "Encoding": encoding
            if shannonEntropy <= 4.85
            else "Unavailable for high entropy data",
            "payload.encoding": encoding
            if shannonEntropy <= 4.85
            else "Unavailable for high entropy data",
            "Characters used": uniqueCharCount,
            "payload.chars.used": uniqueCharCount,
            "Unique characters": bytearray(list(uniqueCharsSet)).hex(),
        },
    }


def macAddrToVendor(macAddr):
    """
    Return the vendor name for a MAC address.
    Uses macVendorMap dict loaded once at startup for O(1) macPrefix lookup.
    MAC prefixes are stored as the first 8 characters of the normalised address (e.g. "00:1A:2B").
    """
    macPrefix = macAddr[:8].upper()
    return macVendorMap.get(macPrefix, "Unknown Vendor")


def _formatLinkAddress(addrValue, addrLen=None):
    """
    Convert a link-layer address to a readable string.
    Returns "N/A" for empty/zero addresses.
    """
    if addrValue is None:
        return "N/A"

    rawAddr = None
    if isinstance(addrValue, (bytes, bytearray)):
        rawAddr = bytes(addrValue)
    elif isinstance(addrValue, int):
        byteLen = max(1, (addrValue.bit_length() + 7) // 8)
        rawAddr = addrValue.to_bytes(byteLen, "big")

    if rawAddr is not None:
        if isinstance(addrLen, int) and addrLen > 0 and len(rawAddr) >= addrLen:
            rawAddr = rawAddr[:addrLen]
        if not rawAddr or all(byte == 0 for byte in rawAddr):
            return "N/A"
        return ":".join(f"{byte:02x}" for byte in rawAddr)

    addrText = str(addrValue).strip()
    if not addrText or addrText == "00:00:00:00:00:00":
        return "N/A"
    return addrText


def _isLikelyMacAddress(value):
    """
    Return True when the provided value looks like a MAC address.
    """
    valueText = str(value or "").strip()
    if not valueText or valueText == "N/A":
        return False
    return bool(re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", valueText))


def _macToString(value):
    """
    Lightweight MAC/address formatter used by the wireless decoder paths.
    Returns "Broadcast" for the all-ones MAC and "N/A" for unknown values.
    """
    if value is None:
        return "N/A"
    try:
        text = str(value).strip()
    except Exception:
        return "N/A"
    if not text:
        return "N/A"
    if text == "ff:ff:ff:ff:ff:ff":
        return "Broadcast"
    if text == "00:00:00:00:00:00":
        return "N/A"
    return text


def extractLinkLayerInfo(p):
    """
    Return normalized link-layer metadata for Ethernet and Linux cooked packets.
    Returns a dict with keys: linkProto, srcAddr, dstAddr, linuxCooked.

    IEEE 802.11 (Wi-Fi) frames are also recognized here so that the rest of
    the pipeline can attach wireless metadata to the packet.
    """
    if dec_wireless_80211._looksLikeWifi(p):
        dot11Layer, _radioTapLayer, _encryptedLayer = dec_wireless_80211.getWirelessLayers(p)
        srcAddr = (
            _macToString(getattr(dot11Layer, "addr2", None)) if dot11Layer is not None else "N/A"
        )
        dstAddr = (
            _macToString(getattr(dot11Layer, "addr1", None)) if dot11Layer is not None else "N/A"
        )
        return {
            "linkProto": "IEEE 802.11",
            "srcAddr": srcAddr,
            "dstAddr": dstAddr,
            "linuxCooked": None,
        }

    etherClass = getattr(scapy, "Ether", None)
    if (etherClass and p.haslayer(etherClass)) or p.haslayer("Ether"):
        etherLayer = p[etherClass] if etherClass and p.haslayer(etherClass) else p["Ether"]
        return {
            "linkProto": "Ethernet",
            "srcAddr": str(getattr(etherLayer, "src", "N/A") or "N/A"),
            "dstAddr": str(getattr(etherLayer, "dst", "N/A") or "N/A"),
            "linuxCooked": None,
        }

    # IEEE 802.3 / 802.2 LLC frames (e.g. STP BPDUs) — Dot3 is not a
    # subclass of Ether, so we must check it separately.
    dot3Class = getattr(scapy, "Dot3", None)
    if (dot3Class and p.haslayer(dot3Class)) or p.haslayer("Dot3"):
        dot3Layer = p[dot3Class] if dot3Class and p.haslayer(dot3Class) else p["Dot3"]
        return {
            "linkProto": "IEEE 802.3",
            "srcAddr": str(getattr(dot3Layer, "src", "N/A") or "N/A"),
            "dstAddr": str(getattr(dot3Layer, "dst", "N/A") or "N/A"),
            "linuxCooked": None,
        }

    cookedV2Class = getattr(scapy, "CookedLinuxV2", None)
    cookedV1Class = getattr(scapy, "CookedLinux", None)
    cookedLayer = None
    cookedVersion = None

    if cookedV2Class and p.haslayer(cookedV2Class):
        cookedLayer = p[cookedV2Class]
        cookedVersion = "v2"
    elif cookedV1Class and p.haslayer(cookedV1Class):
        cookedLayer = p[cookedV1Class]
        cookedVersion = "v1"

    if cookedLayer is None:
        # Fall back to p.src / p.dst only when they look like link-layer addresses.
        srcAddr = _formatLinkAddress(getattr(p, "src", None))
        dstAddr = _formatLinkAddress(getattr(p, "dst", None))
        if not _isLikelyMacAddress(srcAddr):
            srcAddr = "N/A"
        if not _isLikelyMacAddress(dstAddr):
            dstAddr = "N/A"
        return {
            "linkProto": "Unknown",
            "srcAddr": srcAddr,
            "dstAddr": dstAddr,
            "linuxCooked": None,
        }

    try:
        lladdrLen = int(getattr(cookedLayer, "lladdrlen", 0) or 0)
    except Exception:
        lladdrLen = 0

    srcAddr = _formatLinkAddress(getattr(cookedLayer, "src", None), lladdrLen)

    try:
        packetType = int(getattr(cookedLayer, "pkttype", 0) or 0)
    except Exception:
        packetType = 0

    try:
        linkAddrType = int(getattr(cookedLayer, "lladdrtype", 0) or 0)
    except Exception:
        linkAddrType = 0

    protoValue = getattr(cookedLayer, "proto", None)
    if isinstance(protoValue, int):
        protoText = f"0x{protoValue:04x}"
    else:
        protoText = str(protoValue) if protoValue is not None else "N/A"

    linkProto = "Linux Cooked" if cookedVersion == "v1" else "Linux Cooked v2"
    linuxCookedSection = {
        "Version": cookedVersion.upper(),
        "sll.version": cookedVersion,
        "Packet Type": packetType,
        "sll.pkttype": packetType,
        "Link Address Type": linkAddrType,
        "sll.lladdrtype": linkAddrType,
        "Link Address Length": lladdrLen,
        "sll.lladdrlen": lladdrLen,
        "Source Link Address": srcAddr,
        "sll.src": srcAddr,
        "Protocol": protoText,
        "sll.proto": protoText,
    }

    if cookedVersion == "v2":
        try:
            ifIndex = int(getattr(cookedLayer, "ifindex", 0) or 0)
        except Exception:
            ifIndex = 0
        linuxCookedSection["Interface Index"] = ifIndex
        linuxCookedSection["sll.ifindex"] = ifIndex

    return {
        "linkProto": linkProto,
        "srcAddr": srcAddr,
        "dstAddr": "N/A",
        "linuxCooked": linuxCookedSection,
    }


SCTP_PORT_PROTOCOLS = {
    2904: "M2UA",
    2905: "M3UA",
    2906: "SUA",
    3565: "M2PA",
    9900: "IUA",
    2944: "H.248/MEGACO",
    3868: "Diameter",
    3869: "Diameter",
}


def isSctpPacket(p):
    try:
        if p.haslayer("SCTP"):
            return True
    except Exception:
        pass
    try:
        return int(getattr(p["IP"], "proto", -1)) == 132
    except Exception:
        return False


def _inferSctpApplicationProtocol(data, srcPort, dstPort):
    portProto = SCTP_PORT_PROTOCOLS.get(srcPort) or SCTP_PORT_PROTOCOLS.get(dstPort)
    if portProto:
        return portProto

    if len(data) >= 28 and int(data[12]) == 0:
        chunkLength = int.from_bytes(data[14:16], "big")
        if 28 <= chunkLength <= len(data):
            ppid = int.from_bytes(data[24:28], "big")
            if ppid == 7:
                return "H.248/MEGACO"
            if ppid == 3:
                return "M3UA"
            if ppid == 4:
                return "SUA"
            if ppid == 5:
                return "M2UA"
            if ppid == 6:
                return "M2PA"
            if ppid == 8:
                return "Diameter"

    return "SCTP"


def packetLoop(p, packetIndex, srcPortFilter, dstPortFilter, timeout):
    """
    Process a single scapy packet: extract TCP, UDP, or ICMP payload, write the raw
    testcase file, gather analysis data (MIME, entropy, geoip, etc.) and merge
    everything into a single JSON output file.  For UDP packets on port 53 the DNS
    layer is decoded.  SNMP (161/162), DHCP (67/68), NTP/SNTP (123), and SIP (5060/5061)
    packets are also decoded and included in the output.  SSH (22/2222, plus
    banner-based detection) is decoded for protocol metadata such as
    identification banner/version and transport packet framing. HTTP (any port whose payload
    looks like HTTP) and HTTP/2 (connection preface or binary frames) are decoded for
    both requests and responses.  FTP (20/21), SMTP (25/587/465), POP3/POP (110/995),
    IMAP/IMAP4 (143/993), Telnet (23), IRC (6667-6669), MTP (1755), LDAP (389/636),
    MySQL (3306), PostgreSQL (5432), XMPP (5222/5223), SMB (139/445), MQTT (1883/8883),
    RTSP (554), TFTP (UDP 69), BGP (179), NNTP (119), RADIUS (1812/1813/1645/1646),
    WebSocket (80/443/8080/8443/8765), NFS/RPC (2049/111), Kerberos (88), SMPP (2775),
    Soulseek (2234/2240/2242), BitTorrent (6881-6889/6969 + signature detection), and
    WAN/link-control protocols (ATM, Token Ring, Frame Relay, SDLC, HDLC, SLIP,
    PPP, LCP, LAP, NCP), IGMP, and ARP/RARP address-resolution frames are also
    decoded when layer data is available. ICMP packets are fully supported as a
    separate transport type.

    packetIndex is the 0-based position of this packet in the full capture, used as
    the filename index so files from concurrent threads do not collide.
    Returns the merged info dict, or None if the packet should be skipped.
    """
    # for every 250 packets, print a progress update with the packet index
    if packetIndex % 250 == 0:
        print(f"[Worker] Processing packet #{packetIndex}")
    initialDstPort = None
    linkLayerInfo = extractLinkLayerInfo(p)
    linkProto = linkLayerInfo["linkProto"]
    srcMacAddr = linkLayerInfo["srcAddr"]
    dstMacAddr = linkLayerInfo["dstAddr"]
    linuxCookedSection = linkLayerInfo["linuxCooked"]
    srcMacVendor = macAddrToVendor(srcMacAddr) if srcMacAddr != "N/A" else "N/A"
    dstMacVendor = macAddrToVendor(dstMacAddr) if dstMacAddr != "N/A" else "N/A"
    isSSH = False
    wanLinkSection = dec_wan_link.decodeWanLinkProtocols(p)
    networkLayer = getPacketNetworkLayer(p)

    # Decode ARP/RARP packets that do not carry an IP layer.
    if networkLayer is None:
        # Decode link-layer discovery protocols (CDP / LACP) that ride
        # directly on Ethernet EtherTypes 0x88cc / 0x8809 with no IP layer.
        # CDP may also be carried over 802.2 LLC/SNAP (OUI 00:00:0C,
        # SNAP code 0x2000) on classic 802.3 frames.
        etherLayer = None
        etherClass = getattr(scapy, "Ether", None)
        if (etherClass and p.haslayer(etherClass)) or p.haslayer("Ether"):
            etherLayer = p[etherClass] if etherClass and p.haslayer(etherClass) else p["Ether"]
        etherType = None
        if etherLayer is not None:
            try:
                etherType = int(getattr(etherLayer, "type", 0) or 0)
            except Exception:
                etherType = None
        # CDP over 802.3 LLC/SNAP — detect via the SNAP layer.
        snapCode = None
        snapClass = getattr(scapy, "SNAP", None)
        if (snapClass and p.haslayer(snapClass)) or p.haslayer("SNAP"):
            snapLayer = p[snapClass] if snapClass and p.haslayer(snapClass) else p["SNAP"]
            try:
                snapCode = int(getattr(snapLayer, "code", 0) or 0)
            except Exception:
                snapCode = None
        isCdpFrame = etherType == 0x88CC or snapCode == 0x2000
        isLacpFrame = etherType == 0x8809

        # STP BPDUs (IEEE 802.1D) ride on 802.2 LLC (DSAP=0x42 SSAP=0x42)
        # inside classic 802.3 frames — no EtherType, so we detect via the
        # LLC layer that scapy parses on Dot3 packets.
        isStpFrame = False
        llcClass = getattr(scapy, "LLC", None)
        if (llcClass and p.haslayer(llcClass)) or p.haslayer("LLC"):
            try:
                llcLayer = p[llcClass] if llcClass and p.haslayer(llcClass) else p["LLC"]
                llcDsap = int(getattr(llcLayer, "dsap", 0) or 0)
                llcSsap = int(getattr(llcLayer, "ssap", 0) or 0) & 0xFE
                if llcDsap == 0x42 and llcSsap == 0x42:
                    isStpFrame = True
            except Exception:
                pass

        if isStpFrame:
            # IEEE 802.1D Spanning Tree Protocol BPDU
            if etherLayer is not None:
                stpLinkRaw = bytes(etherLayer.payload)
            else:
                dot3Class = getattr(scapy, "Dot3", None)
                if (dot3Class and p.haslayer(dot3Class)) or p.haslayer("Dot3"):
                    dot3Layer = p[dot3Class] if dot3Class and p.haslayer(dot3Class) else p["Dot3"]
                    stpLinkRaw = bytes(dot3Layer.payload)
                else:
                    stpLinkRaw = bytes(p)
            stpSection = dec_stp.decodeSTP(p, stpLinkRaw)
            if stpSection is not None:
                timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                )
                protocolName = "STP"
                dstPortStr = "stp"
                try:
                    dataTypeInfo = getDatatypes(
                        stpLinkRaw, 0, 0, "0.0.0.0", "0.0.0.0", timeout, "udp",
                    )
                except Exception:
                    mimeType = magic.from_buffer(stpLinkRaw, mime=True)
                    dataTypeInfo = {
                        "MIME Type": mimeType,
                        "payload.mime": mimeType,
                        "Decompressed": {"Decompressed": False},
                        "payload.decompressed": {"Decompressed": False},
                        "Data Types": ["Unknown data type"],
                        "Traits": {"Length": len(stpLinkRaw)},
                    }
                packetInfo = {
                    "packet.processed": int(packetIndex),
                    "packet.timestamp": timestamp,
                    "packet.proto": protocolName,
                    "link.proto": protocolName,
                    "packet.decoded_protocols": [protocolName],
                    "Ethernet Frame": {
                        "ether.src.mac.addr": srcMacAddr,
                        "link.src.mac.addr": srcMacAddr,
                        "ether.dst.mac.addr": dstMacAddr,
                        "link.dst.mac.addr": dstMacAddr,
                        "ether.src.mac.vendor": srcMacVendor,
                        "link.src.mac.vendor": srcMacVendor,
                        "ether.dst.mac.vendor": dstMacVendor,
                        "link.dst.mac.vendor": dstMacVendor,
                    }
                    if (srcMacAddr != "N/A" or dstMacAddr != "N/A")
                    else "N/A",
                    "IP": "N/A",
                    protocolName: stpSection,
                    "Raw data": {
                        "Payload": {
                            "payload.hex": stpLinkRaw.hex(),
                            "payload.ascii": stpLinkRaw.decode(errors="ignore"),
                        },
                        "Packet": bytes(p).hex(),
                        "packet.hex": bytes(p).hex(),
                        "payload.len": len(stpLinkRaw),
                    },
                }
                if wanLinkSection is not None:
                    packetInfo["Link Control"] = wanLinkSection
                return joinInfo(
                    outputDir,
                    dstPortStr,
                    packetIndex,
                    _jsonDumpEncoded(dataTypeInfo),
                    _jsonDumpEncoded(packetInfo),
                    "0.0.0.0",
                )

        if isCdpFrame:
            # Cisco Discovery Protocol
            if snapCode == 0x2000 and p.haslayer("SNAP"):
                linkRaw = bytes(p["SNAP"].payload)
            else:
                linkRaw = bytes(etherLayer.payload) if etherLayer is not None else bytes(p)
            cdpSection = dec_cdp.decodeCDP(p, linkRaw)
            if cdpSection is not None:
                timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                )
                protocolName = "CDP"
                dstPortStr = "cdp"
                try:
                    dataTypeInfo = getDatatypes(
                        linkRaw, 0, 0, "0.0.0.0", "0.0.0.0", timeout, "udp",
                    )
                except Exception:
                    mimeType = magic.from_buffer(linkRaw, mime=True)
                    dataTypeInfo = {
                        "MIME Type": mimeType,
                        "payload.mime": mimeType,
                        "Decompressed": {"Decompressed": False},
                        "payload.decompressed": {"Decompressed": False},
                        "Data Types": ["Unknown data type"],
                        "Traits": {"Length": len(linkRaw)},
                    }
                packetInfo = {
                    "packet.processed": int(packetIndex),
                    "packet.timestamp": timestamp,
                    "packet.proto": protocolName,
                    "link.proto": protocolName,
                    "packet.decoded_protocols": [protocolName],
                    "Ethernet Frame": {
                        "ether.src.mac.addr": srcMacAddr,
                        "link.src.mac.addr": srcMacAddr,
                        "ether.dst.mac.addr": dstMacAddr,
                        "link.dst.mac.addr": dstMacAddr,
                        "ether.src.mac.vendor": srcMacVendor,
                        "link.src.mac.vendor": srcMacVendor,
                        "ether.dst.mac.vendor": dstMacVendor,
                        "link.dst.mac.vendor": dstMacVendor,
                    }
                    if (srcMacAddr != "N/A" or dstMacAddr != "N/A")
                    else "N/A",
                    "IP": "N/A",
                    protocolName: cdpSection,
                    "Raw data": {
                        "Payload": {
                            "payload.hex": linkRaw.hex(),
                            "payload.ascii": linkRaw.decode(errors="ignore"),
                        },
                        "Packet": bytes(p).hex(),
                        "packet.hex": bytes(p).hex(),
                        "payload.len": len(linkRaw),
                    },
                }
                if wanLinkSection is not None:
                    packetInfo["Link Control"] = wanLinkSection
                return joinInfo(
                    outputDir,
                    dstPortStr,
                    packetIndex,
                    _jsonDumpEncoded(dataTypeInfo),
                    _jsonDumpEncoded(packetInfo),
                    "0.0.0.0",
                )
        if isLacpFrame:
            # LACP / Marker (IEEE 802.3ad Link Aggregation)
            linkRaw = bytes(etherLayer.payload) if etherLayer is not None else bytes(p)
            lacpSection = dec_lacp.decodeLACP(p, linkRaw)
            if lacpSection is not None:
                timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
                    "%Y-%m-%d %H:%M:%S.%f"
                )
                protocolName = "LACP"
                dstPortStr = "lacp"
                try:
                    dataTypeInfo = getDatatypes(
                        linkRaw, 0, 0, "0.0.0.0", "0.0.0.0", timeout, "udp",
                    )
                except Exception:
                    mimeType = magic.from_buffer(linkRaw, mime=True)
                    dataTypeInfo = {
                        "MIME Type": mimeType,
                        "payload.mime": mimeType,
                        "Decompressed": {"Decompressed": False},
                        "payload.decompressed": {"Decompressed": False},
                        "Data Types": ["Unknown data type"],
                        "Traits": {"Length": len(linkRaw)},
                    }
                packetInfo = {
                    "packet.processed": int(packetIndex),
                    "packet.timestamp": timestamp,
                    "packet.proto": protocolName,
                    "link.proto": protocolName,
                    "packet.decoded_protocols": [protocolName],
                    "Ethernet Frame": {
                        "ether.src.mac.addr": srcMacAddr,
                        "link.src.mac.addr": srcMacAddr,
                        "ether.dst.mac.addr": dstMacAddr,
                        "link.dst.mac.addr": dstMacAddr,
                        "ether.src.mac.vendor": srcMacVendor,
                        "link.src.mac.vendor": srcMacVendor,
                        "ether.dst.mac.vendor": dstMacVendor,
                        "link.dst.mac.vendor": dstMacVendor,
                    }
                    if (srcMacAddr != "N/A" or dstMacAddr != "N/A")
                    else "N/A",
                    "IP": "N/A",
                    protocolName: lacpSection,
                    "Raw data": {
                        "Payload": {
                            "payload.hex": linkRaw.hex(),
                            "payload.ascii": linkRaw.decode(errors="ignore"),
                        },
                        "Packet": bytes(p).hex(),
                        "packet.hex": bytes(p).hex(),
                        "payload.len": len(linkRaw),
                    },
                }
                if wanLinkSection is not None:
                    packetInfo["Link Control"] = wanLinkSection
                return joinInfo(
                    outputDir,
                    dstPortStr,
                    packetIndex,
                    _jsonDumpEncoded(dataTypeInfo),
                    _jsonDumpEncoded(packetInfo),
                    "0.0.0.0",
                )
        arpDecoded = dec_address_resolution.decodeAddressResolutionPacket(p)
        if arpDecoded is not None:
            protocolName, arpSection, srcIp, dstIp = arpDecoded
            arpClass = getattr(scapy, "ARP", None)
            if arpClass and p.haslayer(arpClass):
                rawPayload = bytes(p[arpClass])
            elif p.haslayer("ARP"):
                rawPayload = bytes(p["ARP"])
            else:
                rawPayload = bytes(p)
            if rawPayload is None or len(rawPayload) == 0:
                return None

            dstPortStr = protocolName.lower()
            #writeTestcase(rawPayload, outputDir, dstPortStr, packetIndex)
            try:
                dataTypeInfo = getDatatypes(
                    rawPayload,
                    0,
                    0,
                    srcIp,
                    dstIp,
                    timeout,
                    "udp",
                )
            except Exception:
                # Keep ARP/RARP packets even when higher-level trait extraction fails.
                mimeType = magic.from_buffer(rawPayload, mime=True)
                dataTypeInfo = {
                    "MIME Type": mimeType,
                    "payload.mime": mimeType,
                    "Decompressed": {"Decompressed": False},
                    "payload.decompressed": {"Decompressed": False},
                    "Data Types": ["Unknown data type"],
                    "Traits": {"Length": len(rawPayload)},
                }
            timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
            decodedProtocols = [protocolName]
            packetInfo = {
                "packet.processed": int(packetIndex),
                "packet.timestamp": timestamp,
                "packet.proto": protocolName,
                "link.proto": protocolName,
                "packet.decoded_protocols": decodedProtocols,
                "Ethernet Frame": {
                    "ether.src.mac.addr": srcMacAddr,
                    "link.src.mac.addr": srcMacAddr,
                    "ether.dst.mac.addr": dstMacAddr,
                    "link.dst.mac.addr": dstMacAddr,
                    "ether.src.mac.vendor": srcMacVendor,
                    "link.src.mac.vendor": srcMacVendor,
                    "ether.dst.mac.vendor": dstMacVendor,
                    "link.dst.mac.vendor": dstMacVendor,
                }
                if (srcMacAddr != "N/A" or dstMacAddr != "N/A")
                else "N/A",
                "IP": {
                    "ip.src.addr": srcIp,
                    "network.ip.src.addr": srcIp,
                    "ip.dst.addr": dstIp,
                    "network.ip.dst.addr": dstIp,
                    "network.ip.chksum": "N/A",
                    "ip.chksum": "N/A",
                    "network.len": len(rawPayload),
                    "ip.len": len(rawPayload),
                    "network.ip.len": len(rawPayload),
                },
                protocolName: arpSection,
                "Raw data": {
                    "Payload": {
                        "payload.hex": rawPayload.hex(),
                        "payload.ascii": rawPayload.decode(errors="ignore"),
                    },
                    "Packet": bytes(p).hex(),
                    "packet.hex": bytes(p).hex(),
                    "payload.len": len(rawPayload),
                },
            }
            if wanLinkSection is not None:
                packetInfo["Link Control"] = wanLinkSection
                packetInfo["packet.decoded_protocols"] = decodedProtocols + list(
                    wanLinkSection.get("wan.detected", [])
                )

            return joinInfo(
                outputDir,
                dstPortStr,
                packetIndex,
                _jsonDumpEncoded(dataTypeInfo),
                _jsonDumpEncoded(packetInfo),
                dstIp if dstIp != "0.0.0.0" else srcIp,
            )

        # Decode IEEE 802.11 (Wi-Fi) link-layer frames that do not carry
        # IP / ARP / WAN-link layers.  When keys are present we additionally
        # try to strip WEP/CCMP/TKIP and re-run the packet loop on the
        # decrypted payload to populate IP/TCP/UDP normally.
        wirelessSection = dec_wireless_80211.decodeWirelessFrame(p)
        if wirelessSection is not None:
            wifiDecryptResult = dec_wireless_80211.decryptWifiPayload(p, activeWifiKeys)
            rawFrame = bytes(p)
            decryptedFrame = None
            if wifiDecryptResult and wifiDecryptResult.get("ok") and wifiDecryptResult.get("plaintextHex"):
                try:
                    decryptedFrame = bytes.fromhex(wifiDecryptResult["plaintextHex"])
                except Exception:
                    decryptedFrame = None
            if decryptedFrame:
                # Re-parse the decrypted bytes as an 802.2 LLC frame so
                # we can descend into IP / TCP / UDP / DHCP etc.  Most
                # CCMP-encrypted Wi-Fi data frames use an LLC/SNAP
                # header (DSAP=0xAA SSAP=0xAA Control=0x03 OUI=00:00:00
                # EtherType=0x0800 for IPv4) rather than a plain
                # 802.3 Ethernet frame, so ``scapy.Ether`` mis-parses
                # the destination MAC bytes.
                try:
                    innerPacket = scapy.LLC(decryptedFrame)
                except Exception:
                    try:
                        innerPacket = scapy.Ether(decryptedFrame)
                    except Exception:
                        innerPacket = scapy.SafeDataPlane(bytes(decryptedFrame))
                try:
                    innerInfo = packetLoop(
                        innerPacket,
                        packetIndex,
                        srcPortFilter,
                        dstPortFilter,
                        timeout,
                    )
                except Exception:
                    innerInfo = None
                if innerInfo is not None:
                    # packetLoop returns a {"packet.info": {...},
                    # "extra.info": {...}} dict via joinInfo(); unwrap it.
                    innerPacketInfo = None
                    if isinstance(innerInfo, dict):
                        innerPacketInfo = innerInfo.get("packet.info")
                    elif isinstance(innerInfo, (str, bytes, bytearray)):
                        try:
                            innerPacketInfo = json.loads(innerInfo)
                        except Exception:
                            innerPacketInfo = None
                    if isinstance(innerPacketInfo, dict):
                        # Splice the wireless metadata + decryption status
                        # in front of the inner packet info so the renderer
                        # still sees the decrypted network traffic.
                        #
                        # Note: we deliberately do NOT prepend "WIFI" to
                        # ``packet.decoded_protocols`` here.  The link-layer
                        # protocol is already recorded via ``link.proto =
                        # "IEEE 802.11"`` (set below), and prepending the
                        # generic "WIFI" placeholder used to make the
                        # List-panel "App Protocol" column display "WIFI"
                        # for every decrypted TCP/UDP/ICMP frame — masking
                        # the real application-layer protocol (HTTP, SSH,
                        # DNS, ...).  Leaving ``decoded_protocols`` to the
                        # inner packet's transport/app-layer values keeps
                        # the renderer honest about what was actually
                        # decoded inside the (now-stripped) 802.11 frame.
                        innerPacketInfo["Wireless"] = wirelessSection
                        innerPacketInfo["link.proto"] = "IEEE 802.11"
                        innerPacketInfo["link.src.mac.addr"] = srcMacAddr
                        innerPacketInfo["link.dst.mac.addr"] = dstMacAddr
                        innerPacketInfo["link.src.mac.vendor"] = srcMacVendor
                        innerPacketInfo["link.dst.mac.vendor"] = dstMacVendor
                        innerPacketInfo["wifi.decrypt.ok"] = True
                        innerPacketInfo["wifi.decrypt.algorithm"] = wifiDecryptResult.get("algorithm")
                        return json.dumps(innerPacketInfo)

            timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
            decodedProtocols = list(wirelessSection.get("packet.decoded_protocols") or ["WIFI"])
            decodedProtocols = ["WIFI"] + [d for d in decodedProtocols if d != "WIFI"]
            wifiInfo = {
                "packet.processed": int(packetIndex),
                "packet.timestamp": timestamp,
                "packet.proto": "WIFI",
                "link.proto": "IEEE 802.11",
                "packet.decoded_protocols": decodedProtocols,
                "Ethernet Frame": {
                    "ether.src.mac.addr": srcMacAddr,
                    "link.src.mac.addr": srcMacAddr,
                    "ether.dst.mac.addr": dstMacAddr,
                    "link.dst.mac.addr": dstMacAddr,
                    "ether.src.mac.vendor": srcMacVendor,
                    "link.src.mac.vendor": srcMacVendor,
                    "ether.dst.mac.vendor": dstMacVendor,
                    "link.dst.mac.vendor": dstMacVendor,
                }
                if (srcMacAddr != "N/A" or dstMacAddr != "N/A")
                else "N/A",
                "Wireless": wirelessSection,
                "wifi.decrypt.ok": bool(wifiDecryptResult and wifiDecryptResult.get("ok")),
                "wifi.decrypt.algorithm": (wifiDecryptResult or {}).get("algorithm", "None"),
                "wifi.decrypt.error": (wifiDecryptResult or {}).get("error"),
                "Raw data": {
                    "Payload": {
                        "payload.hex": rawFrame.hex(),
                        "payload.ascii": rawFrame.decode(errors="ignore"),
                    },
                    "Packet": rawFrame.hex(),
                    "packet.hex": rawFrame.hex(),
                    "payload.len": len(rawFrame),
                },
            }
            try:
                dataTypeInfo = getDatatypes(
                    rawFrame,
                    0,
                    0,
                    "0.0.0.0",
                    "0.0.0.0",
                    timeout,
                    "udp",
                )
            except Exception:
                mimeType = magic.from_buffer(rawFrame, mime=True)
                dataTypeInfo = {
                    "MIME Type": mimeType,
                    "payload.mime": mimeType,
                    "Decompressed": {"Decompressed": False},
                    "payload.decompressed": {"Decompressed": False},
                    "Data Types": ["Unknown data type"],
                    "Traits": {"Length": len(rawFrame)},
                }
            if wanLinkSection is not None:
                wifiInfo["Link Control"] = wanLinkSection
                wifiInfo["packet.decoded_protocols"] = decodedProtocols + list(
                    wanLinkSection.get("wan.detected", [])
                )
            return joinInfo(
                outputDir,
                "wifi",
                packetIndex,
                _jsonDumpEncoded(dataTypeInfo),
                _jsonDumpEncoded(wifiInfo),
                "0.0.0.0",
            )

        rawPayload = bytes(p.payload) if bytes(p.payload) else bytes(p)
        if rawPayload is None or len(rawPayload) == 0:
            return None

        protocolName = "LINK" if wanLinkSection is not None else "FRAME"
        dstPortStr = "link" if protocolName == "LINK" else "frame"
        #writeTestcase(rawPayload, outputDir, dstPortStr, packetIndex)
        mimeType = magic.from_buffer(rawPayload, mime=True)
        timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )
        decodedProtocols = (
            list(wanLinkSection.get("wan.detected", []))
            if wanLinkSection is not None
            else ["FRAME"]
        )
        packetInfo = {
            "packet.processed": int(packetIndex),
            "packet.timestamp": timestamp,
            "packet.proto": protocolName,
            "link.proto": protocolName,
            "packet.decoded_protocols": decodedProtocols,
            "Ethernet Frame": {
                "ether.src.mac.addr": srcMacAddr,
                "link.src.mac.addr": srcMacAddr,
                "ether.dst.mac.addr": dstMacAddr,
                "link.dst.mac.addr": dstMacAddr,
                "ether.src.mac.vendor": srcMacVendor,
                "link.src.mac.vendor": srcMacVendor,
                "ether.dst.mac.vendor": dstMacVendor,
                "link.dst.mac.vendor": dstMacVendor,
            }
            if (srcMacAddr != "N/A" or dstMacAddr != "N/A")
            else "N/A",
            "Raw data": {
                "Payload": {
                    "payload.hex": rawPayload.hex(),
                    "payload.ascii": rawPayload.decode(errors="ignore"),
                },
                "Packet": bytes(p).hex(),
                "packet.hex": bytes(p).hex(),
                "payload.len": len(rawPayload),
            },
        }
        if wanLinkSection is not None:
            packetInfo["Link Control"] = wanLinkSection
        dataTypeInfo = {
            "MIME Type": mimeType,
            "payload.mime": mimeType,
            "Decompressed": {"Decompressed": False},
            "payload.decompressed": {"Decompressed": False},
            "Data Types": ["Unknown data type"],
            "Traits": {"Length": len(rawPayload)},
        }
        return joinInfo(
            outputDir,
            dstPortStr,
            packetIndex,
            _jsonDumpEncoded(dataTypeInfo),
            _jsonDumpEncoded(packetInfo),
            "0.0.0.0",
        )

    isTcp = p.haslayer("TCP")
    isUdp = p.haslayer("UDP")
    isSctp = isSctpPacket(p)
    ipProtocolNumber = getPacketNetworkProtocolNumber(networkLayer)
    isIgmp = p.haslayer("IGMP") or ipProtocolNumber == 2
    isIcmp = p.haslayer("ICMP") or ipProtocolNumber == 58
    # OSPF runs directly over IP (protocol number 89).
    isOspf = p.haslayer("OSPF") or ipProtocolNumber == 89

    if isTcp:
        rawPayload = p["TCP"].payload.original
        srcPort = p["TCP"].sport
        dstPort = p["TCP"].dport
        transportProtocol = "tcp"
        initialDstPort = dstPort
        streamKey = getTcpStreamKey(networkLayer.src, srcPort, networkLayer.dst, dstPort)
        # check if we are the first packet in stream, and if so, store the initial destination port for this stream
        if p["TCP"].flags.S and not p["TCP"].flags.A:
            tcpStreamInitialDstPortMap[streamKey] = initialDstPort
        elif p["TCP"].flags.S and p["TCP"].flags.A:
            # SYN-ACK packet, check if we have already stored the initial destination port for this stream
            if streamKey not in tcpStreamInitialDstPortMap:
                tcpStreamInitialDstPortMap[streamKey] = initialDstPort
        elif streamKey in tcpStreamInitialDstPortMap:
            initialDstPort = tcpStreamInitialDstPortMap[streamKey]
        else:
            initialDstPort = tcpStreamInitialDstPortMap.get(streamKey, dstPort)
        dstPortStr = str(initialDstPort if initialDstPort is not None else dstPort)
    elif isUdp:
        rawPayload = p["UDP"].payload.original
        srcPort = p["UDP"].sport
        dstPort = p["UDP"].dport
        transportProtocol = "udp"
        dstPortStr = str(dstPort)
    elif isSctp:
        sctpLayer = p["SCTP"] if p.haslayer("SCTP") else None
        rawPayload = bytes(networkLayer.payload)
        srcPort = int(getattr(sctpLayer, "sport", int.from_bytes(rawPayload[0:2], "big")) or 0)
        dstPort = int(getattr(sctpLayer, "dport", int.from_bytes(rawPayload[2:4], "big")) or 0)
        transportProtocol = "sctp"
        dstPortStr = str(dstPort)
    elif isIgmp:
        rawPayload = bytes(networkLayer.payload)
        srcPort = 0
        dstPort = 0
        transportProtocol = "igmp"
        dstPortStr = "igmp"
    elif isOspf:
        rawPayload = bytes(networkLayer.payload)
        srcPort = 0
        dstPort = 0
        transportProtocol = "ospf"
        dstPortStr = "ospf"
    elif isIcmp:
        # ICMP: use the full ICMP layer bytes as the payload.  IPv6
        # ICMPv6 packets report haslayer("ICMP") True in some scapy
        # versions but p["ICMP"] raises — fall back to
        # networkLayer.payload for those.
        try:
            if p.haslayer("ICMP"):
                icmpLayer = p["ICMP"]
            else:
                icmpLayer = networkLayer.payload
        except Exception:
            icmpLayer = networkLayer.payload
        rawPayload = bytes(icmpLayer)
        srcPort = 0
        dstPort = 0
        transportProtocol = "icmp"
        dstPortStr = "icmp"
    else:
        # Catch-all fallback for packets we can see but do not have a decoder for yet.
        ipPayload = bytes(networkLayer.payload)
        rawPayload = ipPayload if len(ipPayload) > 0 else bytes(networkLayer)
        srcPort = 0
        dstPort = 0
        transportProtocol = "ip"
        dstPortStr = "undecodable"

    if (srcPortFilter is None or srcPort == srcPortFilter) and (
        dstPortFilter is None or dstPort == dstPortFilter
    ):
        if rawPayload is not None:
            streamLabelPort = dstPort
            if isTcp:
                streamKey = getTcpStreamKey(networkLayer.src, srcPort, networkLayer.dst, dstPort)
                streamLabelPort = tcpStreamInitialDstPortMap.get(streamKey, dstPort)
            #writeTestcase(rawPayload, outputDir, dstPortStr, packetIndex)
            if len(rawPayload) == 0:
                dataTypeInfo = buildEmptyPayloadDataTypeInfo()
            elif transportProtocol == "ip":
                mimeType = magic.from_buffer(rawPayload, mime=True)
                dataTypeInfo = {
                    "MIME Type": mimeType,
                    "payload.mime": mimeType,
                    "Decompressed": {"Decompressed": False},
                    "payload.decompressed": {"Decompressed": False},
                    "Data Types": ["Unknown data type"],
                    "Traits": {"Length": len(rawPayload)},
                }
            else:
                dataTypeInfo = getDatatypes(
                    rawPayload,
                    srcPort,
                    streamLabelPort,
                    networkLayer.src,
                    networkLayer.dst,
                    timeout,
                    transportProtocol,
                    initialDstPort,
                    activeRecon=activeRecon,
                )
            timestamp = datetime.fromtimestamp(float(Decimal(p.time))).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )

            # Resolve geoip once per packet so we don't hit the cache (or DB) twice
            # for the same IP within a single packet.
            srcGeoInfo = getGeoipInfo(networkLayer.src, "src")
            dstGeoInfo = getGeoipInfo(networkLayer.dst, "dst")
            isLocalNetwork = (
                srcGeoInfo.get("Location") == "Localnet"
                and dstGeoInfo.get("Location") == "Localnet"
            )

            if isTcp:
                # Build TCP flag string once
                tcpHeaderWords = int(getattr(p["TCP"], "dataofs", 0) or 0)
                tcpFlags = ""
                if p["TCP"].flags.S:
                    tcpFlags += "SYN|"
                if p["TCP"].flags.A:
                    tcpFlags += "ACK|"
                if p["TCP"].flags.F:
                    tcpFlags += "FIN|"
                if p["TCP"].flags.R:
                    tcpFlags += "RST|"
                if p["TCP"].flags.P:
                    tcpFlags += "PSH|"
                if p["TCP"].flags.U:
                    tcpFlags += "URG|"
                if p["TCP"].flags.ECE:
                    tcpFlags += "ECE|"
                if p["TCP"].flags.CWR:
                    tcpFlags += "CWR|"
                if tcpFlags.endswith("|"):
                    tcpFlags = tcpFlags[:-1]

                transportSection = {
                    "tcp.src.port": int(srcPort),
                    "transport.tcp.src.port": int(srcPort),
                    "tcp.dst.port": int(dstPort),
                    "transport.tcp.dst.port": int(dstPort),
                    "tcp.seq": int(p["TCP"].seq),
                    "transport.tcp.seq": int(p["TCP"].seq),
                    "tcp.ack": int(p["TCP"].ack),
                    "transport.tcp.ack": int(p["TCP"].ack),
                    "tcp.chksum": getOptionalHexInt(getattr(p["TCP"], "chksum", None)),
                    "transport.tcp.chksum": getOptionalHexInt(getattr(p["TCP"], "chksum", None)),
                    "Urgent flag": bool(p["TCP"].urgptr),
                    "tcp.urgptr": bool(p["TCP"].urgptr),
                    "transport.tcp.urgptr": bool(p["TCP"].urgptr),
                    "TCP Flag Data": {
                        "Flags": tcpFlags if tcpFlags else "None",
                        "tcp.flags": tcpFlags if tcpFlags else "None",
                        "transport.tcp.flags": tcpFlags if tcpFlags else "None",
                    },
                    "Options": list(p["TCP"].options),
                    "tcp.options": list(p["TCP"].options),
                    "transport.tcp.options": list(p["TCP"].options),
                    "TCP Payload Length": int(len(rawPayload)),
                    "tcp.payload.len": int(len(rawPayload)),
                    "transport.tcp.payload.len": int(len(rawPayload)),
                    "tcp.len": int(tcpHeaderWords * 4),
                    "transport.tcp.len": int(tcpHeaderWords * 4),
                    "Wire length": len(p["TCP"]),
                    "wire.len": len(p["TCP"]),
                    "wire.proto": "TCP",
                    "transport.proto": "TCP",
                }
                # Decode SIP on TCP ports 5060/5061
                if streamLabelPort in (5060, 5061) or srcPort in (5060, 5061):
                    sipSection = dec_sip.decodeSIP(rawPayload)
                    if sipSection is not None:
                        transportSection["SIP"] = sipSection
                # Decode SNMP on TCP port 161/162 (less common but valid)
                if streamLabelPort in (161, 162) or srcPort in (161, 162):
                    snmpSection = dec_snmp.decodeSNMP(p)
                    if snmpSection is not None:
                        transportSection["SNMP"] = snmpSection
                # Decode HTTP on any TCP port — decodeHTTP() returns None for non-HTTP payloads
                httpSection = dec_http.decodeHTTP(rawPayload)
                if httpSection is not None:
                    transportSection["HTTP"] = httpSection
                    contentType = httpSection.get("Content-Type", "")
                    if "application/grpc" in str(contentType).lower():
                        grpcSection = dec_grpc.decodeGRPC(rawPayload, contentType)
                        if grpcSection is not None:
                            transportSection["gRPC"] = grpcSection
                # Decode HTTP/2 only for streams that have presented the client
                # connection preface. This avoids classifying unrelated encrypted
                # payloads (including SSH) as HTTP/2 based on random bytes.
                shouldDecodeHttp2 = False
                if rawPayload.startswith(HTTP2_PREFACE_BYTES):
                    shouldDecodeHttp2 = True
                    with http2DetectedStreamsLock:
                        http2DetectedStreams.add(streamKey)
                else:
                    with http2DetectedStreamsLock:
                        shouldDecodeHttp2 = streamKey in http2DetectedStreams

                if shouldDecodeHttp2:
                    http2Section = dec_http2.decodeHTTP2(rawPayload)
                    if http2Section is not None:
                        transportSection["HTTP2"] = http2Section
                # Decode gRPC envelopes carried inside HTTP/2 DATA frames on
                # the conventional TCP/50051 service port.
                if streamLabelPort == 50051 or srcPort == 50051 or dstPort == 50051:
                    grpcSection = dec_grpc.decodeGRPCFromHTTP2(rawPayload)
                    if grpcSection is None:
                        grpcSection = dec_grpc.decodeGRPC(rawPayload)
                    if grpcSection is not None:
                        transportSection["gRPC"] = grpcSection
                # Decode FTP on TCP ports 20/21
                if streamLabelPort in (20, 21) or srcPort in (20, 21):
                    ftpSection = dec_ftp.decodeFTP(rawPayload)
                    if ftpSection is not None:
                        transportSection["FTP"] = ftpSection
                # Decode SMTP on TCP ports 25/587/465
                if streamLabelPort in (25, 587, 465) or srcPort in (25, 587, 465):
                    smtpSection = dec_smtp.decodeSMTP(rawPayload)
                    if smtpSection is not None:
                        transportSection["SMTP"] = smtpSection
                # Decode POP3/POP on TCP ports 110/995
                if streamLabelPort in (110, 995) or srcPort in (110, 995):
                    pop3Section = dec_pop3.decodePOP3(rawPayload)
                    if pop3Section is not None:
                        transportSection["POP3"] = pop3Section
                # Decode IMAP/IMAP4 on TCP ports 143/993
                if streamLabelPort in (143, 993) or srcPort in (143, 993):
                    imapSection = dec_imap.decodeIMAP(rawPayload)
                    if imapSection is not None:
                        transportSection["IMAP"] = imapSection
                # Decode Telnet on TCP port 23
                if streamLabelPort == 23 or srcPort == 23:
                    telnetSection = dec_telnet.decodeTelnet(rawPayload)
                    if telnetSection is not None:
                        transportSection["Telnet"] = telnetSection
                    # Also scan non-IAC data packets for cleartext credentials
                    telnetCreds = dec_telnet.extractTelnetCredentials(rawPayload)
                    if telnetCreds:
                        if "Telnet" not in transportSection:
                            transportSection["Telnet"] = {}
                        transportSection["Telnet"].setdefault("Credentials", {}).update(
                            telnetCreds
                        )
                # Decode IRC on TCP ports 6667/6668/6669
                if streamLabelPort in (6667, 6668, 6669) or srcPort in (6667, 6668, 6669):
                    ircSection = dec_irc.decodeIRC(rawPayload)
                    if ircSection is not None:
                        transportSection["IRC"] = ircSection
                # Decode MTP/MMS on TCP port 1755
                if streamLabelPort == 1755 or srcPort == 1755:
                    mtpSection = dec_mtp.decodeMTP(rawPayload)
                    if mtpSection is not None:
                        transportSection["MTP"] = mtpSection
                # Decode LDAP on TCP ports 389/636
                if streamLabelPort in (389, 636) or srcPort in (389, 636):
                    ldapSection = dec_ldap.decodeLDAP(rawPayload)
                    if ldapSection is not None:
                        transportSection["LDAP"] = ldapSection
                # Decode MySQL on TCP port 3306
                if streamLabelPort == 3306 or srcPort == 3306:
                    mysqlSection = dec_mysql.decodeMySQL(rawPayload)
                    if mysqlSection is not None:
                        transportSection["MySQL"] = mysqlSection
                # Decode PostgreSQL on TCP port 5432
                if streamLabelPort == 5432 or srcPort == 5432:
                    pgSection = dec_postgresql.decodePostgreSQL(rawPayload)
                    if pgSection is not None:
                        transportSection["PostgreSQL"] = pgSection
                # Decode XMPP on TCP ports 5222/5223
                if streamLabelPort in (5222, 5223) or srcPort in (5222, 5223):
                    xmppSection = dec_xmpp.decodeXMPP(rawPayload)
                    if xmppSection is not None:
                        transportSection["XMPP"] = xmppSection
                # Decode SMB on TCP ports 139/445
                if streamLabelPort in (139, 445) or srcPort in (139, 445):
                    smbSection = dec_smb.decodeSMB(rawPayload)
                    if smbSection is not None:
                        transportSection["SMB"] = smbSection
                # Decode SMPP on TCP ports 2775/3550
                if streamLabelPort in (2775, 3550) or srcPort in (2775, 3550):
                    smppSection = dec_smpp.decodeSMPP(rawPayload)
                    if smppSection is not None:
                        transportSection["SMPP"] = smppSection
                # Decode ISO 8583 financial messages on common ports
                if streamLabelPort in (8583, 5000, 5001, 14401) or srcPort in (
                    8583,
                    5000,
                    5001,
                    14401,
                ):
                    iso8583Section = dec_iso8583.decodeISO8583(rawPayload)
                    if iso8583Section is not None:
                        transportSection["ISO8583"] = iso8583Section
                # Decode Soulseek message envelopes on common TCP ports
                if streamLabelPort in (2234, 2240, 2242) or srcPort in (2234, 2240, 2242):
                    soulseekSection = dec_soulseek.decodeSoulseek(rawPayload)
                    if soulseekSection is not None:
                        transportSection["Soulseek"] = soulseekSection
                # Decode BitTorrent peer-wire/handshake patterns (with common-port assist)
                btCommonPorts = {6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969}
                if (
                    streamLabelPort in btCommonPorts
                    or srcPort in btCommonPorts
                    or rawPayload.startswith(b"\x13BitTorrent protocol")
                ):
                    bittorrentSection = dec_bittorrent.decodeBitTorrent(rawPayload)
                    if bittorrentSection is not None:
                        transportSection["BitTorrent"] = bittorrentSection
                # Decode MQTT on TCP ports 1883/8883
                if streamLabelPort in (1883, 8883) or srcPort in (1883, 8883):
                    mqttSection = dec_mqtt.decodeMQTT(rawPayload)
                    if mqttSection is not None:
                        transportSection["MQTT"] = mqttSection
                # Decode RTSP on TCP port 554
                if streamLabelPort == 554 or srcPort == 554:
                    rtspSection = dec_rtsp.decodeRTSP(rawPayload)
                    if rtspSection is not None:
                        transportSection["RTSP"] = rtspSection
                # Decode BGP on TCP port 179
                if streamLabelPort == 179 or srcPort == 179:
                    bgpSection = dec_bgp.decodeBGP(rawPayload)
                    if bgpSection is not None:
                        transportSection["BGP"] = bgpSection
                # Decode NNTP on TCP port 119
                if streamLabelPort == 119 or srcPort == 119:
                    nntpSection = dec_nntp.decodeNNTP(rawPayload)
                    if nntpSection is not None:
                        transportSection["NNTP"] = nntpSection
                # Decode RADIUS on TCP ports 1812/1813/1645/1646 (RFC 6614 defines RADIUS over TCP)
                if dstPort in (1812, 1813, 1645, 1646) or srcPort in (
                    1812,
                    1813,
                    1645,
                    1646,
                ):
                    radiusSection = dec_radius.decodeRADIUS(rawPayload)
                    if radiusSection is not None:
                        transportSection["RADIUS"] = radiusSection
                # Decode WebSocket on TCP ports 80/443/8080/8443/8765 (stream-following aware)
                if streamLabelPort in (80, 443, 8080, 8443, 8765) or srcPort in (80, 443, 8080, 8443, 8765):
                    wsSection = dec_websocket.decodeWebSocket(rawPayload)
                    if wsSection is not None:
                        transportSection["WebSocket"] = wsSection
                # Decode NFS/RPC on TCP ports 2049/111
                if streamLabelPort in (2049, 111) or srcPort in (2049, 111):
                    nfsSection = dec_nfs.decodeNFS(rawPayload)
                    if nfsSection is not None:
                        transportSection["NFS"] = nfsSection
                # Decode Kerberos on TCP port 88
                if streamLabelPort == 88 or srcPort == 88:
                    kerberosSection = dec_kerberos.decodeKerberos(rawPayload)
                    if kerberosSection is not None:
                        transportSection["Kerberos"] = kerberosSection
                # Decode SSH metadata on TCP ports 22/2222, or when payload starts with SSH banner
                if (
                    streamLabelPort in (22, 2222)
                    or srcPort in (22, 2222) or dstPort in (22, 2222)
                    or rawPayload.startswith(b"SSH-")
                ):
                    sshSection = dec_ssh.decodeSSH(rawPayload, srcPort, dstPort)
                    if sshSection is not None:
                        transportSection["SSH"] = sshSection
                # Decode Modbus/TCP on TCP port 502
                if streamLabelPort == 502 or srcPort == 502 or dstPort == 502:
                    modbusSection = dec_modbus.decodeModbus(rawPayload)
                    if modbusSection is not None:
                        transportSection["Modbus"] = modbusSection
                # Decode DNP3 on TCP port 20000, or when payload starts with 0x0564 sync
                if (
                    streamLabelPort == 20000
                    or srcPort == 20000
                    or dstPort == 20000
                    or (len(rawPayload) >= 2 and rawPayload[0] == 0x05 and rawPayload[1] == 0x64)
                ):
                    dnp3Section = dec_dnp3.decodeDNP3(rawPayload)
                    if dnp3Section is not None:
                        transportSection["DNP3"] = dnp3Section
                # Decode S7comm on TCP port 102, or when payload starts with TPKT 0x03 0x00
                if (
                    streamLabelPort == 102
                    or srcPort == 102
                    or dstPort == 102
                    or (len(rawPayload) >= 2 and rawPayload[0] == 0x03 and rawPayload[1] == 0x00)
                ):
                    s7commSection = dec_s7comm.decodeS7comm(rawPayload)
                    if s7commSection is not None:
                        transportSection["S7comm"] = s7commSection
                # Decode EPMAP (Microsoft RPC Endpoint Mapper) on TCP/135.
                if streamLabelPort == 135 or srcPort == 135 or dstPort == 135:
                    epmapSection = dec_epmap.decodeEPMAP(rawPayload)
                    if epmapSection is not None:
                        transportSection["EPMAP"] = epmapSection
                protocolKey = "TCP"
            elif isUdp:
                # Build UDP section; decode DNS if present
                dnsSection = None
                if p.haslayer("DNS"):
                    dnsLayer = p["DNS"]
                    queryNames = []
                    answerNames = []
                    answerIps = []
                    try:
                        qd = dnsLayer.qd
                        while qd is not None and hasattr(qd, "qname"):
                            queryNames.append(
                                qd.qname.decode(errors="ignore").rstrip(".")
                            )
                            qd = qd.payload if hasattr(qd, "payload") else None
                    except Exception:
                        pass
                    try:
                        an = dnsLayer.an
                        while an is not None and hasattr(an, "rrname"):
                            answerNames.append(
                                an.rrname.decode(errors="ignore").rstrip(".")
                            )
                            if hasattr(an, "rdata"):
                                answerIps.append(str(an.rdata))
                            an = an.payload if hasattr(an, "payload") else None
                    except Exception:
                        pass
                    firstQname = queryNames[0] if queryNames else ""
                    firstAip = answerIps[0] if answerIps else ""
                    dnsSection = {
                        "Transaction ID": int(dnsLayer.id),
                        "dns.id": int(dnsLayer.id),
                        "Is Response": bool(dnsLayer.qr),
                        "dns.qr": bool(dnsLayer.qr),
                        "Query Names": queryNames,
                        "dns.qnames": queryNames,
                        "First Query Name": firstQname,
                        "dns.qname": firstQname,
                        "Answer Names": answerNames,
                        "dns.anames": answerNames,
                        "Answer IPs": answerIps,
                        "dns.aips": answerIps,
                        "First Answer IP": firstAip,
                        "dns.aip": firstAip,
                        "Question Count": int(dnsLayer.qdcount),
                        "dns.qdcount": int(dnsLayer.qdcount),
                        "Answer Count": int(dnsLayer.ancount),
                        "dns.ancount": int(dnsLayer.ancount),
                    }

                transportSection = {
                    "udp.src.port": int(srcPort),
                    "udp.dst.port": int(dstPort),
                    "udp.chksum": getOptionalHexInt(getattr(p["UDP"], "chksum", None)),
                    "UDP length": int(p["UDP"].len),
                    "udp.len": int(p["UDP"].len),
                    "Wire length": len(p["UDP"]),
                    "wire.len": len(p["UDP"]),
                    "wire.proto": "UDP",
                    "transport.proto": "UDP",
                    "transport.udp.src.port": int(srcPort),
                    "transport.udp.dst.port": int(dstPort),
                    "transport.udp.chksum": getOptionalHexInt(getattr(p["UDP"], "chksum", None)),
                    "transport.udp.len": int(p["UDP"].len),
                    "transport.len": len(p["UDP"]),
                }
                if dnsSection is not None:
                    transportSection["DNS"] = dnsSection
                # Decode mDNS on UDP/5353.
                if dstPort == 5353 or srcPort == 5353:
                    mdnsSection = dec_mdns.decodeMDNS(rawPayload)
                    if mdnsSection is not None:
                        transportSection["mDNS"] = mdnsSection
                # Decode LLMNR on UDP/5355.
                if dstPort == 5355 or srcPort == 5355:
                    llmnrSection = dec_llmnr.decodeLLMNR(rawPayload)
                    if llmnrSection is not None:
                        transportSection["LLMNR"] = llmnrSection
                # Decode SSDP / UPnP discovery on UDP/1900.
                if dstPort == 1900 or srcPort == 1900:
                    ssdpSection = dec_ssdp.decodeSSDP(rawPayload)
                    if ssdpSection is not None:
                        transportSection["SSDP"] = ssdpSection
                        if ssdpSection.get("UPnP"):
                            transportSection["UPnP"] = ssdpSection
                # Decode SNMP on UDP ports 161/162
                if dstPort in (161, 162) or srcPort in (161, 162):
                    snmpSection = dec_snmp.decodeSNMP(p)
                    if snmpSection is not None:
                        transportSection["SNMP"] = snmpSection
                # Decode DHCP on UDP ports 67/68
                if dstPort in (67, 68) or srcPort in (67, 68):
                    dhcpSection = dec_dhcp.decodeDHCP(p)
                    if dhcpSection is not None:
                        transportSection["DHCP"] = dhcpSection
                # Decode DHCPv6 on UDP ports 546/547.
                if dstPort in (546, 547) or srcPort in (546, 547):
                    dhcpv6Section = dec_dhcpv6.decodeDHCPv6(rawPayload)
                    if dhcpv6Section is not None:
                        transportSection["DHCPv6"] = dhcpv6Section
                # EPMAP can also be carried over connectionless RPC on UDP/135.
                if dstPort == 135 or srcPort == 135:
                    epmapSection = dec_epmap.decodeEPMAP(rawPayload)
                    if epmapSection is not None:
                        transportSection["EPMAP"] = epmapSection
                # Decode NTP on UDP port 123
                if dstPort == 123 or srcPort == 123:
                    ntpSection = dec_ntp.decodeNTP(p)
                    if ntpSection is not None:
                        transportSection["NTP"] = ntpSection
                # Decode SIP on UDP ports 5060/5061
                if dstPort in (5060, 5061) or srcPort in (5060, 5061):
                    sipSection = dec_sip.decodeSIP(rawPayload)
                    if sipSection is not None:
                        transportSection["SIP"] = sipSection
                # Decode TFTP on UDP port 69
                if dstPort == 69 or srcPort == 69:
                    tftpSection = dec_tftp.decodeTFTP(rawPayload)
                    if tftpSection is not None:
                        transportSection["TFTP"] = tftpSection
                # Decode MQTT on UDP ports 1883/8883
                if dstPort in (1883, 8883) or srcPort in (1883, 8883):
                    mqttSection = dec_mqtt.decodeMQTT(rawPayload)
                    if mqttSection is not None:
                        transportSection["MQTT"] = mqttSection
                # Decode LDAP on UDP ports 389/636
                if dstPort in (389, 636) or srcPort in (389, 636):
                    ldapSection = dec_ldap.decodeLDAP(rawPayload)
                    if ldapSection is not None:
                        transportSection["LDAP"] = ldapSection
                # Decode RADIUS on UDP ports 1812/1813/1645/1646
                if dstPort in (1812, 1813, 1645, 1646) or srcPort in (
                    1812,
                    1813,
                    1645,
                    1646,
                ):
                    radiusSection = dec_radius.decodeRADIUS(rawPayload)
                    if radiusSection is not None:
                        transportSection["RADIUS"] = radiusSection
                # Decode NFS/RPC on UDP ports 2049/111
                if dstPort in (2049, 111) or srcPort in (2049, 111):
                    nfsSection = dec_nfs.decodeNFS(rawPayload)
                    if nfsSection is not None:
                        transportSection["NFS"] = nfsSection
                # Decode Kerberos on UDP port 88
                if dstPort == 88 or srcPort == 88:
                    kerberosSection = dec_kerberos.decodeKerberos(rawPayload)
                    if kerberosSection is not None:
                        transportSection["Kerberos"] = kerberosSection
                # Decode BitTorrent DHT/KRPC patterns on common UDP ports/signatures
                btCommonUdpPorts = {6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969}
                if (
                    dstPort in btCommonUdpPorts
                    or srcPort in btCommonUdpPorts
                    or (len(rawPayload) >= 3 and rawPayload[:1] == b"d")
                ):
                    bittorrentSection = dec_bittorrent.decodeBitTorrent(rawPayload)
                    if bittorrentSection is not None:
                        transportSection["BitTorrent"] = bittorrentSection
                # Decode HSRP on UDP port 1985 (HSRPv1 multicast 224.0.0.2 / HSRPv2 224.0.0.102)
                if dstPort == 1985 or srcPort == 1985:
                    hsrpSection = dec_hsrp.decodeHSRP(p, rawPayload)
                    if hsrpSection is not None:
                        transportSection["HSRP"] = hsrpSection
                # Decode MNDP (MikroTik Neighbor Discovery Protocol) on UDP port 5678
                if dstPort == 5678 or srcPort == 5678:
                    mndpSection = dec_mndp.decodeMNDP(p, rawPayload)
                    if mndpSection is not None:
                        transportSection["MNDP"] = mndpSection
                protocolKey = "UDP"
            elif isSctp:
                sctpSection = dec_sctp.decodeSctpPacket(p)
                if sctpSection is None:
                    sctpSection = {
                        "sctp.src.port": int(srcPort),
                        "transport.sctp.src.port": int(srcPort),
                        "sctp.dst.port": int(dstPort),
                        "transport.sctp.dst.port": int(dstPort),
                        "Wire length": len(rawPayload),
                        "wire.len": len(rawPayload),
                        "transport.len": len(rawPayload),
                        "transport.proto": "SCTP",
                    }
                transportSection = sctpSection
                protocolKey = "SCTP"
            elif isIcmp:
                # ICMP transport section. Match the guarded access used
                # earlier (see ~line 3254): ICMPv6 packets can report
                # haslayer("ICMP") True yet raise on p["ICMP"], so fall
                # back to networkLayer.payload in that case.
                try:
                    if p.haslayer("ICMP"):
                        icmpLayer = p["ICMP"]
                    else:
                        icmpLayer = networkLayer.payload
                except Exception:
                    icmpLayer = networkLayer.payload
                icmpWireLen = len(bytes(icmpLayer))
                icmpTypeMap = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    4: "Source Quench",
                    5: "Redirect",
                    8: "Echo Request",
                    9: "Router Advertisement",
                    10: "Router Solicitation",
                    11: "Time Exceeded",
                    12: "Parameter Problem",
                    13: "Timestamp",
                    14: "Timestamp Reply",
                    15: "Information Request",
                    16: "Information Reply",
                }
                icmpType = int(icmpLayer.type) if hasattr(icmpLayer, "type") else 0
                icmpCode = int(icmpLayer.code) if hasattr(icmpLayer, "code") else 0
                icmpTypeStr = icmpTypeMap.get(icmpType, f"Type {icmpType}")
                icmpId = "N/A"
                icmpSeq = "N/A"
                try:
                    icmpId = int(icmpLayer.id)
                except Exception:
                    pass
                try:
                    icmpSeq = int(icmpLayer.seq)
                except Exception:
                    pass
                icmpChksum = "N/A"
                try:
                    icmpChksum = hex(int(icmpLayer.chksum))
                except Exception:
                    pass
                transportSection = {
                    "Type": icmpTypeStr,
                    "icmp.type": icmpTypeStr,
                    "Code": icmpCode,
                    "icmp.code": icmpCode,
                    "ID": icmpId,
                    "icmp.id": icmpId,
                    "Sequence": icmpSeq,
                    "icmp.seq": icmpSeq,
                    "ICMP Checksum": icmpChksum,
                    "icmp.chksum": icmpChksum,
                    "transport.icmp.type": icmpTypeStr,
                    "transport.icmp.code": icmpCode,
                    "transport.icmp.id": icmpId,
                    "transport.icmp.seq": icmpSeq,
                    "transport.icmp.chksum": icmpChksum,
                    "Wire length": icmpWireLen,
                    "wire.len": icmpWireLen,
                    "transport.len": icmpWireLen,
                    "transport.proto": "ICMP",
                }
                protocolKey = "ICMP"
            elif isIgmp:
                transportSection = dec_igmp.decodeIGMP(p, rawPayload)
                protocolKey = "IGMP"
            elif isOspf:
                ospfSection = dec_ospf.decodeOSPF(p, rawPayload)
                if ospfSection is not None:
                    transportSection = ospfSection
                else:
                    ipProtoNum = getPacketNetworkProtocolNumber(networkLayer)
                    transportSection = {
                        "transport.src.port": 0,
                        "transport.dst.port": 0,
                        "IP Protocol Number": ipProtoNum,
                        "ip.proto.num": ipProtoNum,
                        "network.ip.proto.num": ipProtoNum,
                        "Wire length": len(rawPayload),
                        "wire.len": len(rawPayload),
                        "network.len": len(networkLayer),
                        "network.proto": "OSPF",
                        "transport.proto": "OSPF",
                    }
                protocolKey = "OSPF"
            else:
                ipProtoNum = getPacketNetworkProtocolNumber(networkLayer)
                transportSection = {
                    "transport.src.port": int(srcPort),
                    "transport.dst.port": int(dstPort),
                    "IP Protocol Number": ipProtoNum,
                    "ip.proto.num": ipProtoNum,
                    "network.ip.proto.num": ipProtoNum,
                    "Wire length": len(networkLayer),
                    "wire.len": len(networkLayer),
                    "network.len": len(networkLayer),
                    "network.proto": getPacketNetworkProtocolLabel(networkLayer),
                    "transport.proto": "Unknown protocol",
                }
                protocolKey = "Undecodable"
            packetInfo = {
                "packet.processed": int(packetIndex),
                "packet.timestamp": timestamp,
                "packet.proto": protocolKey,
                "link.proto": linkProto,
                "Ethernet Frame": {
                    "ether.src.mac.addr": srcMacAddr,
                    "link.src.mac.addr": srcMacAddr,
                    "ether.dst.mac.addr": dstMacAddr,
                    "link.dst.mac.addr": dstMacAddr,
                    "ether.src.mac.vendor": srcMacVendor,
                    "link.src.mac.vendor": srcMacVendor,
                    "ether.dst.mac.vendor": dstMacVendor,
                    "link.dst.mac.vendor": dstMacVendor,
                }
                if (
                    srcGeoInfo.get("Location") == "Localnet"
                    or dstGeoInfo.get("Location") == "Localnet"
                )
                else "N/A",
                "IP": {
                    "ip.src.addr": str(networkLayer.src),
                    "network.ip.src.addr": str(networkLayer.src),
                    "ip.dst.addr": str(networkLayer.dst),
                    "network.ip.dst.addr": str(networkLayer.dst),
                    "ip.chksum": getPacketNetworkChecksumHex(networkLayer),
                    "network.ip.chksum": getPacketNetworkChecksumHex(networkLayer),
                    "ip.len": getPacketNetworkLength(networkLayer),
                    "network.ip.len": getPacketNetworkLength(networkLayer),
                    "network.proto": getPacketNetworkProtocolLabel(networkLayer),
                },

                protocolKey: transportSection,

                "Raw data": {
                    "Payload": {
                        "payload.hex": rawPayload.hex(),
                        "payload.ascii": rawPayload.decode(errors="ignore"),
                    },
                        "Packet": bytes(p).hex(),
                        "packet.hex": bytes(p).hex(),
                        "payload.len": len(rawPayload),
                    },
                }

            if linuxCookedSection is not None:
                packetInfo["Linux Cooked"] = linuxCookedSection
            if checkTor:
                if networkLayer.dst in torNetworkIps:
                    torInfo = torNetworkIps[networkLayer.dst]
                    packetInfo["Tor Info"] = {
                        "tor.nickname": torInfo["nickname"],
                        "tor.platform": torInfo["platform"],
                        "tor.exit.node": True,
                    }
                else:
                    packetInfo["Tor Info"] = {
                        "tor.nickname": None,
                        "tor.platform": None,
                        "tor.exit.node": False,
                    }
            if protocolKey == "IGMP":
                packetInfo["packet.decoded_protocols"] = ["IGMP"]
            if wanLinkSection is not None:
                packetInfo["Link Control"] = wanLinkSection
                existingDecoded = packetInfo.get("packet.decoded_protocols", [])
                if not isinstance(existingDecoded, list):
                    existingDecoded = []
                linkDecoded = list(wanLinkSection.get("wan.detected", []))
                packetInfo["packet.decoded_protocols"] = list(
                    dict.fromkeys(existingDecoded + linkDecoded)
                )
            # Use the non-local IP as the host key; fall back to src for LAN captures
            hostKey = (
                networkLayer.dst if dstGeoInfo.get("Location") != "Localnet" else networkLayer.src
            )

            mergedInfo = joinInfo(
                outputDir,
                dstPortStr,
                packetIndex,
                _jsonDumpEncoded(dataTypeInfo),
                _jsonDumpEncoded(packetInfo),
                hostKey,
            )
            return mergedInfo


def processPacketAtIndex(packetIndex, srcPortFilter, dstPortFilter, timeout):
    """
    Thin wrapper used by ThreadPoolExecutor.map so we can pass a single (index, packet)
    task without pickling scapy packet objects.  The global `packets` list is already
    loaded in memory, so this is just a cheap indexed lookup + the real per-packet work.
    """
    if stopEvent.is_set():
        return None
    p = packets[packetIndex]
    try:
        return packetLoop(p, packetIndex, srcPortFilter, dstPortFilter, timeout)
    except Exception as exc:
        errorMessage = f"fallback after decoder error: {exc}"
        if verbose >= 0:
            print(
                f"[Worker] Packet index {packetIndex} fallback after error: {exc}",
                file=sys.stderr,
            )
        return buildFallbackPacketEntry(p, packetIndex, errorMessage)


def startThreading():
    """
    Process packets from the pre-loaded `packets` list using a
    ThreadPoolExecutor with chunked processing for reduced overhead.

    Rather than re-reading the pcap file in every thread (which was the old behaviour),
    this submits chunked tasks to reduce thread scheduling overhead. ThreadPoolExecutor
    handles work-stealing, so threads stay busy even if individual packets take different
    amounts of time (e.g. when active-recon network calls vary in latency).
    """
    currentJobId = str(getattr(args, "job_id", "") or "").strip()

    # Always process when called; this function can be invoked from embedded/frozen contexts.argparse
    # Process all packets; packetLoop decides which protocols are handled.
    packetIndices = list(range(len(packets)))

    # Use consistent worker-sized batches so threads can continuously pull work.
    # Smaller batches improve responsiveness at the cost of more scheduler overhead.
    chunkSize = max(1, int(hostChunkSize) // 2)
    packetChunks = [
        packetIndices[i : i + chunkSize]
        for i in range(0, len(packetIndices), chunkSize)
    ]

    def processChunk(chunk):
        """Process a chunk of packet indices."""
        processedCount = 0
        chunkStart = time.perf_counter()
        for idx in chunk:
            if stopEvent.is_set():
                break
            try:
                result = processPacketAtIndex(
                    idx, args.source_port, args.dest_port, args.timeout
                )
                if result:
                    processedCount += 1
            except Exception as exc:
                if verbose >= 0:
                    print(
                        f"[Worker] Packet index {idx} failed: {exc}",
                        file=sys.stderr,
                    )
                continue
        return {
            "processed": processedCount,
            "elapsed_s": time.perf_counter() - chunkStart,
        }

    # Emit the first in-memory snapshot as soon as at least one packet is ready,
    # then fall back to the normal chunk cadence for later updates.
    nextSnapshotPacketCount = 1 if emitJsonSnapshots else hostChunkSize

    perfStartTime = time.perf_counter()
    perfWaitSeconds = 0.0
    perfWorkerSeconds = 0.0
    perfSnapshotSeconds = 0.0
    perfCompletedChunks = 0
    perfProcessedPackets = 0
    perfSnapshotCount = 0

    with ThreadPoolExecutor(max_workers=numWorkerThreads) as executor:
        # Keep only a small bounded number of in-flight batches so worker threads
        # pull the next batch when ready without paying the overhead of submitting
        # thousands of futures up front on very large captures.
        maxInFlight = max(numWorkerThreads * 2, 1)
        chunkIter = iter(packetChunks)
        taskFutures = {}

        def submitNextChunk():
            if stopEvent.is_set():
                return False
            nextChunk = next(chunkIter, None)
            if nextChunk is None:
                return False
            future = executor.submit(processChunk, nextChunk)
            taskFutures[future] = nextChunk
            return True

        for _ in range(maxInFlight):
            if not submitNextChunk():
                break

        while taskFutures:
            if stopEvent.is_set():
                break

            waitStart = time.perf_counter()
            doneFutures, _ = wait(
                set(taskFutures.keys()),
                return_when=FIRST_COMPLETED,
            )
            perfWaitSeconds += time.perf_counter() - waitStart

            for future in doneFutures:
                chunkRef = taskFutures.pop(future, None)
                try:
                    chunkMetrics = future.result() or {}
                    perfWorkerSeconds += float(chunkMetrics.get("elapsed_s") or 0.0)
                    perfProcessedPackets += int(chunkMetrics.get("processed") or 0)
                    perfCompletedChunks += 1

                    with allPacketInfoLock:
                        processedPacketCount = len(allPacketInfo)

                    # Mirror live progress into the shared job-info dict so
                    # the /status endpoint can report it even while the
                    # bridge's early-yield gate stops emitting snapshots.
                    with processingJobLock:
                        activeJob = processingJobs.get(currentJobId)
                        if activeJob is not None:
                            activeJob["processedPackets"] = processedPacketCount
                            activeJob["totalPackets"] = totalPackets

                    if processedPacketCount >= nextSnapshotPacketCount:
                        with allPacketInfoLock:
                            # Snapshot only when we are actually emitting progress,
                            # avoiding O(n) list copies on every completed batch.
                            allPacketInfoSnapshot = list(allPacketInfo)
                            processedPacketCount = len(allPacketInfoSnapshot)

                        # we need to get a variable containing the cutoff threshold
                        # from the frontend, so we don't keep emitting packets after
                        # the frontend starts deferring everything left.
                        # Use earlyYieldPacketThreshold to stop emitting snapshots
                        # once the frontend would defer them anyway.
                        while processedPacketCount >= nextSnapshotPacketCount and processedPacketCount < earlyYieldPacketThreshold:
                            snapshotStart = time.perf_counter()
                            if emitJsonSnapshots:
                                captureData = buildHostsPayload(allPacketInfoSnapshot, "")
                                emitBridgeProgress(
                                    f"in-memory://hosts-{nextSnapshotPacketCount}.json",
                                    nextSnapshotPacketCount,
                                    totalPackets,
                                    False,
                                    captureData,
                                    str(getattr(args, "job_id", "") or "").strip(),
                                )
                            else:
                                chunkSnapshotName = f"hosts-{nextSnapshotPacketCount}.json"
                                snapshotPath = writeHostsSnapshot(
                                    outputDir,
                                    allPacketInfoSnapshot,
                                    "",
                                    chunkSnapshotName,
                                )
                                emitBridgeProgress(
                                    snapshotPath,
                                    nextSnapshotPacketCount,
                                    totalPackets,
                                    False,
                                    jobId=str(getattr(args, "job_id", "") or "").strip(),
                                )
                            perfSnapshotSeconds += time.perf_counter() - snapshotStart
                            perfSnapshotCount += 1
                            nextSnapshotPacketCount += hostChunkSize

                        # Once the early-yield threshold has been reached the
                        # while-loop above stops emitting full snapshots, which
                        # starves the frontend's processing-warning banner — the
                        # processed-packet count would freeze at the threshold
                        # until the final ``complete`` payload.  Emit a cheap
                        # progress-only update (no capture data) on every
                        # completed batch so the renderer can keep the count and
                        # ETA ticking without paying for an O(n) snapshot copy.
                        if processedPacketCount >= earlyYieldPacketThreshold:
                            currentJobId = str(getattr(args, "job_id", "") or "").strip()
                            emitBridgeProgressOnly(
                                processedPacketCount,
                                totalPackets,
                                jobId=currentJobId,
                            )
                except Exception as exc:
                    if verbose >= 0:
                        print(
                            f"[Worker {future}] Packet {chunkRef} raised an exception: {exc}",
                            file=sys.stderr,
                        )
                finally:
                    submitNextChunk()

    if verbose >= 1:
        totalElapsed = time.perf_counter() - perfStartTime
        packetsPerSecond = (
            (float(perfProcessedPackets) / perfWorkerSeconds)
            if perfWorkerSeconds > 0.0
            else 0.0
        )
        print(
            "[Perf][Pref] threading elapsed_s="
            + f"{totalElapsed:.3f}"
            + " wait_s="
            + f"{perfWaitSeconds:.3f}"
            + " worker_s="
            + f"{perfWorkerSeconds:.3f}"
            + " snapshot_s="
            + f"{perfSnapshotSeconds:.3f}"
            + " completed_chunks="
            + str(perfCompletedChunks)
            + " processed_packets="
            + str(perfProcessedPackets)
            + " pps="
            + f"{packetsPerSecond:.1f}"
            + " snapshots_emitted="
            + str(perfSnapshotCount),
            file=sys.stderr,
        )


def buildParser():
    parser = argparse.ArgumentParser(
        prog="snitch.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            f"""                                
PacketSnitch.
This software analyzes pcap network captures. It extracts TCP and UDP packet data,
writes testcases, and gathers extra information such as MIME types, entropy, geoip,
network class, banners, and more. DNS packets (UDP port 53) are decoded and included
in the output. Optionally, it performs active reconnaissance to enrich the output
with additional network and server information.
        Outputs:
          - Testcase files: outputDirPath/<dest_port>/pcap.data_packet.<index>.dat
          - Testcase info: outputDirPath/<dest_port>/pcap.info_packet.<index>.json
          - all_testcases_info.json: a consolidated file with info for the entire
            capture.
                                 """,
        ),
        epilog="Example usage: \n   python3 snitch.py traffic.pcap -o outputDirPath -s 80 -d 8080 -T 5 -a",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print backend version and exit.",
    )
    parser.add_argument("pcap_file", nargs="?", help="The .pcap file to parse.")
    parser.add_argument(
        "--use-tor-check",
        dest="use_tor_check",
        action="store_true",
        default=True,
        help="Check if packet destination IP is part of the Tor exit network.",
    )
    parser.add_argument(
        "--no-tor-check",
        dest="use_tor_check",
        action="store_false",
        help="Disable Tor exit-node lookup and continue without Tor enrichment.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="The output directory for the testcases.",
        default="testcases",
    )
    parser.add_argument(
        "-s",
        "--source-port",
        help="Only generate from this source port.",
        type=int,
    )
    parser.add_argument(
        "-d",
        "--dest-port",
        help="Only generate for this destination port.",
        type=int,
    )
    parser.add_argument(
        "-T",
        "--timeout",
        help="Timeout for network requests in seconds (default: 3).",
        type=int,
        default=3,
    )
    parser.add_argument(
        "-a",
        "--active-recon",
        help="Perform active reconnaissance to gather extra info (geoip, banners, titles).",
        action="store_true",
    )
    parser.add_argument(
        "-c",
        "--conf",
        help="Path to configuration YAML file (default: conf.yaml).",
    )
    parser.add_argument(
        "--host-chunk-size",
        help="Packet count per incremental hosts snapshot (default: 2000).",
        type=int,
        default=DEFAULT_HOST_CHUNK_SIZE,
    )
    parser.add_argument(
        "--early-yield-packet-threshold",
        help="Minimum packets before first incremental snapshot is emitted (default: 12000).",
        type=int,
        default=12000,
    )
    parser.add_argument(
        "--worker-threads",
        help="Number of backend worker threads (default: 2x CPU cores).",
        type=int,
        default=2 * (os.cpu_count() or 1),
    )
    parser.add_argument(
        "--wifi-keys-file",
        dest="wifi_keys_file",
        help=(
            "Path to a JSON file containing 802.11 wifi keys to install on "
            "startup. Used by the legacy backend spawn path so background "
            "reruns triggered by 'Send Wi-Fi keys to backend' can decrypt "
            "802.11 frames even when the concurrent-run guard bypasses the "
            "HTTP service."
        ),
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Enable verbose output for debugging.",
        action="count",
        default=0,
    )
    parser.add_argument(
        "--server",
        action="store_true",
        help="Run in HTTP bridge server mode.",
    )
    parser.add_argument(
        "--server-host",
        default="127.0.0.1",
        help="HTTP bridge bind host (server mode).",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=9020,
        help="HTTP bridge bind port (server mode).",
    )
    return parser


def initializeRuntimeResources():
    global runtimeInitialized
    global geoIpReader

    if runtimeInitialized:
        return

    geoDbPath = _resolveCommonResourcePath("GeoLite2-City.mmdb")
    macVendorsPath = _resolveCommonResourcePath("mac-vendors-export.csv")
    icannCsvPath = _resolveCommonResourcePath("service-names-port-numbers.csv")

    if geoDbPath and os.path.exists(geoDbPath):
        geoIpReader = geoip2.database.Reader(geoDbPath)
        print("[Main] GeoIP database loaded from " + geoDbPath, file=sys.stderr)
    else:
        print(
            "[Main] Warning: GeoIP database not found. Checked common dirs: "
            + ", ".join(_candidateCommonDirectories()),
            file=sys.stderr,
        )

    if icannCsvPath and os.path.exists(icannCsvPath):
        with open(icannCsvPath, newline="", encoding="utf-8") as csvFile:
            for csvRow in csv.DictReader(csvFile):
                try:
                    portNum = int(csvRow.get("Port Number", ""))
                    protoStr = csvRow.get("Transport Protocol", "").strip().lower()
                    portDescription = csvRow.get("Description", "No description available")
                    serviceName = csvRow.get("Service Name", "Unknown")
                    if portNum and protoStr:
                        portDescriptionMap[(portNum, protoStr)] = portDescription
                        portServiceNameMap[(portNum, protoStr)] = serviceName
                except (ValueError, TypeError):
                    pass
    else:
        print(
            "[Main] Warning: ICANN port CSV not found. Checked common dirs: "
            + ", ".join(_candidateCommonDirectories()),
            file=sys.stderr,
        )

    if macVendorsPath and os.path.exists(macVendorsPath):
        with open(macVendorsPath, newline="", encoding="utf-8") as csvFile:
            for csvRow in csv.DictReader(csvFile):
                if "Mac Prefix" in csvRow and "Vendor Name" in csvRow:
                    macVendorMap[csvRow["Mac Prefix"].upper()] = csvRow["Vendor Name"]
    else:
        print(
            "[Main] Warning: MAC vendor CSV not found. Checked common dirs: "
            + ", ".join(_candidateCommonDirectories()),
            file=sys.stderr,
        )

    runtimeInitialized = True


def runCaptureFromArgs(runArgs):
    global args
    global verbose
    global hostChunkSize
    global emitJsonSnapshots
    global pcapFilePath
    global config
    global packets
    global totalPackets
    global allPacketCount
    global numWorkerThreads
    global outputDir
    global activeRecon
    global allPacketInfo
    global tcpStreamInitialDstPortMap
    global checkTor
    global torJsonData
    global torNetworkIps

    args = runArgs
    currentJobId = str(getattr(runArgs, "job_id", "") or "").strip()
    verbose = int(getattr(runArgs, "verbose", 0) or 0)
    hostChunkSize = _coercePositiveInt(
        getattr(runArgs, "host_chunk_size", DEFAULT_HOST_CHUNK_SIZE),
        DEFAULT_HOST_CHUNK_SIZE,
    )
    global earlyYieldPacketThreshold
    earlyYieldPacketThreshold = _coercePositiveInt(
        getattr(runArgs, "early_yield_packet_threshold", DEFAULT_EARLY_YIELD_PACKET_THRESHOLD),
        DEFAULT_EARLY_YIELD_PACKET_THRESHOLD,
    )
    emitJsonSnapshots = bool(getattr(runArgs, "emit_json_snapshots", False))
    stopEvent.clear()

    if getattr(runArgs, "wifi_keys", None):
        try:
            _setActiveWifiKeys(runArgs.wifi_keys)
        except Exception:
            pass
    elif getattr(runArgs, "wifi_keys_file", None):
        try:
            wifiKeysPath = str(runArgs.wifi_keys_file).strip()
            if wifiKeysPath and os.path.isfile(wifiKeysPath):
                with open(wifiKeysPath, "r", encoding="utf-8") as wifiKeysFile:
                    wifiKeysPayload = json.load(wifiKeysFile)
                if isinstance(wifiKeysPayload, list) and wifiKeysPayload:
                    _setActiveWifiKeys(wifiKeysPayload)
        except Exception:
            # Failed to read the wifi keys file is non-fatal — the backend
            # will just skip 802.11 decryption for this run.
            pass

    checkTor = bool(getattr(args, "use_tor_check", True))
    torJsonData = {}
    torNetworkIps = {}
    if checkTor:
        try:
            torResponse = requests.get(
                "https://onionoo.torproject.org/details?running=true&flag=Exit&fields=nickname,or_addresses,platform",
                timeout=25,
                headers=packetSnitchRequestHeaders(),
            )
            torResponse.raise_for_status()
            torJsonData = torResponse.json()
            for relay in torJsonData.get("relays", []):
                for addr in relay.get("or_addresses", []):
                    ip = str(addr).rsplit(":", 1)[0].strip("[]")
                    if not ip:
                        continue
                    torNetworkIps[ip] = {
                        "nickname": relay.get("nickname"),
                        "platform": relay.get("platform"),
                    }
        except Exception as torErr:
            # Tor enrichment is optional; continue packet processing when
            # Onionoo is unavailable or returns invalid data.
            checkTor = False
            torJsonData = {}
            torNetworkIps = {}
            if verbose >= 0:
                print(
                    f"[Main] Warning: Tor network lookup unavailable: {torErr}",
                    file=sys.stderr,
                )


    allPacketInfo = []
    with cachedBannersLock:
        cachedBanners.clear()
    with geoIpCacheLock:
        geoIpCache.clear()
    with http2DetectedStreamsLock:
        http2DetectedStreams.clear()

    initializeRuntimeResources()

    try:
        config = configLoader(runArgs.conf if getattr(runArgs, "conf", None) else "conf.yaml")
    except Exception:
        config = {
            "active_recon": True,
        }

    pcapFilePath = runArgs.pcap_file
    if not pcapFilePath or not os.path.exists(pcapFilePath):
        return {
            "success": False,
            "error": "The .pcap file does not exist.",
        }

    packets = scapy.rdpcap(runArgs.pcap_file)  # type: ignore
    # Populate the WPA2 4-way handshake cache once per capture so that
    # CCMP data-frame decryption can find ANonce/SNonce/MAC tuples
    # without re-scanning the entire pcap per packet.
    try:
        dec_wireless_80211.populateWifiHandshakeCache(packets)
    except Exception:
        pass
    tcpStreamInitialDstPortMap = buildTcpStreamInitialDstPortMap(packets)
    allPacketCount = len(packets)
    totalPackets = len(packets)
    if totalPackets == 0:
        return {
            "success": False,
            "error": "No packets found in the capture.",
        }

    requestedWorkerThreads = int(
        getattr(runArgs, "worker_threads", 2 * (os.cpu_count() or 1))
        or 2 * (os.cpu_count() or 1)
    )
    numWorkerThreads = max(1, requestedWorkerThreads)
    outputDir = currentDir + "/" + "testcases"
    if runArgs.output and runArgs.output != "testcases":
        outputDir = runArgs.output
        print("[Main] Using output directory: " + runArgs.output, file=sys.stderr)
    if "output_dir" in config:
        outputDir = currentDir + "/" + config["output_dir"]
        print("[Main] Using output directory from config: " + outputDir, file=sys.stderr)

    if not runArgs.active_recon:
        activeRecon = bool(config.get("active_recon", False))
    else:
        activeRecon = True

    print(
        "[Main] Preparing to process "
        + str(totalPackets)
        + " packets with "
        + str(numWorkerThreads)
        + " threads.",
        file=sys.stderr,
    )

    needsOutputDir = not emitJsonSnapshots
    processingCancelled = False
    finalCaptureData = None
    try:
        if needsOutputDir:
            if os.path.isdir(outputDir):
                shutil.rmtree(outputDir, ignore_errors=True)
            os.makedirs(outputDir, exist_ok=True)
        try:
            startThreading()
        except Exception as startErr:
            print(
                f"[Main] Warning: startThreading raised an exception ({startErr}); retrying.",
                file=sys.stderr,
            )
            startThreading()
        processingCancelled = stopEvent.is_set()
    finally:
        with allPacketInfoLock:
            finalPacketInfoSnapshot = list(allPacketInfo)
        if emitJsonSnapshots:
            captureData = buildHostsPayload(finalPacketInfoSnapshot, "")
            finalCaptureData = captureData
            emitBridgeProgress(
                "in-memory://hosts.json",
                len(finalPacketInfoSnapshot),
                totalPackets,
                True,
                captureData,
                currentJobId,
            )
        else:
            writeHostsSnapshot(outputDir, finalPacketInfoSnapshot, "", hostOutputFile)
            emitBridgeProgress(
                outputDir + "/" + hostOutputFile,
                len(finalPacketInfoSnapshot),
                totalPackets,
                True,
                jobId=currentJobId,
            )

    if needsOutputDir:
        print(
            "[Main] Processing complete. Generated testcases and info files are located in: "
            + outputDir,
            file=sys.stderr,
        )
    else:
        print(
            "[Main] Processing complete. Results streamed in-memory (no testcase directory created).",
            file=sys.stderr,
        )

    return {
        "success": True,
        "cancelled": processingCancelled,
        "outputDir": outputDir,
        "processedPackets": len(finalPacketInfoSnapshot),
        "totalPackets": totalPackets,
        "captureData": finalCaptureData,
    }


class SnitchHttpHandler(BaseHTTPRequestHandler):
    server_version = "SnitchHTTP/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, formatStr, *args):
        print(f"[BridgeServer] {self.address_string()} - {formatStr % args}", file=sys.stderr)

    def sendJson(self, statusCode, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(int(statusCode))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Disable keep-alive so the server doesn't try to read another
        # request after the client closes the connection. This avoids
        # "ConnectionResetError: [Errno 104] Connection reset by peer"
        # when the client disconnects after receiving the response.
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def beginNdjsonStream(self, statusCode=200):
        self.send_response(int(statusCode))
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        # Disable keep-alive so the server doesn't try to read another
        # request after the client closes the NDJSON stream. This avoids
        # "ConnectionResetError: [Errno 104] Connection reset by peer"
        # when the client disconnects after receiving the complete event.
        self.send_header("Connection", "close")
        self.end_headers()

    def sendNdjsonLine(self, payload):
        line = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        self.wfile.write(line)
        self.wfile.flush()

    def parseJsonBody(self):
        try:
            contentLen = int(self.headers.get("Content-Length", "0"))
        except Exception:
            contentLen = 0
        if contentLen <= 0:
            return None
        rawBody = self.rfile.read(contentLen)
        if not rawBody:
            return None
        return json.loads(rawBody.decode("utf-8"))

    def parseMultipartBody(self):
        try:
            contentLen = int(self.headers.get("Content-Length", "0"))
        except Exception:
            contentLen = 0
        if contentLen <= 0:
            return None
        rawBody = self.rfile.read(contentLen)
        if not rawBody:
            return None
        contentType = str(self.headers.get("Content-Type", "") or "").strip()
        boundary = None
        for part in contentType.split(";"):
            part = part.strip()
            if part.lower().startswith("boundary="):
                boundary = part.split("=", 1)[1].strip().strip('"')
                break
        if not boundary:
            return None
        delimiter = ("--" + boundary).encode("utf-8")
        closing = ("--" + boundary + "--").encode("utf-8")
        parts = []
        start = rawBody.find(delimiter)
        if start == -1:
            return parts
        cursor = start + len(delimiter)
        while True:
            nextDelim = rawBody.find(delimiter, cursor)
            if nextDelim == -1:
                break
            part = rawBody[cursor:nextDelim]
            if part.startswith(b"\r\n"):
                part = part[2:]
            if part.endswith(b"\r\n"):
                part = part[:-2]
            headerEnd = part.find(b"\r\n\r\n")
            if headerEnd != -1:
                headers = part[:headerEnd].decode("utf-8", errors="ignore")
                body = part[headerEnd + 4:]
                name = None
                filename = None
                for line in headers.split("\r\n"):
                    if line.lower().startswith("content-disposition:"):
                        for kv in line.split(";"):
                            kv = kv.strip()
                            if kv.lower().startswith("name="):
                                name = kv.split("=", 1)[1].strip().strip('"')
                            if kv.lower().startswith("filename="):
                                filename = kv.split("=", 1)[1].strip().strip('"')
                if name:
                    parts.append({"name": name, "filename": filename, "body": body})
            cursor = nextDelim + len(delimiter)
            if rawBody[cursor:cursor + 2] == b"--":
                break
            if rawBody[cursor:cursor + 2] == b"\r\n":
                cursor += 2
        return parts

    def do_GET(self):
        parsedUrl = urlparse(self.path)
        queryParams = parse_qs(parsedUrl.query or "", keep_blank_values=False)

        if parsedUrl.path in {"/", "/status"}:
            self.sendJson(200, _buildBackendStatusPayload(self.server))
            return
        if parsedUrl.path == "/ping":
            self.sendJson(
                200,
                {
                    "type": "pong",
                    "service": "snitch-http",
                },
            )
            return
        if parsedUrl.path == "/version":
            self.sendJson(
                200,
                {
                    "type": "version",
                    "service": "packetsnitch",
                    "version": PACKETSNITCH_VERSION,
                },
            )
            return
        if parsedUrl.path == "/geoip":
            queryIp = str((queryParams.get("ip") or [""])[0] or "").strip()
            querySide = str((queryParams.get("side") or ["src"])[0] or "src").strip().lower()
            if not queryIp:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Missing ip query parameter",
                    },
                )
                return

            if querySide not in {"src", "dst"}:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Invalid side query parameter",
                    },
                )
                return

            try:
                response = buildGeoipLookupResponse(queryIp, querySide)
            except ValueError:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Invalid IP address",
                    },
                )
                return
            except Exception as geoLookupError:
                self.sendJson(
                    500,
                    {
                        "success": False,
                        "error": str(geoLookupError),
                    },
                )
                return

            self.sendJson(200, response)
            return
        if parsedUrl.path == "/whois":
            queryIp = str((queryParams.get("ip") or [""])[0] or "").strip()
            if not queryIp:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Missing ip query parameter",
                    },
                )
                return

            try:
                response = buildWhoisLookupResponse(queryIp)
            except ValueError:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Invalid IP address",
                    },
                )
                return
            except Exception as whoisLookupError:
                self.sendJson(
                    500,
                    {
                        "success": False,
                        "error": str(whoisLookupError),
                    },
                )
                return

            self.sendJson(200, response)
            return
        if parsedUrl.path == "/ipsum":
            queryIp = str((queryParams.get("ip") or [""])[0] or "").strip()
            if not queryIp:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Missing ip query parameter",
                    },
                )
                return

            try:
                response = buildIpsumLookupResponse(queryIp)
            except ValueError:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Invalid IP address",
                    },
                )
                return
            except Exception as ipsumLookupError:
                self.sendJson(
                    500,
                    {
                        "success": False,
                        "error": str(ipsumLookupError),
                    },
                )
                return

            self.sendJson(200, response)
            return
        if parsedUrl.path == "/tor":
            queryIp = str((queryParams.get("ip") or [""])[0] or "").strip()
            if not queryIp:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Missing ip query parameter",
                    },
                )
                return

            try:
                response = buildTorLookupResponse(queryIp)
            except ValueError:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Invalid IP address",
                    },
                )
                return
            except Exception as torLookupError:
                self.sendJson(
                    500,
                    {
                        "success": False,
                        "error": str(torLookupError),
                    },
                )
                return

            self.sendJson(200, response)
            return
        if parsedUrl.path == "/shodan":
            queryIp = str((queryParams.get("ip") or [""])[0] or "").strip()
            if not queryIp:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Missing ip query parameter",
                    },
                )
                return

            try:
                response = buildShodanInternetDbLookupResponse(queryIp)
            except ValueError:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Invalid IP address",
                    },
                )
                return
            except Exception as shodanLookupError:
                self.sendJson(
                    500,
                    {
                        "success": False,
                        "error": str(shodanLookupError),
                    },
                )
                return

            self.sendJson(200, response)
            return
        if parsedUrl.path == "/virustotal":
            lookupType = str((queryParams.get("type") or ["auto"])[0] or "auto").strip()
            lookupValue = str((queryParams.get("value") or [""])[0] or "").strip()
            diagnosticOnly = str((queryParams.get("diagnostic") or ["0"])[0] or "0").strip().lower() in {"1", "true", "yes"}
            apiKey = str(self.headers.get("x-apikey") or (queryParams.get("apikey") or [""])[0] or "").strip()

            if not diagnosticOnly and not lookupValue:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Missing value query parameter",
                    },
                )
                return

            try:
                response = buildVirusTotalLookupResponse(
                    lookupType,
                    lookupValue,
                    apiKey,
                    diagnosticOnly=diagnosticOnly,
                )
            except ValueError as validationError:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": str(validationError),
                    },
                )
                return
            except Exception as lookupError:
                self.sendJson(
                    500,
                    {
                        "success": False,
                        "error": str(lookupError),
                    },
                )
                return

            self.sendJson(200, response)
            return
        self.sendJson(
            404,
            {
                "success": False,
                "error": "Not found",
            },
        )

    def do_POST(self):
        global progressEventCallback
        global backendJobsProcessedSinceStart

        if self.path == "/control":
            try:
                request = self.parseJsonBody()
                if not isinstance(request, dict):
                    self.sendJson(
                        400,
                        {
                            "success": False,
                            "error": "Invalid JSON request",
                        },
                    )
                    return

                action = str(request.get("action") or "").strip().lower()
                if action == "stop-processing":
                    stopEvent.set()
                    self.sendJson(
                        200,
                        {
                            "success": True,
                            "action": action,
                            "processing": bool(processingJobs),
                        },
                    )
                    return

                if action in {"set-runtime-config", "set-config", "configure"}:
                    response, statusCode = _applyRuntimeConfigUpdate(request)
                    self.sendJson(statusCode, response)
                    return

                if action == "shutdown":
                    stopEvent.set()
                    setattr(self.server, "snitch_shutdown_reason", "control-shutdown")
                    self.sendJson(
                        200,
                        {
                            "success": True,
                            "action": action,
                        },
                    )

                    # Shutdown must run on a different thread than the request handler.
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return

                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Unsupported control action",
                    },
                )
                return
            except Exception as controlError:
                self.sendJson(
                    500,
                    {
                        "success": False,
                        "error": str(controlError),
                        "traceback": traceback.format_exc(),
                    },
                )
                return

        if self.path == "/virustotal/upload":
            apiKey = str(self.headers.get("x-apikey") or "").strip()
            if not apiKey:
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Missing VirusTotal API key",
                    },
                )
                return
            try:
                parts = self.parseMultipartBody() or []
                filePart = next(
                    (part for part in parts if part.get("name") == "file" and part.get("body")),
                    None,
                )
                if not filePart:
                    self.sendJson(
                        400,
                        {
                            "success": False,
                            "error": "Missing file upload body",
                        },
                    )
                    return
                fileBuffer = filePart["body"]
                fileName = str(filePart.get("filename") or "sample.bin").strip() or "sample.bin"
                if len(fileBuffer) == 0:
                    self.sendJson(
                        400,
                        {
                            "success": False,
                            "error": "Empty file upload body",
                        },
                    )
                    return
                uploadResponse = uploadFileToVirusTotal(fileBuffer, fileName, apiKey)
                self.sendJson(200, uploadResponse)
                return
            except Exception as uploadError:
                self.sendJson(
                    500,
                    {
                        "success": False,
                        "error": str(uploadError),
                        "traceback": traceback.format_exc(),
                    },
                )
                return

        if self.path == "/pcap/write":
            try:
                request = self.parseJsonBody()
            except Exception as error:
                self.sendJson(400, {"success": False, "error": f"Invalid JSON body: {error}"})
                return
            if not isinstance(request, dict):
                self.sendJson(400, {"success": False, "error": "Invalid JSON body"})
                return

            outputPath = str(request.get("outputPcap") or "").strip()
            filterExpression = str(request.get("filter") or "").strip()
            sourceRequests = request.get("sources")
            if not outputPath:
                self.sendJson(400, {"success": False, "error": "outputPcap is required"})
                return
            if not isinstance(sourceRequests, list) or not sourceRequests:
                self.sendJson(400, {"success": False, "error": "sources must be a non-empty array"})
                return

            try:
                entries = []
                skippedSources = []
                for sourceIndex, sourceRequest in enumerate(sourceRequests):
                    if not isinstance(sourceRequest, dict):
                        skippedSources.append({"index": sourceIndex, "reason": "invalid source"})
                        continue
                    inputPath = str(sourceRequest.get("inputPcap") or "").strip()
                    sourceId = str(sourceRequest.get("sourceId") or f"source-{sourceIndex + 1}").strip()
                    try:
                        ordinal = int(sourceRequest.get("ordinal", sourceIndex))
                    except (TypeError, ValueError):
                        ordinal = sourceIndex
                    selectedPacketIndexes = sourceRequest.get("packetIndexes")
                    if isinstance(selectedPacketIndexes, list):
                        selectedPacketIndexes = {
                            int(index)
                            for index in selectedPacketIndexes
                            if isinstance(index, (int, float)) and int(index) >= 0
                        }
                    else:
                        selectedPacketIndexes = None
                    if not inputPath or not os.path.isfile(inputPath):
                        skippedSources.append({
                            "sourceId": sourceId,
                            "reason": "input pcap not found",
                        })
                        continue

                    packets = scapy.rdpcap(inputPath)
                    if filterExpression and not isinstance(selectedPacketIndexes, set):
                        # Apply the same display-filter expression to every source.
                        # The JSON/session filter language is not a libpcap BPF
                        # language, so use the backend's decoded packet fields.
                        # A pcap export with a non-empty filter is intentionally
                        # handled separately from the no-filter full export path.
                        try:
                            packets = scapy.sniff(offline=inputPath, filter=filterExpression)
                        except Exception:
                            raise ValueError(
                                "PCAP export filters must be valid libpcap expressions "
                                "when exporting directly from source pcaps"
                            )

                    for packetIndex, packet in enumerate(packets):
                        if selectedPacketIndexes is not None and packetIndex not in selectedPacketIndexes:
                            continue
                        packetBytes = bytes(packet)
                        digest = hashlib.sha256(packetBytes).hexdigest()[:24]
                        timestamp = float(getattr(packet, "time", 0) or 0)
                        entries.append({
                            "packet": packet,
                            "sourceId": sourceId,
                            "ordinal": ordinal,
                            "packetIndex": packetIndex,
                            "digest": digest,
                            "timestamp": timestamp,
                        })

                # A single source is preserved packet-for-packet. For merged
                # sources, collapse byte-identical frames while retaining the
                # first source/order occurrence. This is deliberately not TCP
                # retransmission detection: identical frames from independently
                # captured source pcaps are the false duplicates being removed.
                isMultiSource = len(sourceRequests) > 1
                totalEntryCount = len(entries)
                if isMultiSource:
                    entries.sort(key=lambda entry: (
                        entry["timestamp"],
                        entry["ordinal"],
                        entry["packetIndex"],
                        entry["digest"],
                    ))
                    digestSources = {}
                    collapsedEntries = []
                    for entry in entries:
                        sourceIds = digestSources.setdefault(entry["digest"], set())
                        if sourceIds and entry["sourceId"] not in sourceIds:
                            continue
                        sourceIds.add(entry["sourceId"])
                        collapsedEntries.append(entry)
                    entries = collapsedEntries

                packetsToWrite = [entry["packet"] for entry in entries]
                if not packetsToWrite and skippedSources and not totalEntryCount:
                    self.sendJson(400, {
                        "success": False,
                        "error": "No readable packets were found in the supplied pcap sources",
                        "skippedSources": skippedSources,
                    })
                    return
                scapy.wrpcap(outputPath, packetsToWrite)
                self.sendJson(200, {
                    "success": True,
                    "outputPcap": outputPath,
                    "packetCount": len(packetsToWrite),
                    "totalCount": totalEntryCount,
                    "collapsedCount": totalEntryCount - len(packetsToWrite),
                    "skippedSources": skippedSources,
                })
            except Exception as error:
                self.sendJson(500, {
                    "success": False,
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                })
            return

        if self.path != "/process":
            self.sendJson(
                404,
                {
                    "success": False,
                    "error": "Not found",
                },
            )
            return

        tempPcapPath = None
        try:
            request = self.parseJsonBody()
            if not isinstance(request, dict):
                self.sendJson(
                    400,
                    {
                        "success": False,
                        "error": "Invalid JSON request",
                    },
                )
                return

            pcapPath = request.get("pcapPath")
            pcapBase64 = request.get("pcapBase64")
            pcapFileName = request.get("pcapFileName") or "http-request.pcap"

            if isinstance(pcapBase64, str) and pcapBase64.strip():
                decoded = base64.b64decode(pcapBase64.strip())
                ext = ".pcapng" if str(pcapFileName).lower().endswith(".pcapng") else ".pcap"
                fd, tempPcapPath = tempfile.mkstemp(prefix="snitch-http-", suffix=ext)
                with os.fdopen(fd, "wb") as tempFile:
                    tempFile.write(decoded)
                pcapPath = tempPcapPath

            requestJobId = str(request.get("jobId") or "").strip()
            if not requestJobId:
                requestJobId = f"process-{int(time.time() * 1000)}"

            runArgs = argparse.Namespace(
                pcap_file=pcapPath,
                output=request.get("output") or "testcases",
                source_port=request.get("sourcePort"),
                dest_port=request.get("destPort"),
                timeout=int(request.get("timeout") or 3),
                active_recon=bool(request.get("activeRecon", True)),
                use_tor_check=bool(request.get("useTorCheck", True)),
                conf=request.get("conf"),
                host_chunk_size=_coercePositiveInt(
                    request.get("hostChunkSize"),
                    _getRuntimeConfigSnapshot()["hostChunkSize"],
                ),
                early_yield_packet_threshold=_coercePositiveInt(
                    request.get("earlyYieldPacketThreshold"),
                    DEFAULT_EARLY_YIELD_PACKET_THRESHOLD,
                ),
                worker_threads=int(
                    request.get("workerThreads") or _getRuntimeConfigSnapshot()["workerThreads"]
                ),
                emit_json_snapshots=bool(
                    request["emitJsonSnapshots"]
                    if "emitJsonSnapshots" in request
                    else True
                ),
                verbose=int(request.get("verbose") or 0),
                server=False,
                server_host="127.0.0.1",
                server_port=0,
                job_id=requestJobId,
                wifi_keys=request.get("wifiKeys") if isinstance(request.get("wifiKeys"), list) else None,
            )

            multiprocessingContext = multiprocessing.get_context("spawn")
            progressQueue = multiprocessingContext.Queue()
            resultQueue = multiprocessingContext.Queue()
            _setActiveProcessingJob(jobId=runArgs.job_id, pcapPath=runArgs.pcap_file)
            workerProcess = multiprocessingContext.Process(
                target=_runCaptureInProcess,
                args=(runArgs, progressQueue, resultQueue),
                daemon=True,
            )
            workerProcess.start()

            self.beginNdjsonStream(200)

            while True:
                if not workerProcess.is_alive() and progressQueue.empty():
                    break
                try:
                    progressEvent = progressQueue.get(timeout=0.2)
                except queue.Empty:
                    continue
                progressEventPayload = {
                    "type": "progress",
                    "jobId": str(progressEvent.get("jobId") or runArgs.job_id),
                    "path": progressEvent.get("path"),
                    "processedPackets": progressEvent.get("processedPackets", 0),
                    "totalPackets": progressEvent.get("totalPackets", 0),
                    "complete": bool(progressEvent.get("complete", False)),
                    "captureData": progressEvent.get("captureData")
                    if isinstance(progressEvent.get("captureData"), dict)
                    else None,
                }
                with processingJobLock:
                    activeJob = processingJobs.get(str(runArgs.job_id))
                    if activeJob is not None:
                        activeJob["processedPackets"] = progressEventPayload["processedPackets"]
                        activeJob["totalPackets"] = progressEventPayload["totalPackets"]
                self.sendNdjsonLine(progressEventPayload)

            workerProcess.join(timeout=1)
            resultHolder = resultQueue.get() if not resultQueue.empty() else {}
            with processingJobLock:
                backendJobsProcessedSinceStart += 1
            _clearActiveProcessingJob(runArgs.job_id)

            if "error" in resultHolder:
                self.sendNdjsonLine(
                    {
                        "type": "error",
                        "jobId": str(runArgs.job_id),
                        "success": False,
                        "error": str(resultHolder.get("error")),
                        "traceback": resultHolder.get("traceback", ""),
                    }
                )
                return

            result = resultHolder.get("result") or {}
            self.sendNdjsonLine(
                {
                    "type": "complete",
                    "jobId": str(runArgs.job_id),
                    "success": bool(result.get("success")),
                    "cancelled": bool(result.get("cancelled", False)),
                    "error": result.get("error"),
                    "stdout": "",
                    "processedPackets": int(result.get("processedPackets") or 0),
                    "totalPackets": int(result.get("totalPackets") or 0),
                    "captureData": result.get("captureData")
                    if isinstance(result.get("captureData"), dict)
                    else None,
                }
            )
        except Exception as requestError:
            try:
                self.sendJson(
                    500,
                    {
                        "success": False,
                        "error": str(requestError),
                        "traceback": traceback.format_exc(),
                    },
                )
            except Exception:
                # If streaming already started and socket is gone, there's nothing else to do.
                pass
        finally:
            if tempPcapPath and os.path.exists(tempPcapPath):
                try:
                    os.unlink(tempPcapPath)
                except Exception:
                    pass


def runHttpServer(serverHost, serverPort):
    class ThreadedHttpServer(ThreadingHTTPServer):
        allow_reuse_address = True

    # Retry the bind a few times — the previous backend process may have
    # just exited and the OS may need a moment to release the TCP socket.
    maxBindAttempts = 5
    bindRetryDelaySeconds = 1.0
    httpServer = None
    for bindAttempt in range(1, maxBindAttempts + 1):
        try:
            httpServer = ThreadedHttpServer((serverHost, int(serverPort)), SnitchHttpHandler)
            break
        except OSError as bindError:
            errnoStr = getattr(bindError, "errno", None)
            if bindAttempt < maxBindAttempts:
                print(
                    f"[BridgeServer] Bind attempt {bindAttempt}/{maxBindAttempts} failed"
                    f" host={serverHost} port={int(serverPort)}"
                    f" (errno={errnoStr}): {bindError}; retrying in {bindRetryDelaySeconds:.1f}s",
                    file=sys.stderr,
                )
                time.sleep(bindRetryDelaySeconds)
            else:
                print(
                    f"[BridgeServer] Failed to bind host={serverHost} port={int(serverPort)}"
                    f" (errno={errnoStr}): {bindError}",
                    file=sys.stderr,
                )
                return "bind-failed", 1

    with httpServer as server:
        setattr(server, "snitch_shutdown_reason", "server-stop")
        print(
            f"[BridgeServer] Listening host={serverHost} port={int(serverPort)}",
            file=sys.stderr,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            # Suppress traceback for expected interactive/process-manager shutdowns.
            return "keyboard-interrupt", 130

        return getattr(server, "snitch_shutdown_reason", "server-stop"), 0


def main():
    global backendRuntimeMode
    global backendShutdownReason

    parser = buildParser()
    parsedArgs = parser.parse_args()

    if parsedArgs.version:
        backendRuntimeMode = "version"
        backendShutdownReason = "version-request"
        print(PACKETSNITCH_VERSION)
        return 0

    startupMode = "http-server" if parsedArgs.server else "cli"
    backendRuntimeMode = startupMode
    logBackendStartup(startupMode)

    # Ensure shared runtime resources are ready for both server and CLI modes.
    # Without this, server-only workflows (e.g. loading a saved session and
    # calling /geoip) can run before the GeoIP reader is initialized.
    initializeRuntimeResources()

    if parsedArgs.server:
        backendShutdownReason, exitCode = runHttpServer(
            parsedArgs.server_host, parsedArgs.server_port
        )
        return int(exitCode)

    if not parsedArgs.pcap_file:
        parser.error("pcap_file is required unless --server is used")

    result = runCaptureFromArgs(parsedArgs)
    backendShutdownReason = "completed" if result.get("success") else "failed"
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    exitCode = 0
    try:
        exitCode = main()
    except KeyboardInterrupt:
        backendShutdownReason = "keyboard-interrupt"
        exitCode = 130
    except Exception as fatalError:
        # Catch-all so that any unhandled exception (e.g. OSError from a
        # bind failure in runHttpServer) produces a clean diagnostic line
        # with the correct shutdown reason, instead of a raw traceback
        # that leaves the bridge guessing about what happened.
        backendShutdownReason = "fatal-error"
        exitCode = 1
        print(
            f"[Main] Fatal error: {fatalError}\n{traceback.format_exc()}",
            file=sys.stderr,
        )
    finally:
        if geoIpReader is not None:
            try:
                geoIpReader.close()
            except Exception:
                pass

        if backendRuntimeMode != "version":
            logBackendShutdown(backendRuntimeMode, backendShutdownReason, exitCode)
    sys.exit(exitCode)
