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
import json
import os
import queue
import re
import shutil
import socket
import ssl
import sys
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
from urllib.parse import parse_qs, unquote_plus, urlparse
from datetime import datetime
from decimal import Decimal
from functools import lru_cache
from cryptography.utils import CryptographyDeprecationWarning


warnings.simplefilter("module")
os.environ["PYTHONWARNINGS"] = "module"
warnings.formatwarning = lambda msg, cat, fname, ln, file=None, line=None: (
    f"[Main] {cat.__name__} {msg}\n"
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
backendRuntimeMode = "unknown"
backendShutdownReason = "normal"


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

activeRecon = "False"
numWorkerThreads = (os.cpu_count()//2 or 2)
isSSH = False
# Shared result lists, protected by their respective locks so that threads
# can safely append results concurrently without data corruption.
allPacketInfo = []
allPacketInfoLock = threading.Lock()

hostOutputFile = "hosts.json"
hostChunkSize = 250
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

# --- Banner cache: (ip, port) -> banner dict, avoids redundant socket probes ---
cachedBanners: dict = {}
cachedBannersLock = threading.Lock()

# --- TCP stream protocol cache: canonical stream key -> initial packet dst port ---
tcpStreamInitialDstPortMap: dict = {}
# Streams positively identified as HTTP/2 via client connection preface.
http2DetectedStreams: set = set()
http2DetectedStreamsLock = threading.Lock()

# --- HTTP method set used by decodeHTTP() for request-line detection ---
HTTP_METHODS: set = {
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "TRACE",
    "CONNECT",
}

TLS_SERVICE_PORTS = {443, 465, 636, 853, 8443, 9443, 5061}
HTTP2_PREFACE_BYTES = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Matches common credential-related field names in HTTP query strings, POST bodies, etc.
# Each keyword is an independent alternative; compound names like "auth_token" or
# "api_key" are covered by the optional prefix/suffix anchors.
CREDENTIAL_FIELD_RE = re.compile(
    r"^(?:.*[_\-.])?(?:pass(?:w(?:or)?d?)?|pw|secret|auth|auth_token|"
    r"credential|api[_\-.]?key|token|user(?:name)?|login|email)(?:[_\-.].*)?$",
    re.IGNORECASE,
)


def _extractUrlCredentials(paramStr):
    """
    Parse a URL-encoded query string or POST body (e.g. ``user=alice&pass=s3cr3t``).
    Returns a dict of {fieldName: value} for every field whose name matches
    CREDENTIAL_FIELD_RE and whose value is non-empty.  Returns an empty dict when
    nothing interesting is found.
    """
    creds = {}
    if not paramStr:
        return creds
    for pair in paramStr.split("&"):
        if "=" not in pair:
            continue
        rawKey, _, rawVal = pair.partition("=")
        key = unquote_plus(rawKey.strip())
        val = unquote_plus(rawVal.strip())
        if val and CREDENTIAL_FIELD_RE.match(key):
            creds[key] = val
    return creds


# Cookie names that are always treated as sensitive regardless of CREDENTIAL_FIELD_RE.
# These are common session / auth cookie names used by popular frameworks and platforms.
_SENSITIVE_COOKIE_RE = re.compile(
    r"^(?:sess(?:ion)?(?:id)?|auth(?:_?token)?|access_token|refresh_token|"
    r"remember(?:_me)?(?:_token)?|jwt|bearer|csrf(?:_token)?|xsrf(?:_token)?|"
    r"sid|uid|user(?:id)?|login|pass(?:w(?:or)?d?)?|pw|secret|"
    r"PHPSESSID|ASP\.NET_SessionId|__Secure-.*|__Host-.*)$",
    re.IGNORECASE,
)


def _extractCookieCredentials(cookieHeader):
    """
    Parse a ``Cookie:`` request header (e.g. ``session=abc; token=xyz; q=1``).
    Always stores the raw full cookie string under the key ``cookie_raw``.
    Also stores each individual cookie whose name matches CREDENTIAL_FIELD_RE or
    _SENSITIVE_COOKIE_RE under the key ``cookie.<name>``.
    Returns a dict; an empty dict means nothing sensitive was found.
    """
    if not cookieHeader:
        return {}
    creds = {"cookie_raw": cookieHeader}
    for crumb in cookieHeader.split(";"):
        crumb = crumb.strip()
        if "=" not in crumb:
            continue
        name, _, value = crumb.partition("=")
        name = name.strip()
        value = value.strip()
        if value and (
            CREDENTIAL_FIELD_RE.match(name) or _SENSITIVE_COOKIE_RE.match(name)
        ):
            creds[f"cookie.{name}"] = value
    return creds


def _extractSetCookieCredentials(setCookieHeader):
    """
    Parse a ``Set-Cookie:`` response header and return a dict with the raw value
    and the parsed cookie name/value pair (before any attributes like HttpOnly).
    """
    if not setCookieHeader:
        return {}
    creds = {"set_cookie_raw": setCookieHeader}
    # The first pair before any ";" is the actual cookie name=value
    firstPair = setCookieHeader.split(";")[0].strip()
    if "=" in firstPair:
        name, _, value = firstPair.partition("=")
        name = name.strip()
        value = value.strip()
        if value:
            creds[f"cookie.{name}"] = value
    return creds


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
        }


def _applyRuntimeConfigUpdate(request):
    global hostChunkSize
    global numWorkerThreads

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

    return {
        "success": True,
        "action": "set-runtime-config",
        **_getRuntimeConfigSnapshot(),
    }, 200


# Matches JSON key-value pairs where the key looks like a credential field.
# The keyword list mirrors CREDENTIAL_FIELD_RE but is spelled out explicitly here
# so the pattern is self-contained and does not depend on regex string manipulation.
_CRED_KEYWORDS = (
    r"pass(?:w(?:or)?d?)?|pw|secret|auth|auth_token|credential|"
    r"api[_\-.]?key|token|user(?:name)?|login|email"
)
_JSON_CRED_RE = re.compile(
    r'"(?:(?:.*[_\-.])?' + r"(?:" + _CRED_KEYWORDS + r")" + r'(?:[_\-.].*)?)"'
    r'\s*:\s*"([^"]{1,512})"',
    re.IGNORECASE,
)

# Matches plain-text key:value or key=value lines where the key is credential-like.
# Delimiters before the key include whitespace, common punctuation, and '&' (form data).
_TEXT_CRED_RE = re.compile(
    r"(?:^|[\s,{;&])"
    r"(?:(?:.*[_\-.])?(?:" + _CRED_KEYWORDS + r")(?:[_\-.].*)?)"
    r'(?:\s*[=:]\s*)([^\s&"\'<>,;]{1,512})',
    re.IGNORECASE | re.MULTILINE,
)


def _extractPostBodyCredentials(body, contentType):
    """
    Scan a POST/PUT/PATCH body for credential fields regardless of content type.
    - For ``application/json`` bodies: uses JSON key-value regex.
    - For all other bodies (multipart, plain-text, XML, etc.): uses a more general
      key=value / key:value regex.
    Returns a dict of {fieldName: value}; empty dict when nothing is found.
    """
    if not body or not body.strip():
        return {}
    creds = {}
    lowerContentType = contentType.lower()
    if "json" in lowerContentType:
        for match in _JSON_CRED_RE.finditer(body):
            val = match.group(1).strip()
            if val:
                # Derive a human-readable key from the JSON property name
                fullMatch = match.group(0)
                keyEnd = fullMatch.index('"', 1)
                creds[fullMatch[1:keyEnd]] = val
    else:
        for match in _TEXT_CRED_RE.finditer(body):
            val = match.group(1).strip()
            if val:
                # Use the raw matched token before the separator as the key
                raw = match.group(0).lstrip(" \t,{;&")
                sep = next((i for i, c in enumerate(raw) if c in "=:"), len(raw))
                key = raw[:sep].strip()
                if key:
                    creds[key] = val
    return creds


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

def streamStabilzeProtocol(streamKey, initialDstPort):
    """
    Stabilize the protocol for a TCP stream based on its initial destination port.
    Updates the global tcpStreamInitialDstPortMap with the canonical stream key.
    """
    # we need to follow the four tuple of the stream, and store the initial destination port for that stream
    if streamKey not in tcpStreamInitialDstPortMap:
        tcpStreamInitialDstPortMap[streamKey] = initialDstPort
    return tcpStreamInitialDstPortMap[streamKey]


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
        httpResponse = requests.get(url, timeout=timeout, verify=False)
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
    destDir = outputDirPath + "/" + portDir
    if not os.path.exists(destDir):
        try:
            os.mkdir(destDir)
        except Exception:
            print("[Worker] Could not create minor dir.")
    with open(destDir + "/pcap.data_packet." + str(index) + ".dat", "wb") as out:
        out.write(data)


def _jsonValuesEquivalent(leftValue, rightValue):
    """
    Compare JSON-like values for semantic equality.
    Falls back to direct equality when JSON serialisation fails.
    """
    try:
        return json.dumps(leftValue, sort_keys=True, default=str) == json.dumps(
            rightValue, sort_keys=True, default=str
        )
    except Exception:
        return leftValue == rightValue


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


packetsByHost = {}


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


def byHost(outputDirPath, finalSummary):
    """
    Organise allPacketInfo entries by destination host and write the result to hosts.json.
    Bug fix: the original code created the empty list but then only appended on the
    *else* branch, silently dropping the first packet for every unique host.
    Now every packet is always appended.
    """
    global packetsByHost
    for entry in allPacketInfo:
        host = entry.get("host")
        if host not in packetsByHost:
            packetsByHost[host] = []
        # Always append — previously the first packet per host was lost
        packetsByHost[host].append(entry.get("packet"))

    packetsByHost = sortAndIndexPackets(packetsByHost)

    # Write the consolidated hosts file; use a context manager to guarantee flush/close
    with open(outputDirPath + "/" + hostOutputFile, "w+", encoding="utf-8") as f:
        f.write(
            json.dumps({"host": packetsByHost, "final.summary": finalSummary}, indent=2)
        )


def buildHostsPayload(packetEntries, finalSummary=""):
    """
    Build a frontend-compatible hosts payload from packet entries.
    """
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

def emitBridgeProgress(pathValue, processedPackets, totalPackets, isFinal, captureData=None):
    """
    Emit backend progress in the legacy stderr format and, when configured,
    forward a structured payload to the TCP bridge callback.
    """

    finalFlag = 1 if isFinal else 0
    print(
        f"{progressLinePrefix} path={pathValue} processed={processedPackets} total={totalPackets} final={finalFlag}",
        file=sys.stderr,
    )

    if callable(progressEventCallback):
        try:
            payload = {
                "path": pathValue,
                "processedPackets": int(processedPackets),
                "totalPackets": int(totalPackets),
                "complete": bool(isFinal),
            }
            if isinstance(captureData, dict):
                payload["captureData"] = captureData
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
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": f"PacketSnitch/{PACKETSNITCH_VERSION}",
                },
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
            headers={
                "Accept": "text/plain",
                "User-Agent": f"PacketSnitch/{PACKETSNITCH_VERSION}",
            },
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


def getTcpStreamKey(srcIp, srcPort, dstIp, dstPort):
    """
    Return a direction-agnostic key for a TCP stream.
    """
    endpointA = (str(srcIp), int(srcPort))
    endpointB = (str(dstIp), int(dstPort))
    return tuple(sorted((endpointA, endpointB)))


def buildTcpStreamInitialDstPortMap(packetList):
    """
    Build a map of TCP stream key -> destination port from the stream's first packet
    in capture order.
    """
    streamMap = {}
    for p in packetList:
        if not (p.haslayer("IP") and p.haslayer("TCP")):
            continue
        streamKey = getTcpStreamKey(
            p["IP"].src, p["TCP"].sport, p["IP"].dst, p["TCP"].dport
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


def decodeSNMP(p):
    """
    Decode SNMP layer fields from a scapy packet.
    Returns a dict with both display-friendly keys (e.g., 'Version') and
    dot-notation keys (e.g., 'snmp.version') for version, community, and PDU type,
    or None if the packet does not contain an SNMP layer or decoding fails.
    """
    if not p.haslayer("SNMP"):
        return None
    snmpLayer = p["SNMP"]
    try:
        version = int(snmpLayer.version)
        versionMap = {0: "SNMPv1", 1: "SNMPv2c", 3: "SNMPv3"}
        versionStr = versionMap.get(version, f"Unknown({version})")
        community = ""
        if hasattr(snmpLayer, "community") and snmpLayer.community is not None:
            community = (
                snmpLayer.community.decode(errors="ignore")
                if isinstance(snmpLayer.community, bytes)
                else str(snmpLayer.community)
            )
        pduType = "Unknown"
        if hasattr(snmpLayer, "PDU") and snmpLayer.PDU is not None:
            pduType = snmpLayer.PDU.__class__.__name__
        return {
            "Version": versionStr,
            "snmp.version": versionStr,
            "Community": community,
            "snmp.community": community,
            "PDU Type": pduType,
            "snmp.pdu_type": pduType,
        }
    except Exception:
        return None


def decodeDHCP(p):
    """
    Decode DHCP/BOOTP layer fields from a scapy packet.
    Returns a dict with both display-friendly keys and dot-notation keys for message
    type, transaction ID, and IP fields (Client IP, Your IP, Server IP), or None if
    the packet does not contain a DHCP layer or decoding fails.
    """
    if not p.haslayer("DHCP"):
        return None
    dhcpLayer = p["DHCP"]
    bootpLayer = p["BOOTP"] if p.haslayer("BOOTP") else None
    try:
        msgType = "Unknown"
        msgTypeMap = {
            1: "Discover",
            2: "Offer",
            3: "Request",
            4: "Decline",
            5: "ACK",
            6: "NAK",
            7: "Release",
            8: "Inform",
        }
        for opt in dhcpLayer.options:
            if isinstance(opt, tuple) and opt[0] == "message-type" and len(opt) > 1:
                msgType = msgTypeMap.get(opt[1], str(opt[1]))
                break
        result = {
            "Message Type": msgType,
            "dhcp.msg_type": msgType,
        }
        if bootpLayer:
            try:
                xid = hex(int(bootpLayer.xid)) if hasattr(bootpLayer, "xid") else "N/A"
            except (TypeError, ValueError):
                xid = "N/A"
            ciaddr = str(bootpLayer.ciaddr) if hasattr(bootpLayer, "ciaddr") else "N/A"
            yiaddr = str(bootpLayer.yiaddr) if hasattr(bootpLayer, "yiaddr") else "N/A"
            siaddr = str(bootpLayer.siaddr) if hasattr(bootpLayer, "siaddr") else "N/A"
            result["Transaction ID"] = xid
            result["dhcp.xid"] = xid
            result["Client IP"] = ciaddr
            result["dhcp.ciaddr"] = ciaddr
            result["Your IP"] = yiaddr
            result["dhcp.yiaddr"] = yiaddr
            result["Server IP"] = siaddr
            result["dhcp.siaddr"] = siaddr
        return result
    except Exception:
        return None


def decodeNTP(p):
    """
    Decode NTP layer fields from a scapy packet.
    Returns a dict with both display-friendly keys and dot-notation keys for leap
    indicator, version, mode, stratum, and reference ID, or None if the packet does
    not contain an NTP layer or decoding fails.
    """
    if not p.haslayer("NTP"):
        return None
    ntpLayer = p["NTP"]
    modeMap = {
        0: "Reserved",
        1: "Symmetric Active",
        2: "Symmetric Passive",
        3: "Client",
        4: "Server",
        5: "Broadcast",
        6: "NTP Control",
        7: "Private",
    }
    try:
        leap = int(ntpLayer.leap) if hasattr(ntpLayer, "leap") else 0
        version = int(ntpLayer.version) if hasattr(ntpLayer, "version") else 0
        mode = int(ntpLayer.mode) if hasattr(ntpLayer, "mode") else 0
        stratum = int(ntpLayer.stratum) if hasattr(ntpLayer, "stratum") else 0
        modeStr = modeMap.get(mode, f"Unknown({mode})")
        refId = str(ntpLayer.id) if hasattr(ntpLayer, "id") else "N/A"
        return {
            "Leap Indicator": leap,
            "ntp.leap": leap,
            "Version": version,
            "ntp.version": version,
            "Mode": modeStr,
            "ntp.mode": modeStr,
            "Stratum": stratum,
            "ntp.stratum": stratum,
            "Reference ID": refId,
            "ntp.ref_id": refId,
        }
    except Exception:
        return None


def decodeIGMP(p, rawPayload):
    """
    Decode IGMP fields from a packet. Uses the scapy IGMP layer when available,
    otherwise falls back to parsing the first 8 bytes of the raw IP payload.
    """
    igmpTypeMap = {
        0x11: "Membership Query",
        0x12: "IGMPv1 Membership Report",
        0x16: "IGMPv2 Membership Report",
        0x17: "Leave Group",
        0x22: "IGMPv3 Membership Report",
    }

    igmpTypeNum = 0
    maxRespCode = 0
    checksumVal = 0
    groupAddr = "0.0.0.0"

    igmpClass = getattr(scapy, "IGMP", None)
    hasIgmpLayer = bool(igmpClass and p.haslayer(igmpClass)) or p.haslayer("IGMP")
    if hasIgmpLayer:
        igmpLayer = p[igmpClass] if igmpClass and p.haslayer(igmpClass) else p["IGMP"]
        try:
            igmpTypeNum = int(getattr(igmpLayer, "type", 0) or 0)
        except Exception:
            igmpTypeNum = 0
        try:
            maxRespCode = int(getattr(igmpLayer, "mrcode", 0) or 0)
        except Exception:
            maxRespCode = 0
        try:
            checksumVal = int(getattr(igmpLayer, "chksum", 0) or 0)
        except Exception:
            checksumVal = 0
        groupAddr = str(getattr(igmpLayer, "gaddr", "0.0.0.0") or "0.0.0.0")
    elif rawPayload and len(rawPayload) >= 8:
        igmpTypeNum = int(rawPayload[0])
        maxRespCode = int(rawPayload[1])
        checksumVal = int.from_bytes(rawPayload[2:4], byteorder="big", signed=False)
        try:
            groupAddr = socket.inet_ntoa(rawPayload[4:8])
        except Exception:
            groupAddr = "0.0.0.0"

    igmpType = igmpTypeMap.get(igmpTypeNum, f"Type {igmpTypeNum}")
    igmpVersion = "Unknown"
    if igmpTypeNum == 0x12:
        igmpVersion = "v1"
    elif igmpTypeNum in (0x16, 0x17, 0x11):
        igmpVersion = "v2"
    elif igmpTypeNum == 0x22:
        igmpVersion = "v3"

    return {
        "Type": igmpType,
        "igmp.type": igmpType,
        "network.igmp.type": igmpType,
        "Type Number": igmpTypeNum,
        "igmp.type_num": igmpTypeNum,
        "network.igmp.type_num": igmpTypeNum,
        "Version": igmpVersion,
        "igmp.version": igmpVersion,
        "network.igmp.version": igmpVersion,
        "Max Response Time (ds)": maxRespCode,
        "igmp.max_resp_time_ds": maxRespCode,
        "network.igmp.max_resp_time_ds": maxRespCode,
        "Group Address": groupAddr,
        "igmp.group_addr": groupAddr,
        "network.igmp.group_addr": groupAddr,
        "IGMP Checksum": hex(checksumVal),
        "igmp.chksum": hex(checksumVal),
        "network.igmp.chksum": hex(checksumVal),
        "Wire length": len(rawPayload) if rawPayload is not None else 0,
        "wire.len": len(rawPayload) if rawPayload is not None else 0,
        "network.igmp.wire.len": len(rawPayload) if rawPayload is not None else 0,
    }


def decodeSIP(rawPayload):
    """
    Decode SIP message fields from raw payload bytes.
    Parses the first line and common headers (From, To, Call-ID, Authorization).
    Returns a dict with both display-friendly keys and dot-notation keys for message
    type, method/status, and headers, or None if the payload is not a SIP message or
    decoding fails.
    """
    sipMethods = {
        "INVITE",
        "ACK",
        "BYE",
        "CANCEL",
        "REGISTER",
        "OPTIONS",
        "SUBSCRIBE",
        "NOTIFY",
        "REFER",
        "INFO",
        "UPDATE",
        "PRACK",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
        if not lines:
            return None
        firstLine = lines[0].strip()
        isSipResponse = firstLine.startswith("SIP/")
        isSipRequest = (
            firstLine.split(" ")[0] in sipMethods if " " in firstLine else False
        )
        if not isSipResponse and not isSipRequest:
            return None
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                key, _, val = line.partition(": ")
                headers[key.strip()] = val.strip()
        
        # Extract Authorization and Proxy-Authorization headers for credentials
        authorization = headers.get("Authorization", "")
        proxyAuthorization = headers.get("Proxy-Authorization", "")
        
        if isSipRequest:
            parts = firstLine.split(" ", 2)
            method = parts[0]
            requestUri = parts[1] if len(parts) > 1 else "Unknown"
            result = {
                "Type": "Request",
                "sip.type": "Request",
                "Method": method,
                "sip.method": method,
                "Request URI": requestUri,
                "sip.uri": requestUri,
                "From": headers.get("From", "Unknown"),
                "sip.from": headers.get("From", "Unknown"),
                "To": headers.get("To", "Unknown"),
                "sip.to": headers.get("To", "Unknown"),
                "Call-ID": headers.get("Call-ID", "Unknown"),
                "sip.call_id": headers.get("Call-ID", "Unknown"),
            }
            if authorization:
                result["Authorization"] = authorization
                result["sip.authorization"] = authorization
            if proxyAuthorization:
                result["Proxy-Authorization"] = proxyAuthorization
                result["sip.proxy_authorization"] = proxyAuthorization
            return result
        else:
            parts = firstLine.split(" ", 2)
            statusCode = parts[1] if len(parts) > 1 else "Unknown"
            statusMsg = parts[2] if len(parts) > 2 else "Unknown"
            result = {
                "Type": "Response",
                "sip.type": "Response",
                "Status Code": statusCode,
                "sip.status_code": statusCode,
                "Status Message": statusMsg,
                "sip.status_msg": statusMsg,
                "From": headers.get("From", "Unknown"),
                "sip.from": headers.get("From", "Unknown"),
                "To": headers.get("To", "Unknown"),
                "sip.to": headers.get("To", "Unknown"),
                "Call-ID": headers.get("Call-ID", "Unknown"),
                "sip.call_id": headers.get("Call-ID", "Unknown"),
            }
            if authorization:
                result["Authorization"] = authorization
                result["sip.authorization"] = authorization
            if proxyAuthorization:
                result["Proxy-Authorization"] = proxyAuthorization
                result["sip.proxy_authorization"] = proxyAuthorization
            return result
    except Exception:
        return None


def decodeHTTP(rawPayload):
    """
    Decode an HTTP request or response from raw payload bytes.
    Handles both HTTP/1.x requests and responses.  Returns a dict with
    both display-friendly keys (e.g., 'Method') and dot-notation keys
    (e.g., 'http.method') for use by the frontend, or None if the payload
    does not look like an HTTP message.

    For requests the following fields are extracted:
      Method, URL, HTTP Version, Host, User-Agent, Content-Type,
      Content-Length, Referer, Accept, Accept-Encoding, Connection.
    For responses the following fields are extracted:
      HTTP Version, Status Code, Status Message, Content-Type,
      Content-Length, Server, Content-Encoding, Transfer-Encoding,
      Connection, Location (for redirects).
    """
    try:
        text = rawPayload.decode(errors="ignore")
        # Normalise line endings so both CRLF and bare-LF messages are handled uniformly
        normalised = text.replace("\r\n", "\n")
        headerSection = normalised.split("\n\n")[0]
        lines = headerSection.split("\n")
        if not lines:
            return None
        firstLine = lines[0].strip()
        isHttpResponse = firstLine.startswith("HTTP/")
        isHttpRequest = (
            firstLine.split(" ")[0] in HTTP_METHODS if " " in firstLine else False
        )
        if not isHttpResponse and not isHttpRequest:
            return None

        # Parse headers into a dict (lowercase keys for case-insensitive lookup)
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                key, _, val = line.partition(": ")
                headers[key.strip().lower()] = val.strip()

        if isHttpRequest:
            parts = firstLine.split(" ", 2)
            method = parts[0]
            url = parts[1] if len(parts) > 1 else "Unknown"
            httpVersion = parts[2] if len(parts) > 2 else "Unknown"
            result = {
                "Type": "Request",
                "http.type": "Request",
                "Method": method,
                "http.method": method,
                "URL": url,
                "http.url": url,
                "HTTP Version": httpVersion,
                "http.version": httpVersion,
                "Host": headers.get("host", "Unknown"),
                "http.host": headers.get("host", "Unknown"),
                "User-Agent": headers.get("user-agent", "Unknown"),
                "http.user_agent": headers.get("user-agent", "Unknown"),
                "Content-Type": headers.get("content-type", "Unknown"),
                "http.content_type": headers.get("content-type", "Unknown"),
                "Content-Length": headers.get("content-length", "Unknown"),
                "http.content_length": headers.get("content-length", "Unknown"),
                "Referer": headers.get("referer", "Unknown"),
                "http.referer": headers.get("referer", "Unknown"),
                "Accept": headers.get("accept", "Unknown"),
                "http.accept": headers.get("accept", "Unknown"),
                "Accept-Encoding": headers.get("accept-encoding", "Unknown"),
                "http.accept_encoding": headers.get("accept-encoding", "Unknown"),
                "Connection": headers.get("connection", "Unknown"),
                "http.connection": headers.get("connection", "Unknown"),
            }
            # --- Credential extraction ----------------------------------------
            # Extract credential fields from query-string (GET, POST, any method)
            creds = {}
            if "?" in url:
                queryStr = url.split("?", 1)[1].split("#")[0]
                creds.update(_extractUrlCredentials(queryStr))
            # Also check Authorization header (Basic auth decoded by the frontend,
            # but include the raw value so the frontend decoder can handle it too)
            authHeader = headers.get("authorization", "")
            if authHeader:
                creds["authorization"] = authHeader
            # Extract Cookie header — session tokens and auth cookies are sensitive
            cookieHeader = headers.get("cookie", "")
            if cookieHeader:
                creds.update(_extractCookieCredentials(cookieHeader))
            # For request bodies (POST/PUT/PATCH) scan for credential fields
            contentType = headers.get("content-type", "")
            if method in ("POST", "PUT", "PATCH"):
                bodyStart = normalised.find("\n\n")
                if bodyStart != -1:
                    body = normalised[bodyStart + 2 :]
                    if body.strip():
                        if "urlencoded" in contentType.lower():
                            creds.update(_extractUrlCredentials(body))
                        else:
                            # JSON, multipart, plain-text, XML — regex scan
                            creds.update(_extractPostBodyCredentials(body, contentType))
            if creds:
                result["Credentials"] = creds
            return result
        else:
            parts = firstLine.split(" ", 2)
            httpVersion = parts[0]
            statusCode = parts[1] if len(parts) > 1 else "Unknown"
            statusMessage = parts[2] if len(parts) > 2 else "Unknown"
            responseResult = {
                "Type": "Response",
                "http.type": "Response",
                "HTTP Version": httpVersion,
                "http.version": httpVersion,
                "Status Code": statusCode,
                "http.status_code": statusCode,
                "Status Message": statusMessage,
                "http.status_msg": statusMessage,
                "Content-Type": headers.get("content-type", "Unknown"),
                "http.content_type": headers.get("content-type", "Unknown"),
                "Content-Length": headers.get("content-length", "Unknown"),
                "http.content_length": headers.get("content-length", "Unknown"),
                "Server": headers.get("server", "Unknown"),
                "http.server": headers.get("server", "Unknown"),
                "Content-Encoding": headers.get("content-encoding", "Unknown"),
                "http.content_encoding": headers.get("content-encoding", "Unknown"),
                "Transfer-Encoding": headers.get("transfer-encoding", "Unknown"),
                "http.transfer_encoding": headers.get("transfer-encoding", "Unknown"),
                "Connection": headers.get("connection", "Unknown"),
                "http.connection": headers.get("connection", "Unknown"),
                "Location": headers.get("location", "Unknown"),
                "http.location": headers.get("location", "Unknown"),
            }
            setCookieVal = headers.get("set-cookie", "")
            if setCookieVal:
                responseCreds = _extractSetCookieCredentials(setCookieVal)
                if responseCreds:
                    responseResult["Credentials"] = responseCreds
            return responseResult
    except Exception:
        return None


def decodeFTP(rawPayload):
    """
    Decode FTP commands and responses from raw payload bytes.
    Returns a dict with Type (Command/Response), command/status, and argument/message,
    or None if the payload is not recognisable as FTP traffic.
    """
    FTP_COMMANDS = {
        "USER",
        "PASS",
        "ACCT",
        "CWD",
        "CDUP",
        "SMNT",
        "QUIT",
        "REIN",
        "PORT",
        "PASV",
        "TYPE",
        "STRU",
        "MODE",
        "RETR",
        "STOR",
        "STOU",
        "APPE",
        "ALLO",
        "REST",
        "RNFR",
        "RNTO",
        "ABOR",
        "DELE",
        "RMD",
        "MKD",
        "PWD",
        "LIST",
        "NLST",
        "SITE",
        "SYST",
        "STAT",
        "HELP",
        "NOOP",
        "FEAT",
        "OPTS",
        "MLST",
        "MLSD",
        "SIZE",
        "MDTM",
        "EPRT",
        "EPSV",
        "AUTH",
        "PBSZ",
        "PROT",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        parts = firstLine.split(" ", 1)
        word = parts[0].upper()
        if word in FTP_COMMANDS:
            arg = parts[1].strip() if len(parts) > 1 else ""
            result = {
                "Type": "Command",
                "ftp.type": "Command",
                "Command": word,
                "ftp.command": word,
                "Argument": arg,
                "ftp.argument": arg,
            }
            if word == "USER" and arg:
                result["Credentials"] = {"username": arg}
            elif word == "PASS" and arg:
                result["Credentials"] = {"password": arg}
                # Keep plaintext out of display argument fields while preserving
                # extracted credential metadata for downstream processing.
                result["Argument"] = "***"
                result["ftp.argument"] = "***"
            return result
        if len(word) == 3 and word.isdigit():
            statusCode = word
            message = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Response",
                "ftp.type": "Response",
                "Status Code": statusCode,
                "ftp.status_code": statusCode,
                "Message": message,
                "ftp.message": message,
            }
        return None
    except Exception:
        return None


def decodeSMTP(rawPayload):
    """
    Decode SMTP commands and responses from raw payload bytes.
    Returns a dict with Type (Command/Response), command/status code, and arguments/message,
    or None if the payload is not recognisable as SMTP traffic.
    """
    SMTP_COMMANDS = {
        "EHLO",
        "HELO",
        "MAIL",
        "RCPT",
        "DATA",
        "RSET",
        "VRFY",
        "EXPN",
        "HELP",
        "NOOP",
        "QUIT",
        "AUTH",
        "STARTTLS",
        "BDAT",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        parts = firstLine.split(" ", 1)
        word = parts[0].upper()
        if word in SMTP_COMMANDS:
            arg = parts[1].strip() if len(parts) > 1 else ""
            result = {
                "Type": "Command",
                "smtp.type": "Command",
                "Command": word,
                "smtp.command": word,
                "Argument": arg,
                "smtp.argument": arg,
            }
            # --- Credential extraction for AUTH commands ----------------------
            # AUTH PLAIN <base64>  →  decode "\0username\0password"
            # AUTH LOGIN           →  subsequent lines are base64 user then pass
            if word == "AUTH":
                argParts = arg.split()
                mechanism = argParts[0].upper() if argParts else ""
                creds = {}
                if mechanism == "PLAIN" and len(argParts) > 1:
                    try:
                        decoded = base64.b64decode(argParts[1]).decode(errors="replace")
                        segments = decoded.split("\x00")
                        segments = [s for s in segments if s]
                        if len(segments) >= 2:
                            creds["username"] = segments[0]
                            creds["password"] = segments[1]
                        elif len(segments) == 1:
                            creds["username"] = segments[0]
                    except Exception:
                        pass
                elif mechanism == "LOGIN":
                    # Subsequent packets carry the base64-encoded username and
                    # password separately; capture what we have in this packet.
                    if len(argParts) > 1:
                        try:
                            creds["username"] = base64.b64decode(argParts[1]).decode(
                                errors="replace"
                            )
                        except Exception:
                            pass
                    # Scan remaining lines in the same payload for the password
                    for extraLine in lines[1:]:
                        extraLine = extraLine.strip()
                        if extraLine:
                            try:
                                creds["password"] = base64.b64decode(extraLine).decode(
                                    errors="replace"
                                )
                            except Exception:
                                pass
                            break
                # Mask the argument in the display field only when inline credential
                # data was present (so "AUTH LOGIN" without inline data stays readable)
                if len(argParts) > 1:
                    result["Argument"] = mechanism + " ***"
                    result["smtp.argument"] = mechanism + " ***"
                if creds:
                    result["Credentials"] = creds
            return result
        if len(word) == 3 and word.isdigit():
            statusCode = word
            message = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Response",
                "smtp.type": "Response",
                "Status Code": statusCode,
                "smtp.status_code": statusCode,
                "Message": message,
                "smtp.message": message,
            }
        return None
    except Exception:
        return None


def decodePOP3(rawPayload):
    """
    Decode POP3 commands and responses from raw payload bytes.
    Returns a dict with Type (Command/Response), command/status, and argument/message,
    or None if the payload is not recognisable as POP3 traffic.
    """
    POP3_COMMANDS = {
        "USER",
        "PASS",
        "APOP",
        "QUIT",
        "STAT",
        "LIST",
        "RETR",
        "DELE",
        "NOOP",
        "RSET",
        "TOP",
        "UIDL",
        "CAPA",
        "AUTH",
        "STLS",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        parts = firstLine.split(" ", 1)
        word = parts[0].upper()
        if word in POP3_COMMANDS:
            arg = parts[1].strip() if len(parts) > 1 else ""
            result = {
                "Type": "Command",
                "pop3.type": "Command",
                "Command": word,
                "pop3.command": word,
                "Argument": arg,
                "pop3.argument": arg,
            }
            # Capture credentials; mask the display field for PASS
            if word == "USER" and arg:
                result["Credentials"] = {"username": arg}
            elif word == "PASS" and arg:
                result["Credentials"] = {"password": arg}
                result["Argument"] = "***"
                result["pop3.argument"] = "***"
            return result
        if word in ("+OK", "-ERR"):
            message = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Response",
                "pop3.type": "Response",
                "Status": word,
                "pop3.status": word,
                "Message": message,
                "pop3.message": message,
            }
        return None
    except Exception:
        return None


def decodeIMAP(rawPayload):
    """
    Decode IMAP commands and server responses from raw payload bytes.
    Returns a dict with Type (Command/Response/Untagged), tag, command/status, and argument,
    or None if the payload is not recognisable as IMAP traffic.
    """
    IMAP_COMMANDS = {
        "CAPABILITY",
        "NOOP",
        "LOGOUT",
        "AUTHENTICATE",
        "LOGIN",
        "SELECT",
        "EXAMINE",
        "CREATE",
        "DELETE",
        "RENAME",
        "SUBSCRIBE",
        "UNSUBSCRIBE",
        "LIST",
        "LSUB",
        "STATUS",
        "APPEND",
        "CHECK",
        "CLOSE",
        "EXPUNGE",
        "SEARCH",
        "FETCH",
        "STORE",
        "COPY",
        "UID",
        "IDLE",
        "NAMESPACE",
        "STARTTLS",
        "ENABLE",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        if firstLine.startswith("* "):
            rest = firstLine[2:].strip()
            restParts = rest.split(" ", 1)
            status = restParts[0]
            info = restParts[1].strip() if len(restParts) > 1 else ""
            return {
                "Type": "Untagged",
                "imap.type": "Untagged",
                "Status": status,
                "imap.status": status,
                "Info": info,
                "imap.info": info,
            }
        parts = firstLine.split(" ", 2)
        if len(parts) >= 2:
            tag = parts[0]
            word = parts[1].upper()
            arg = parts[2].strip() if len(parts) > 2 else ""
            if word in IMAP_COMMANDS:
                result = {
                    "Type": "Command",
                    "imap.type": "Command",
                    "Tag": tag,
                    "imap.tag": tag,
                    "Command": word,
                    "imap.command": word,
                    "Argument": arg,
                    "imap.argument": arg,
                }
                # Extract LOGIN credentials and mask the password in the display field
                if word == "LOGIN" and arg:
                    argParts = arg.split(" ", 1)
                    username = argParts[0].strip('"')
                    if len(argParts) > 1:
                        password = argParts[1].strip('"')
                        result["Credentials"] = {
                            "username": username,
                            "password": password,
                        }
                        result["Argument"] = username + " ***"
                        result["imap.argument"] = username + " ***"
                    else:
                        result["Credentials"] = {"username": username}
                return result
            if word in ("OK", "NO", "BAD", "PREAUTH", "BYE"):
                return {
                    "Type": "Response",
                    "imap.type": "Response",
                    "Tag": tag,
                    "imap.tag": tag,
                    "Status": word,
                    "imap.status": word,
                    "Message": arg,
                    "imap.message": arg,
                }
        return None
    except Exception:
        return None


def decodeTelnet(rawPayload):
    """
    Decode Telnet IAC (Interpret As Command) negotiation bytes from raw payload.
    Returns a dict with negotiation options and any printable text found,
    or None if no Telnet IAC bytes are present.
    """
    IAC = 0xFF
    TELNET_COMMANDS = {
        0xF0: "SE",
        0xF1: "NOP",
        0xF2: "Data Mark",
        0xF3: "Break",
        0xF4: "Interrupt Process",
        0xF5: "Abort Output",
        0xF6: "Are You There",
        0xF7: "Erase Character",
        0xF8: "Erase Line",
        0xF9: "Go Ahead",
        0xFA: "SB",
        0xFB: "WILL",
        0xFC: "WONT",
        0xFD: "DO",
        0xFE: "DONT",
        0xFF: "IAC",
    }
    TELNET_OPTIONS = {
        0: "Binary",
        1: "Echo",
        2: "Reconnection",
        3: "Suppress GA",
        5: "Status",
        6: "Timing Mark",
        24: "Terminal Type",
        31: "Window Size",
        32: "Terminal Speed",
        33: "Remote Flow",
        34: "Linemode",
        36: "Environment",
        39: "New Environment",
    }
    try:
        if IAC not in rawPayload:
            return None
        negotiations = []
        i = 0
        while i < len(rawPayload):
            if rawPayload[i] == IAC and i + 1 < len(rawPayload):
                cmd = rawPayload[i + 1]
                cmdName = TELNET_COMMANDS.get(cmd, f"0x{cmd:02X}")
                if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(rawPayload):
                    optByte = rawPayload[i + 2]
                    optName = TELNET_OPTIONS.get(optByte, f"Option-{optByte}")
                    negotiations.append(f"{cmdName} {optName}")
                    i += 3
                else:
                    negotiations.append(cmdName)
                    i += 2
            else:
                i += 1
        printableText = "".join(chr(b) for b in rawPayload if 32 <= b <= 126).strip()
        result = {
            "Negotiations": negotiations,
            "telnet.negotiations": negotiations,
            "Printable Text": printableText[:200] if printableText else "",
            "telnet.text": printableText[:200] if printableText else "",
        }
        # Scan negotiation packets' printable text for any embedded credentials
        creds = _extractTelnetCredentialText(printableText)
        if creds:
            result["Credentials"] = creds
        return result
    except Exception:
        return None


# Compiled patterns for Telnet credential extraction (reused across all calls)
_TELNET_USER_RE = re.compile(r"(?:login|user(?:name)?)\s*:\s*(\S+)", re.IGNORECASE)
_TELNET_PASS_RE = re.compile(r"(?:pass(?:w(?:or)?d?)?|pw)\s*:\s*(\S+)", re.IGNORECASE)


def _extractTelnetCredentialText(text):
    """
    Scan a printable Telnet text snippet for login/password prompt-response patterns
    (e.g. ``login: alice`` or ``Password: s3cr3t``).
    Returns a dict of found credential fields, or an empty dict.
    """
    if not text:
        return {}
    creds = {}
    userMatch = _TELNET_USER_RE.search(text)
    passMatch = _TELNET_PASS_RE.search(text)
    if userMatch:
        creds["username"] = userMatch.group(1)
    if passMatch:
        creds["password"] = passMatch.group(1)
    return creds


def extractTelnetCredentials(rawPayload):
    """
    Detect cleartext Telnet login credentials from raw TCP port-23 payloads that
    do NOT necessarily contain IAC negotiation bytes.  This handles the data-transfer
    phase of a Telnet session where usernames and passwords are transmitted as plain
    ASCII lines (line-at-a-time mode) or labelled prompt/response pairs.

    Returns a dict with any found credential fields, or an empty dict.
    """
    try:
        printableText = "".join(chr(b) for b in rawPayload if 32 <= b <= 126).strip()
        if not printableText:
            return {}
        # Check for labelled prompt-response patterns (server echo or combined packet)
        creds = _extractTelnetCredentialText(printableText)
        return creds
    except Exception:
        return {}


def decodeIRC(rawPayload):
    """
    Decode IRC protocol messages from raw payload bytes.
    Parses prefix, command, and parameters per RFC 1459.
    Returns a dict with the IRC command and parameters, or None if not recognisable.
    """
    IRC_COMMANDS = {
        "NICK",
        "USER",
        "JOIN",
        "PART",
        "PRIVMSG",
        "NOTICE",
        "QUIT",
        "PING",
        "PONG",
        "MODE",
        "TOPIC",
        "NAMES",
        "LIST",
        "INVITE",
        "KICK",
        "WHOIS",
        "WHO",
        "WHOWAS",
        "MOTD",
        "LUSERS",
        "VERSION",
        "STATS",
        "LINKS",
        "TIME",
        "CONNECT",
        "TRACE",
        "ADMIN",
        "INFO",
        "SERVLIST",
        "SQUERY",
        "KILL",
        "PASS",
        "OPER",
        "REHASH",
        "DIE",
        "RESTART",
        "AWAY",
        "USERHOST",
        "ISON",
        "CAP",
        "AUTHENTICATE",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        messages = []
        for line in text.replace("\r\n", "\n").split("\n"):
            line = line.strip()
            if not line:
                continue
            prefix = ""
            if line.startswith(":"):
                pparts = line.split(" ", 1)
                prefix = pparts[0][1:]
                line = pparts[1] if len(pparts) > 1 else ""
            parts = line.split(" ", 1)
            command = parts[0].upper()
            params = parts[1] if len(parts) > 1 else ""
            if command in IRC_COMMANDS or (len(command) == 3 and command.isdigit()):
                messages.append(
                    {"Prefix": prefix, "Command": command, "Parameters": params}
                )
        if not messages:
            return None
        first = messages[0]
        return {
            "Command": first["Command"],
            "irc.command": first["Command"],
            "Prefix": first["Prefix"],
            "irc.prefix": first["Prefix"],
            "Parameters": first["Parameters"],
            "irc.params": first["Parameters"],
            "Message Count": len(messages),
            "irc.msg_count": len(messages),
        }
    except Exception:
        return None


def decodeMTP(rawPayload):
    """
    Decode MTP/MMS (Microsoft Media Services over TCP, port 1755) packets.
    Checks for the MMS command identifier prefix (0x00000001 little-endian).
    Returns basic MTP/MMS info dict or None if not recognisable.
    """
    import struct

    MMS_COMMANDS = {
        0x00030001: "CONNECT_REQUEST",
        0x00030002: "CONNECT_RESPONSE",
        0x00030003: "TRANSPORT_INFO_REQUEST",
        0x00030004: "TRANSPORT_INFO_RESPONSE",
        0x00030005: "MEDIA_DETAILS_REQUEST",
        0x00030006: "PLAY_REQUEST",
        0x00030007: "STOP",
        0x00030009: "STREAM_STOPPED",
        0x0004001B: "HEADER",
        0x0004001A: "DATA",
    }
    try:
        if len(rawPayload) < 12:
            return None
        prefix = struct.unpack_from("<I", rawPayload, 0)[0]
        if prefix != 0x00000001:
            return None
        length = struct.unpack_from("<I", rawPayload, 4)[0]
        cmdId = struct.unpack_from("<I", rawPayload, 8)[0]
        cmdName = MMS_COMMANDS.get(cmdId, f"0x{cmdId:08X}")
        return {
            "Protocol": "MMS/MTP",
            "mtp.protocol": "MMS/MTP",
            "Command ID": f"0x{cmdId:08X}",
            "mtp.cmd_id": f"0x{cmdId:08X}",
            "Command": cmdName,
            "mtp.command": cmdName,
            "Length": length,
            "mtp.length": length,
        }
    except Exception:
        return None


def decodeLDAP(rawPayload):
    """
    Decode basic LDAP message fields from raw payload bytes using ASN.1 BER structure.
    Extracts message ID and operation type from the outer SEQUENCE.
    Returns a dict with message ID and operation, or None if the payload does not look like LDAP.
    """
    LDAP_OPERATIONS = {
        0x60: "BindRequest",
        0x61: "BindResponse",
        0x62: "UnbindRequest",
        0x63: "SearchRequest",
        0x64: "SearchResEntry",
        0x65: "SearchResDone",
        0x66: "SearchResRef",
        0x67: "ModifyRequest",
        0x68: "ModifyResponse",
        0x69: "AddRequest",
        0x6A: "AddResponse",
        0x6B: "DelRequest",
        0x6C: "DelResponse",
        0x6D: "ModDNRequest",
        0x6E: "ModDNResponse",
        0x6F: "CompareRequest",
        0x70: "CompareResponse",
        0x77: "ExtendedRequest",
        0x78: "ExtendedResponse",
        0x79: "IntermediateResponse",
    }
    try:
        if len(rawPayload) < 4:
            return None
        if rawPayload[0] != 0x30:
            return None
        idx = 1
        if rawPayload[idx] & 0x80:
            numBytes = rawPayload[idx] & 0x7F
            idx += 1 + numBytes
        else:
            idx += 1
        if idx >= len(rawPayload) or rawPayload[idx] != 0x02:
            return None
        idxLen = rawPayload[idx + 1]
        msgId = int.from_bytes(rawPayload[idx + 2 : idx + 2 + idxLen], "big")
        idx += 2 + idxLen
        if idx >= len(rawPayload):
            return None
        opTag = rawPayload[idx]
        opName = LDAP_OPERATIONS.get(opTag, f"0x{opTag:02X}")
        return {
            "Message ID": msgId,
            "ldap.msg_id": msgId,
            "Operation": opName,
            "ldap.operation": opName,
        }
    except Exception:
        return None


def decodeMySQL(rawPayload):
    """
    Decode MySQL protocol packets from raw payload bytes.
    Handles server greeting (handshake), OK, ERR, and client command packets.
    Returns a dict with packet type and relevant fields, or None if not recognisable.
    """
    import struct

    MYSQL_COMMANDS = {
        0x00: "Sleep",
        0x01: "Quit",
        0x02: "Init DB",
        0x03: "Query",
        0x04: "Field List",
        0x05: "Create DB",
        0x06: "Drop DB",
        0x07: "Refresh",
        0x08: "Shutdown",
        0x09: "Statistics",
        0x0A: "Process Info",
        0x0B: "Connect",
        0x0C: "Process Kill",
        0x0D: "Debug",
        0x0E: "Ping",
        0x0F: "Time",
        0x10: "Delayed Insert",
        0x11: "Change User",
        0x16: "Stmt Prepare",
        0x17: "Stmt Execute",
        0x19: "Stmt Close",
        0x1A: "Stmt Reset",
        0x1C: "Set Option",
        0x1D: "Stmt Fetch",
    }
    try:
        if len(rawPayload) < 5:
            return None
        pktLen = struct.unpack_from("<I", rawPayload[:4])[0] & 0xFFFFFF
        seqNum = rawPayload[3]
        payload = rawPayload[4:]
        if not payload:
            return None
        firstByte = payload[0]
        if firstByte == 0x0A:
            versionEnd = payload.find(b"\x00", 1)
            version = (
                payload[1:versionEnd].decode(errors="ignore")
                if versionEnd > 1
                else "Unknown"
            )
            return {
                "Type": "Server Greeting",
                "mysql.type": "Server Greeting",
                "Protocol Version": 10,
                "mysql.proto_version": 10,
                "Server Version": version,
                "mysql.server_version": version,
                "Sequence": seqNum,
                "mysql.seq": seqNum,
            }
        if firstByte == 0x00:
            return {
                "Type": "OK",
                "mysql.type": "OK",
                "Sequence": seqNum,
                "mysql.seq": seqNum,
            }
        if firstByte == 0xFF:
            errCode = (
                struct.unpack_from("<H", payload, 1)[0] if len(payload) >= 3 else 0
            )
            errMsg = payload[9:].decode(errors="ignore") if len(payload) > 9 else ""
            return {
                "Type": "Error",
                "mysql.type": "Error",
                "Error Code": errCode,
                "mysql.error_code": errCode,
                "Error Message": errMsg[:100],
                "mysql.error_msg": errMsg[:100],
                "Sequence": seqNum,
                "mysql.seq": seqNum,
            }
        if seqNum == 0 and firstByte in MYSQL_COMMANDS:
            cmdName = MYSQL_COMMANDS[firstByte]
            query = (
                payload[1:].decode(errors="ignore")[:200] if len(payload) > 1 else ""
            )
            return {
                "Type": "Command",
                "mysql.type": "Command",
                "Command": cmdName,
                "mysql.command": cmdName,
                "Query": query,
                "mysql.query": query,
                "Sequence": seqNum,
                "mysql.seq": seqNum,
            }
        return None
    except Exception:
        return None


def decodePostgreSQL(rawPayload):
    """
    Decode PostgreSQL frontend/backend protocol messages from raw payload bytes.
    Returns a dict with message type and relevant fields, or None if not recognisable.
    """
    import struct

    PG_BACKEND_TYPES = {
        b"R": "Authentication",
        b"K": "BackendKeyData",
        b"2": "BindComplete",
        b"3": "CloseComplete",
        b"C": "CommandComplete",
        b"d": "CopyData",
        b"c": "CopyDone",
        b"f": "CopyFail",
        b"G": "CopyInResponse",
        b"H": "CopyOutResponse",
        b"D": "DataRow",
        b"I": "EmptyQueryResponse",
        b"E": "ErrorResponse",
        b"V": "FunctionCallResponse",
        b"n": "NoData",
        b"N": "NoticeResponse",
        b"A": "NotificationResponse",
        b"t": "ParameterDescription",
        b"S": "ParameterStatus",
        b"1": "ParseComplete",
        b"s": "PortalSuspended",
        b"Z": "ReadyForQuery",
        b"T": "RowDescription",
    }
    PG_FRONTEND_TYPES = {
        b"B": "Bind",
        b"C": "Close",
        b"d": "CopyData",
        b"c": "CopyDone",
        b"f": "CopyFail",
        b"D": "Describe",
        b"E": "Execute",
        b"H": "Flush",
        b"F": "FunctionCall",
        b"P": "Parse",
        b"p": "Password",
        b"Q": "Query",
        b"S": "Sync",
        b"X": "Terminate",
    }
    try:
        if len(rawPayload) < 5:
            return None
        firstInt = struct.unpack_from(">I", rawPayload, 0)[0]
        if firstInt == len(rawPayload) and len(rawPayload) >= 8:
            protoMajor = struct.unpack_from(">H", rawPayload, 4)[0]
            protoMinor = struct.unpack_from(">H", rawPayload, 6)[0]
            return {
                "Type": "StartupMessage",
                "pg.type": "StartupMessage",
                "Protocol Version": f"{protoMajor}.{protoMinor}",
                "pg.proto_version": f"{protoMajor}.{protoMinor}",
            }
        msgType = rawPayload[0:1]
        if msgType in PG_BACKEND_TYPES:
            typeName = PG_BACKEND_TYPES[msgType]
            msgLen = struct.unpack_from(">I", rawPayload, 1)[0]
            return {
                "Type": typeName,
                "pg.type": typeName,
                "Direction": "Backend",
                "pg.direction": "Backend",
                "Message Length": msgLen,
                "pg.msg_length": msgLen,
            }
        if msgType in PG_FRONTEND_TYPES:
            typeName = PG_FRONTEND_TYPES[msgType]
            msgLen = struct.unpack_from(">I", rawPayload, 1)[0]
            body = (
                rawPayload[5 : 5 + min(msgLen - 4, 200)].decode(errors="ignore")
                if msgLen > 4
                else ""
            )
            return {
                "Type": typeName,
                "pg.type": typeName,
                "Direction": "Frontend",
                "pg.direction": "Frontend",
                "Message Length": msgLen,
                "pg.msg_length": msgLen,
                "Body": body,
                "pg.body": body,
            }
        return None
    except Exception:
        return None


def decodeXMPP(rawPayload):
    """
    Decode XMPP (Extensible Messaging and Presence Protocol) XML stream data.
    Parses stream open tags, message, presence, and IQ stanzas.
    Returns a dict with the stanza type and attributes, or None if not XMPP.
    """
    import re

    try:
        text = rawPayload.decode(errors="ignore").strip()
        if not text:
            return None
        isXmpp = (
            text.startswith("<?xml")
            or "<stream:stream" in text
            or text.startswith("<message")
            or text.startswith("<presence")
            or text.startswith("<iq ")
            or text.startswith("<iq>")
            or "<message " in text
            or "<presence" in text
        )
        if not isXmpp:
            return None
        stanzaType = "Unknown"
        if "<stream:stream" in text:
            stanzaType = "StreamOpen"
        elif "</stream:stream>" in text:
            stanzaType = "StreamClose"
        elif "<message" in text:
            stanzaType = "Message"
        elif "<presence" in text:
            stanzaType = "Presence"
        elif "<iq " in text or "<iq>" in text:
            stanzaType = "IQ"
        toMatch = re.search(r'\bto=["\']([^"\']+)["\']', text)
        fromMatch = re.search(r'\bfrom=["\']([^"\']+)["\']', text)
        toAttr = toMatch.group(1) if toMatch else "Unknown"
        fromAttr = fromMatch.group(1) if fromMatch else "Unknown"
        return {
            "Stanza Type": stanzaType,
            "xmpp.stanza": stanzaType,
            "To": toAttr,
            "xmpp.to": toAttr,
            "From": fromAttr,
            "xmpp.from": fromAttr,
        }
    except Exception:
        return None


def decodeSMB(rawPayload):
    """
    Decode SMB (Server Message Block) protocol frames from raw payload bytes.
    Supports both SMBv1 (\\xFFSMB signature) and SMBv2/3 (\\xFESMB signature).
    Returns a dict with SMB version, command, status, and flags, or None if not SMB.
    """
    import struct

    SMB1_COMMANDS = {
        0x00: "CREATE_DIRECTORY",
        0x01: "DELETE_DIRECTORY",
        0x02: "OPEN",
        0x03: "CREATE",
        0x04: "CLOSE",
        0x05: "FLUSH",
        0x06: "DELETE",
        0x07: "RENAME",
        0x08: "QUERY_INFORMATION",
        0x09: "SET_INFORMATION",
        0x0A: "READ",
        0x0B: "WRITE",
        0x24: "LOCKING_ANDX",
        0x25: "TRANSACTION",
        0x2D: "OPEN_ANDX",
        0x2E: "READ_ANDX",
        0x2F: "WRITE_ANDX",
        0x32: "TRANSACTION2",
        0x70: "TREE_CONNECT",
        0x71: "TREE_DISCONNECT",
        0x72: "NEGOTIATE",
        0x73: "SESSION_SETUP_ANDX",
        0x74: "LOGOFF_ANDX",
        0x75: "TREE_CONNECT_ANDX",
        0xA0: "NT_TRANSACT",
        0xA2: "NT_CREATE_ANDX",
        0xA4: "NT_CANCEL",
        0xFE: "INVALID",
        0xFF: "NO_ANDX",
    }
    SMB2_COMMANDS = {
        0x0000: "NEGOTIATE",
        0x0001: "SESSION_SETUP",
        0x0002: "LOGOFF",
        0x0003: "TREE_CONNECT",
        0x0004: "TREE_DISCONNECT",
        0x0005: "CREATE",
        0x0006: "CLOSE",
        0x0007: "FLUSH",
        0x0008: "READ",
        0x0009: "WRITE",
        0x000A: "LOCK",
        0x000B: "IOCTL",
        0x000C: "CANCEL",
        0x000D: "ECHO",
        0x000E: "QUERY_DIRECTORY",
        0x000F: "CHANGE_NOTIFY",
        0x0010: "QUERY_INFO",
        0x0011: "SET_INFO",
        0x0012: "OPLOCK_BREAK",
    }
    try:
        if len(rawPayload) < 8:
            return None
        if rawPayload[:4] == b"\xff\x53\x4d\x42":
            cmd = rawPayload[4]
            status = struct.unpack_from("<I", rawPayload, 5)[0]
            flags = rawPayload[9]
            cmdName = SMB1_COMMANDS.get(cmd, f"0x{cmd:02X}")
            isResponse = bool(flags & 0x80)
            return {
                "Version": "SMBv1",
                "smb.version": "SMBv1",
                "Command": cmdName,
                "smb.command": cmdName,
                "Status": f"0x{status:08X}",
                "smb.status": f"0x{status:08X}",
                "Is Response": isResponse,
                "smb.is_response": isResponse,
            }
        if rawPayload[:4] == b"\xfe\x53\x4d\x42":
            cmd = struct.unpack_from("<H", rawPayload, 12)[0]
            flags = struct.unpack_from("<I", rawPayload, 16)[0]
            status = struct.unpack_from("<I", rawPayload, 8)[0]
            cmdName = SMB2_COMMANDS.get(cmd, f"0x{cmd:04X}")
            isResponse = bool(flags & 0x00000001)
            return {
                "Version": "SMBv2/v3",
                "smb.version": "SMBv2/v3",
                "Command": cmdName,
                "smb.command": cmdName,
                "Status": f"0x{status:08X}",
                "smb.status": f"0x{status:08X}",
                "Is Response": isResponse,
                "smb.is_response": isResponse,
            }
        return None
    except Exception:
        return None


def decodeMQTT(rawPayload):
    """
    Decode MQTT protocol messages from raw payload bytes.
    Extracts message type, QoS level, and topic from PUBLISH messages.
    Returns a dict with MQTT fields, or None if the payload does not look like MQTT.
    """
    import struct

    MQTT_TYPES = {
        1: "CONNECT",
        2: "CONNACK",
        3: "PUBLISH",
        4: "PUBACK",
        5: "PUBREC",
        6: "PUBREL",
        7: "PUBCOMP",
        8: "SUBSCRIBE",
        9: "SUBACK",
        10: "UNSUBSCRIBE",
        11: "UNSUBACK",
        12: "PINGREQ",
        13: "PINGRESP",
        14: "DISCONNECT",
    }
    try:
        if len(rawPayload) < 2:
            return None
        firstByte = rawPayload[0]
        msgType = (firstByte >> 4) & 0x0F
        if msgType not in MQTT_TYPES:
            return None
        flags = firstByte & 0x0F
        qos = (flags >> 1) & 0x03
        dup = bool(flags & 0x08)
        retain = bool(flags & 0x01)
        typeName = MQTT_TYPES[msgType]
        result = {
            "Message Type": typeName,
            "mqtt.msg_type": typeName,
            "QoS": qos,
            "mqtt.qos": qos,
            "DUP Flag": dup,
            "mqtt.dup": dup,
            "Retain Flag": retain,
            "mqtt.retain": retain,
        }
        if msgType == 3 and len(rawPayload) > 4:
            idx = 1
            remainLen = 0
            shift = 0
            while idx < len(rawPayload):
                b = rawPayload[idx]
                idx += 1
                remainLen |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            if idx + 2 <= len(rawPayload):
                topicLen = struct.unpack_from(">H", rawPayload, idx)[0]
                topic = rawPayload[idx + 2 : idx + 2 + topicLen].decode(errors="ignore")
                result["Topic"] = topic
                result["mqtt.topic"] = topic
        return result
    except Exception:
        return None


def decodeRTSP(rawPayload):
    """
    Decode RTSP (Real Time Streaming Protocol) requests and responses from raw payload bytes.
    Similar in structure to HTTP/1.1 text-based protocol.
    Returns a dict with RTSP method/status and headers, or None if not recognisable as RTSP.
    """
    RTSP_METHODS = {
        "OPTIONS",
        "DESCRIBE",
        "ANNOUNCE",
        "SETUP",
        "PLAY",
        "PAUSE",
        "RECORD",
        "TEARDOWN",
        "GET_PARAMETER",
        "SET_PARAMETER",
        "REDIRECT",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        normalised = text.replace("\r\n", "\n")
        headerSection = normalised.split("\n\n")[0]
        lines = headerSection.split("\n")
        if not lines:
            return None
        firstLine = lines[0].strip()
        isRtspResponse = firstLine.startswith("RTSP/")
        isRtspRequest = (
            firstLine.split(" ")[0].upper() in RTSP_METHODS
            if " " in firstLine
            else False
        )
        if not isRtspResponse and not isRtspRequest:
            return None
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                key, _, val = line.partition(": ")
                headers[key.strip().lower()] = val.strip()
        if isRtspRequest:
            parts = firstLine.split(" ", 2)
            method = parts[0].upper()
            url = parts[1] if len(parts) > 1 else "Unknown"
            rtspVersion = parts[2] if len(parts) > 2 else "Unknown"
            return {
                "Type": "Request",
                "rtsp.type": "Request",
                "Method": method,
                "rtsp.method": method,
                "URL": url,
                "rtsp.url": url,
                "RTSP Version": rtspVersion,
                "rtsp.version": rtspVersion,
                "CSeq": headers.get("cseq", "Unknown"),
                "rtsp.cseq": headers.get("cseq", "Unknown"),
                "Session": headers.get("session", "Unknown"),
                "rtsp.session": headers.get("session", "Unknown"),
                "Transport": headers.get("transport", "Unknown"),
                "rtsp.transport": headers.get("transport", "Unknown"),
            }
        else:
            parts = firstLine.split(" ", 2)
            rtspVersion = parts[0]
            statusCode = parts[1] if len(parts) > 1 else "Unknown"
            statusMsg = parts[2] if len(parts) > 2 else "Unknown"
            return {
                "Type": "Response",
                "rtsp.type": "Response",
                "RTSP Version": rtspVersion,
                "rtsp.version": rtspVersion,
                "Status Code": statusCode,
                "rtsp.status_code": statusCode,
                "Status Message": statusMsg,
                "rtsp.status_msg": statusMsg,
                "CSeq": headers.get("cseq", "Unknown"),
                "rtsp.cseq": headers.get("cseq", "Unknown"),
                "Session": headers.get("session", "Unknown"),
                "rtsp.session": headers.get("session", "Unknown"),
                "Content-Type": headers.get("content-type", "Unknown"),
                "rtsp.content_type": headers.get("content-type", "Unknown"),
                "Content-Length": headers.get("content-length", "Unknown"),
                "rtsp.content_length": headers.get("content-length", "Unknown"),
            }
    except Exception:
        return None


def decodeTFTP(rawPayload):
    """
    Decode TFTP (Trivial File Transfer Protocol) packets from raw payload bytes.
    TFTP runs over UDP. Extracts opcode and relevant fields per RFC 1350.
    Returns a dict with opcode type and arguments, or None if not recognisable as TFTP.
    """
    import struct

    TFTP_OPCODES = {1: "RRQ", 2: "WRQ", 3: "DATA", 4: "ACK", 5: "ERROR"}
    TFTP_ERRORS = {
        0: "Not defined",
        1: "File not found",
        2: "Access violation",
        3: "Disk full",
        4: "Illegal operation",
        5: "Unknown TID",
        6: "File already exists",
        7: "No such user",
    }
    try:
        if len(rawPayload) < 4:
            return None
        opcode = struct.unpack_from(">H", rawPayload, 0)[0]
        if opcode not in TFTP_OPCODES:
            return None
        opName = TFTP_OPCODES[opcode]
        if opcode in (1, 2):
            rest = rawPayload[2:]
            nullIdx = rest.find(b"\x00")
            filename = (
                rest[:nullIdx].decode(errors="ignore")
                if nullIdx >= 0
                else rest.decode(errors="ignore")
            )
            modeStart = nullIdx + 1 if nullIdx >= 0 else len(rest)
            modeEnd = rest.find(b"\x00", modeStart)
            mode = (
                rest[modeStart:modeEnd].decode(errors="ignore")
                if modeEnd > modeStart
                else "Unknown"
            )
            return {
                "Opcode": opName,
                "tftp.opcode": opName,
                "Filename": filename,
                "tftp.filename": filename,
                "Mode": mode,
                "tftp.mode": mode,
            }
        if opcode == 3:
            block = struct.unpack_from(">H", rawPayload, 2)[0]
            return {
                "Opcode": opName,
                "tftp.opcode": opName,
                "Block Number": block,
                "tftp.block": block,
                "Data Length": len(rawPayload) - 4,
                "tftp.data_len": len(rawPayload) - 4,
            }
        if opcode == 4:
            block = struct.unpack_from(">H", rawPayload, 2)[0]
            return {
                "Opcode": opName,
                "tftp.opcode": opName,
                "Block Number": block,
                "tftp.block": block,
            }
        if opcode == 5:
            errCode = struct.unpack_from(">H", rawPayload, 2)[0]
            errMsg = rawPayload[4:].rstrip(b"\x00").decode(errors="ignore")
            errDesc = TFTP_ERRORS.get(errCode, f"Error {errCode}")
            return {
                "Opcode": opName,
                "tftp.opcode": opName,
                "Error Code": errCode,
                "tftp.error_code": errCode,
                "Error Description": errDesc,
                "tftp.error_desc": errDesc,
                "Error Message": errMsg,
                "tftp.error_msg": errMsg,
            }
        return None
    except Exception:
        return None


def decodeBGP(rawPayload):
    """
    Decode BGP (Border Gateway Protocol) messages from raw payload bytes.
    BGP runs over TCP port 179. Checks for the 16-byte all-0xFF marker.
    Returns a dict with BGP message type and length, or None if not BGP.
    """
    import struct

    BGP_TYPES = {
        1: "OPEN",
        2: "UPDATE",
        3: "NOTIFICATION",
        4: "KEEPALIVE",
        5: "ROUTE-REFRESH",
    }
    BGP_ERRORS = {
        1: "Message Header Error",
        2: "OPEN Message Error",
        3: "UPDATE Message Error",
        4: "Hold Timer Expired",
        5: "Finite State Machine Error",
        6: "Cease",
    }
    try:
        if len(rawPayload) < 19:
            return None
        if rawPayload[:16] != b"\xff" * 16:
            return None
        msgLen = struct.unpack_from(">H", rawPayload, 16)[0]
        msgType = rawPayload[18]
        typeName = BGP_TYPES.get(msgType, f"Unknown({msgType})")
        result = {
            "Message Type": typeName,
            "bgp.type": typeName,
            "Message Length": msgLen,
            "bgp.length": msgLen,
        }
        if msgType == 1 and len(rawPayload) >= 29:
            version = rawPayload[19]
            asn = struct.unpack_from(">H", rawPayload, 20)[0]
            holdTime = struct.unpack_from(">H", rawPayload, 22)[0]
            routerId = ".".join(str(b) for b in rawPayload[24:28])
            result["BGP Version"] = version
            result["bgp.version"] = version
            result["ASN"] = asn
            result["bgp.asn"] = asn
            result["Hold Time"] = holdTime
            result["bgp.hold_time"] = holdTime
            result["Router ID"] = routerId
            result["bgp.router_id"] = routerId
        if msgType == 3 and len(rawPayload) >= 21:
            errCode = rawPayload[19]
            errSubcode = rawPayload[20]
            errName = BGP_ERRORS.get(errCode, f"Error {errCode}")
            result["Error Code"] = errCode
            result["bgp.error_code"] = errCode
            result["Error Name"] = errName
            result["bgp.error_name"] = errName
            result["Error Subcode"] = errSubcode
            result["bgp.error_subcode"] = errSubcode
        return result
    except Exception:
        return None


def decodeHTTP2(rawPayload):
    """
    Decode HTTP/2 frames from raw payload bytes.
    Detects the HTTP/2 connection preface and binary frame headers (RFC 7540).
    Returns a dict with HTTP/2 frame info, or None if not HTTP/2.
    """
    import struct

    HTTP2_FRAME_TYPES = {
        0x0: "DATA",
        0x1: "HEADERS",
        0x2: "PRIORITY",
        0x3: "RST_STREAM",
        0x4: "SETTINGS",
        0x5: "PUSH_PROMISE",
        0x6: "PING",
        0x7: "GOAWAY",
        0x8: "WINDOW_UPDATE",
        0x9: "CONTINUATION",
    }
    try:
        if len(rawPayload) < 9:
            return None
        hasPreface = rawPayload.startswith(HTTP2_PREFACE_BYTES)
        offset = len(HTTP2_PREFACE_BYTES) if hasPreface else 0
        if offset + 9 > len(rawPayload):
            if hasPreface:
                return {
                    "Connection Preface": True,
                    "http2.preface": True,
                    "Frame Type": "N/A",
                    "http2.frame_type": "N/A",
                }
            return None
        frameLen = struct.unpack_from(">I", b"\x00" + rawPayload[offset : offset + 3])[
            0
        ]
        frameType = rawPayload[offset + 3]
        frameFlags = rawPayload[offset + 4]
        streamId = struct.unpack_from(">I", rawPayload, offset + 5)[0] & 0x7FFFFFFF
        # Tight sanity checks to avoid treating random encrypted bytes as HTTP/2.
        if frameLen > 16384:
            return None
        # SETTINGS, PING and GOAWAY are connection-level frames and must use stream 0.
        if frameType in (0x4, 0x6, 0x7) and streamId != 0:
            return None
        # DATA/HEADERS/PUSH_PROMISE/CONTINUATION are stream-level and cannot use 0.
        if frameType in (0x0, 0x1, 0x5, 0x9) and streamId == 0:
            return None
        typeName = HTTP2_FRAME_TYPES.get(frameType, f"0x{frameType:02X}")
        return {
            "Connection Preface": hasPreface,
            "http2.preface": hasPreface,
            "Frame Type": typeName,
            "http2.frame_type": typeName,
            "Frame Length": frameLen,
            "http2.frame_length": frameLen,
            "Frame Flags": f"0x{frameFlags:02X}",
            "http2.frame_flags": f"0x{frameFlags:02X}",
            "Stream ID": streamId,
            "http2.stream_id": streamId,
        }
    except Exception:
        return None


def decodeSSH(rawPayload, srcPort=None, dstPort=None):
    """
    Decode SSH protocol metadata from raw TCP payload bytes.
    Extracts cleartext identification banners (RFC 4253 section 4.2) and,
    when present, basic packet framing metadata from binary SSH transport
    packets without attempting decryption.
    Returns a dict with SSH fields, or None if not recognisable as SSH traffic.
    """
    SSH_MESSAGE_TYPES = {
        1: "DISCONNECT",
        2: "IGNORE",
        3: "UNIMPLEMENTED",
        4: "DEBUG",
        5: "SERVICE_REQUEST",
        6: "SERVICE_ACCEPT",
        20: "KEXINIT",
        21: "NEWKEYS",
        30: "KEXDH_INIT",
        31: "KEXDH_REPLY",
        50: "USERAUTH_REQUEST",
        51: "USERAUTH_FAILURE",
        52: "USERAUTH_SUCCESS",
        53: "USERAUTH_BANNER",
        80: "GLOBAL_REQUEST",
        81: "REQUEST_SUCCESS",
        82: "REQUEST_FAILURE",
        90: "CHANNEL_OPEN",
        91: "CHANNEL_OPEN_CONFIRMATION",
        92: "CHANNEL_OPEN_FAILURE",
        93: "CHANNEL_WINDOW_ADJUST",
        94: "CHANNEL_DATA",
        95: "CHANNEL_EXTENDED_DATA",
        96: "CHANNEL_EOF",
        97: "CHANNEL_CLOSE",
        98: "CHANNEL_REQUEST",
        99: "CHANNEL_SUCCESS",
        100: "CHANNEL_FAILURE",
    }

    try:
        if not rawPayload or len(rawPayload) == 0:
            return None

        payloadPrefix = rawPayload[:4]
        isBanner = rawPayload.startswith(b"SSH-")

        # SSH cleartext version exchange line, e.g.:
        # SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3\r\n
        if isBanner:
            firstLineRaw = rawPayload.split(b"\n", 1)[0].rstrip(b"\r")
            banner = firstLineRaw.decode(errors="ignore").strip()
            m = re.match(r"^SSH-(\d+\.\d+)-([^\s]+)(?:\s+(.*))?$", banner)

            direction = "Unknown"
            if srcPort in (22, 2222):
                direction = "Server Identification"
            elif dstPort in (22, 2222):
                direction = "Client Identification"
            isSSH = True
            if not m:
                return {
                    "Type": "Identification",
                    "ssh.type": "Identification",
                    "Banner": banner,
                    "ssh.banner": banner,
                    "Direction": direction,
                    "ssh.direction": direction,
                }

            protoVersion = m.group(1)
            softwareVersion = m.group(2)
            comments = m.group(3).strip() if m.group(3) else ""
            isSSH = True
            result = {
                "Type": "Identification",
                "ssh.type": "Identification",
                "Banner": banner,
                "ssh.banner": banner,
                "Protocol Version": protoVersion,
                "ssh.protocol_version": protoVersion,
                "Software Version": softwareVersion,
                "ssh.software_version": softwareVersion,
                "Direction": direction,
                "ssh.direction": direction,
            }
            if comments:
                result["Comments"] = comments
                result["ssh.comments"] = comments
            return result

        # SSH binary packet framing starts with a uint32 packet_length then
        # one byte padding_length. This remains visible even when payload data
        # itself is encrypted.
        if len(rawPayload) < 6:
            return None

        packetLength = int.from_bytes(payloadPrefix, byteorder="big", signed=False)
        if packetLength <= 0 or packetLength > 35000:
            return None

        paddingLength = int(rawPayload[4])
        # Sanity checks from RFC 4253: padding >= 4, packet_length >= padding+1
        if paddingLength < 4 or packetLength < (paddingLength + 1):
            return None

        # The first byte of packet payload is the SSH message number only when
        # encryption is not yet active; otherwise it is encrypted/random.
        msgTypeNum = int(rawPayload[5])
        msgTypeName = SSH_MESSAGE_TYPES.get(msgTypeNum, f"Unknown({msgTypeNum})")
        knownClearMessage = msgTypeNum in SSH_MESSAGE_TYPES
        isSSH = True
        return {
            "Type": "Binary Packet",
            "ssh.type": "Binary Packet",
            "Packet Length": packetLength,
            "ssh.packet_length": packetLength,
            "Padding Length": paddingLength,
            "ssh.padding_length": paddingLength,
            "Message Type": msgTypeName,
            "ssh.msg_type": msgTypeName,
            "Message Type Number": msgTypeNum,
            "ssh.msg_type_num": msgTypeNum,
            "Likely Encrypted": not knownClearMessage,
            "ssh.likely_encrypted": not knownClearMessage,
        }
    except Exception:
        return None


def decodeNNTP(rawPayload):
    """
    Decode NNTP (Network News Transfer Protocol) commands and responses.
    Returns a dict with Type (Command/Response), command/status, and message,
    or None if the payload is not recognisable as NNTP traffic.
    """
    NNTP_COMMANDS = {
        "ARTICLE",
        "BODY",
        "DATE",
        "GROUP",
        "HDR",
        "HEAD",
        "HELP",
        "IHAVE",
        "LAST",
        "LIST",
        "LISTGROUP",
        "MODE",
        "NEWGROUPS",
        "NEWNEWS",
        "NEXT",
        "OVER",
        "POST",
        "QUIT",
        "READER",
        "STAT",
        "AUTHINFO",
        "COMPRESS",
    }
    try:
        text = rawPayload.decode(errors="ignore")
        lines = text.replace("\r\n", "\n").split("\n")
        firstLine = lines[0].strip()
        if not firstLine:
            return None
        parts = firstLine.split(" ", 1)
        word = parts[0].upper()
        if word in NNTP_COMMANDS:
            arg = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Command",
                "nntp.type": "Command",
                "Command": word,
                "nntp.command": word,
                "Argument": arg,
                "nntp.argument": arg,
            }
        if len(word) == 3 and word.isdigit():
            message = parts[1].strip() if len(parts) > 1 else ""
            return {
                "Type": "Response",
                "nntp.type": "Response",
                "Status Code": word,
                "nntp.status_code": word,
                "Message": message,
                "nntp.message": message,
            }
        return None
    except Exception:
        return None


def decodeRADIUS(rawPayload):
    """
    Decode RADIUS (Remote Authentication Dial-In User Service) packets from raw payload bytes.
    Extracts code, identifier, length, and basic attributes.
    Returns a dict with RADIUS fields, or None if not recognisable as RADIUS.
    """
    import struct

    RADIUS_CODES = {
        1: "Access-Request",
        2: "Access-Accept",
        3: "Access-Reject",
        4: "Accounting-Request",
        5: "Accounting-Response",
        11: "Access-Challenge",
        12: "Status-Server",
        13: "Status-Client",
        255: "Reserved",
    }
    RADIUS_ATTRIBUTES = {
        1: "User-Name",
        2: "User-Password",
        3: "CHAP-Password",
        4: "NAS-IP-Address",
        5: "NAS-Port",
        6: "Service-Type",
        7: "Framed-Protocol",
        8: "Framed-IP-Address",
        18: "Reply-Message",
        24: "State",
        25: "Class",
        26: "Vendor-Specific",
        27: "Session-Timeout",
        28: "Idle-Timeout",
        30: "Called-Station-Id",
        31: "Calling-Station-Id",
        32: "NAS-Identifier",
        40: "Acct-Status-Type",
        41: "Acct-Delay-Time",
        42: "Acct-Input-Octets",
        43: "Acct-Output-Octets",
        44: "Acct-Session-Id",
        61: "NAS-Port-Type",
        77: "Connect-Info",
        79: "EAP-Message",
        80: "Message-Authenticator",
    }
    try:
        if len(rawPayload) < 20:
            return None
        code = rawPayload[0]
        identifier = rawPayload[1]
        length = struct.unpack_from(">H", rawPayload, 2)[0]
        if length < 20 or length > len(rawPayload):
            return None
        codeName = RADIUS_CODES.get(code, f"Unknown({code})")
        attributes = []
        idx = 20
        while idx + 2 <= length and idx + 2 <= len(rawPayload):
            attrType = rawPayload[idx]
            attrLen = rawPayload[idx + 1]
            if attrLen < 2:
                break
            attrValue = rawPayload[idx + 2 : idx + attrLen]
            attrName = RADIUS_ATTRIBUTES.get(attrType, f"Attr-{attrType}")
            if attrType == 1:
                attrValueStr = attrValue.decode(errors="ignore")
            elif attrType in (4, 8):
                attrValueStr = (
                    ".".join(str(b) for b in attrValue)
                    if len(attrValue) == 4
                    else attrValue.hex()
                )
            elif attrType in (2, 3):
                attrValueStr = "***"
            else:
                attrValueStr = (
                    attrValue.decode(errors="ignore")
                    if all(32 <= b <= 126 for b in attrValue)
                    else attrValue.hex()
                )
            attributes.append({"Type": attrName, "Value": attrValueStr})
            idx += attrLen
        return {
            "Code": codeName,
            "radius.code": codeName,
            "Identifier": identifier,
            "radius.id": identifier,
            "Length": length,
            "radius.length": length,
            "Attributes": attributes,
            "radius.attrs": attributes,
        }
    except Exception:
        return None


def decodeWebSocket(rawPayload):
    """
    Decode WebSocket frames (RFC 6455) from raw payload bytes.
    Detects the binary frame header: FIN bit, opcode, mask bit, and payload length.
    Also detects WebSocket HTTP Upgrade handshake packets.
    Returns a dict with frame info, or None if not recognisable as WebSocket.
    """
    WS_OPCODES = {
        0x0: "Continuation",
        0x1: "Text",
        0x2: "Binary",
        0x8: "Close",
        0x9: "Ping",
        0xA: "Pong",
    }
    try:
        # Detect WebSocket HTTP Upgrade request
        text = rawPayload.decode(errors="ignore")
        if "Upgrade: websocket" in text or "upgrade: websocket" in text.lower():
            normalised = text.replace("\r\n", "\n")
            lines = normalised.split("\n\n")[0].split("\n")
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    k, _, v = line.partition(": ")
                    headers[k.strip().lower()] = v.strip()
            return {
                "Type": "Upgrade",
                "ws.type": "Upgrade",
                "Upgrade": headers.get("upgrade", "websocket"),
                "ws.upgrade": headers.get("upgrade", "websocket"),
                "Host": headers.get("host", "Unknown"),
                "ws.host": headers.get("host", "Unknown"),
                "Sec-WebSocket-Key": headers.get("sec-websocket-key", "Unknown"),
                "ws.key": headers.get("sec-websocket-key", "Unknown"),
                "Sec-WebSocket-Version": headers.get("sec-websocket-version", "Unknown"),
                "ws.version": headers.get("sec-websocket-version", "Unknown"),
            }
        # Detect WebSocket binary frame framing
        if len(rawPayload) < 2:
            return None
        firstByte = rawPayload[0]
        secondByte = rawPayload[1]
        fin = bool(firstByte & 0x80)
        rsv1 = bool(firstByte & 0x40)
        rsv2 = bool(firstByte & 0x20)
        rsv3 = bool(firstByte & 0x10)
        opcode = firstByte & 0x0F
        # RSV bits should be 0 unless extension negotiated; opcode must be known
        if (rsv1 or rsv2 or rsv3) and opcode not in WS_OPCODES:
            return None
        if opcode not in WS_OPCODES:
            return None
        masked = bool(secondByte & 0x80)
        payloadLen = secondByte & 0x7F
        opcodeName = WS_OPCODES[opcode]
        # Determine extended payload length
        if payloadLen == 126:
            if len(rawPayload) < 4:
                return None
            import struct
            payloadLen = struct.unpack_from(">H", rawPayload, 2)[0]
        elif payloadLen == 127:
            if len(rawPayload) < 10:
                return None
            import struct
            payloadLen = struct.unpack_from(">Q", rawPayload, 2)[0]
        return {
            "Type": "Frame",
            "ws.type": "Frame",
            "Opcode": opcodeName,
            "ws.opcode": opcodeName,
            "FIN": fin,
            "ws.fin": fin,
            "Masked": masked,
            "ws.masked": masked,
            "ws.payload_len": payloadLen,
        }
    except Exception:
        return None


def decodeNFS(rawPayload):
    """
    Decode NFS/RPC (Sun RPC) packets from raw payload bytes.
    NFS runs over TCP/UDP port 2049; portmapper uses port 111.
    Parses the ONC RPC (RFC 5531) header: XID, message type, and for CALL messages
    the RPC version, program, procedure, and credentials.
    Returns a dict with RPC/NFS fields, or None if not recognisable.
    """
    import struct

    RPC_MSG_TYPES = {0: "Call", 1: "Reply"}
    NFS_PROCEDURES = {
        0: "NULL",
        1: "GETATTR",
        2: "SETATTR",
        3: "LOOKUP",
        4: "ACCESS",
        5: "READLINK",
        6: "READ",
        7: "WRITE",
        8: "CREATE",
        9: "MKDIR",
        10: "SYMLINK",
        11: "MKNOD",
        12: "REMOVE",
        13: "RMDIR",
        14: "RENAME",
        15: "LINK",
        16: "READDIR",
        17: "READDIRPLUS",
        18: "FSSTAT",
        19: "FSINFO",
        20: "PATHCONF",
        21: "COMMIT",
    }
    PORTMAP_PROCEDURES = {
        0: "NULL",
        1: "SET",
        2: "UNSET",
        3: "GETPORT",
        4: "DUMP",
        5: "CALLIT",
    }
    RPC_PROGRAMS = {
        100000: "Portmapper",
        100003: "NFS",
        100005: "Mount",
        100021: "NLM",
        100227: "NFS_ACL",
    }
    try:
        if len(rawPayload) < 8:
            return None
        # TCP NFS framing: 4-byte record mark (fragment header) may prefix the RPC
        offset = 0
        if len(rawPayload) >= 4:
            recordMark = struct.unpack_from(">I", rawPayload, 0)[0]
            # High bit set = last fragment; lower 31 bits = fragment length
            if recordMark & 0x80000000:
                fragLen = recordMark & 0x7FFFFFFF
                if fragLen > 0 and fragLen + 4 <= len(rawPayload):
                    offset = 4
        if len(rawPayload) < offset + 8:
            return None
        xid = struct.unpack_from(">I", rawPayload, offset)[0]
        msgType = struct.unpack_from(">I", rawPayload, offset + 4)[0]
        if msgType not in RPC_MSG_TYPES:
            return None
        msgTypeName = RPC_MSG_TYPES[msgType]
        result = {
            "XID": f"0x{xid:08X}",
            "rpc.xid": f"0x{xid:08X}",
            "Message Type": msgTypeName,
            "rpc.msg_type": msgTypeName,
        }
        if msgType == 0:  # Call
            if len(rawPayload) < offset + 24:
                return None
            rpcVersion = struct.unpack_from(">I", rawPayload, offset + 8)[0]
            program = struct.unpack_from(">I", rawPayload, offset + 12)[0]
            progVersion = struct.unpack_from(">I", rawPayload, offset + 16)[0]
            procedure = struct.unpack_from(">I", rawPayload, offset + 20)[0]
            progName = RPC_PROGRAMS.get(program, f"Prog-{program}")
            if program == 100003:
                procName = NFS_PROCEDURES.get(procedure, f"Proc-{procedure}")
            elif program == 100000:
                procName = PORTMAP_PROCEDURES.get(procedure, f"Proc-{procedure}")
            else:
                procName = f"Proc-{procedure}"
            result.update({
                "RPC Version": rpcVersion,
                "rpc.version": rpcVersion,
                "Program": progName,
                "rpc.program": progName,
                "Program Version": progVersion,
                "rpc.prog_version": progVersion,
                "Procedure": procName,
                "rpc.procedure": procName,
            })
        elif msgType == 1:  # Reply
            if len(rawPayload) < offset + 12:
                return None
            replyStatus = struct.unpack_from(">I", rawPayload, offset + 8)[0]
            statusName = "Accepted" if replyStatus == 0 else "Denied"
            result["Reply Status"] = statusName
            result["rpc.reply_status"] = statusName
        return result
    except Exception:
        return None


def decodeKerberos(rawPayload):
    """
    Decode Kerberos 5 messages from raw payload bytes using ASN.1 BER/DER structure.
    Kerberos runs over TCP/UDP port 88. Extracts the message type tag.
    For AS-REQ messages also attempts to extract the client principal name.
    Returns a dict with Kerberos message type info, or None if not recognisable.
    """
    KRB5_MSG_TYPES = {
        0x6A: "AS-REQ",       # [APPLICATION 10]
        0x6B: "AS-REP",       # [APPLICATION 11]
        0x6C: "TGS-REQ",      # [APPLICATION 12]
        0x6D: "TGS-REP",      # [APPLICATION 13]
        0x6E: "AP-REQ",       # [APPLICATION 14]
        0x6F: "AP-REP",       # [APPLICATION 15]
        0x74: "KRB-ERROR",    # [APPLICATION 30]
        0x79: "KRB-PRIV",     # [APPLICATION 25]
        0x7A: "KRB-CRED",     # [APPLICATION 26]
    }
    try:
        payload = rawPayload
        # TCP Kerberos may be prefixed by a 4-byte big-endian length
        if len(payload) < 2:
            return None
        import struct
        if len(payload) >= 4:
            tcpLen = struct.unpack_from(">I", payload, 0)[0]
            if tcpLen + 4 == len(payload) and tcpLen > 0:
                payload = payload[4:]
        if len(payload) < 2:
            return None
        # ASN.1 application tag for Kerberos messages
        tag = payload[0]
        if tag not in KRB5_MSG_TYPES:
            return None
        msgTypeName = KRB5_MSG_TYPES[tag]
        result = {
            "Message Type": msgTypeName,
            "krb5.msg_type": msgTypeName,
        }
        # For AS-REQ (0x6A), attempt to extract pvno (protocol version)
        # ASN.1 structure: [APP tag] length SEQUENCE { pvno INTEGER, ... }
        try:
            idx = 1
            # skip outer tag length
            if payload[idx] & 0x80:
                numBytes = payload[idx] & 0x7F
                idx += 1 + numBytes
            else:
                idx += 1
            # expect SEQUENCE (0x30)
            if idx < len(payload) and payload[idx] == 0x30:
                idx += 1
                if payload[idx] & 0x80:
                    numBytes = payload[idx] & 0x7F
                    idx += 1 + numBytes
                else:
                    idx += 1
                # expect [0] pvno context
                if idx < len(payload) and payload[idx] == 0xA0:
                    idx += 1
                    if payload[idx] & 0x80:
                        numBytes = payload[idx] & 0x7F
                        idx += 1 + numBytes
                    else:
                        idx += 1
                    # INTEGER
                    if idx + 2 < len(payload) and payload[idx] == 0x02:
                        pvnoLen = payload[idx + 1]
                        pvno = int.from_bytes(payload[idx + 2: idx + 2 + pvnoLen], "big")
                        result["Protocol Version"] = pvno
                        result["krb5.pvno"] = pvno
        except Exception:
            pass
        return result
    except Exception:
        return None


def decodeWanLinkProtocols(p):
    """
    Detect and decode WAN/link-control protocols from available scapy layers.
    Supports ATM, Token Ring, Frame Relay, SDLC, HDLC, SLIP, PPP, LCP, LAP, and NCP.
    Returns a dict with both display-friendly keys and dot-notation keys, or None
    when no requested protocol indicators are present.
    """
    try:
        layerNames = [
            getattr(layer, "__name__", str(layer)).lower() for layer in p.layers()
        ]
    except Exception:
        layerNames = []

    if not layerNames:
        return None

    def hasLayerName(*names):
        return any(
            layerName == name or layerName.startswith(name + "_")
            for layerName in layerNames
            for name in names
        )

    detectedProtocols = []

    def mark(protoName, present):
        if present and protoName not in detectedProtocols:
            detectedProtocols.append(protoName)

    mark("ATM", hasLayerName("atm", "atmad", "atmmeta"))
    mark("ATM", hasLayerName("clip", "aal5", "pppoatm", "pppoa"))
    mark("Token Ring", hasLayerName("tokenring", "dot5"))
    mark("Frame Relay", hasLayerName("framerelay", "frame_relay"))
    mark("SDLC", hasLayerName("sdlc"))
    mark("HDLC", hasLayerName("hdlc"))
    mark("SLIP", hasLayerName("slip"))
    mark("PPP", hasLayerName("ppp", "pppoe"))
    mark("LCP", hasLayerName("lcp", "ppp_lcp"))
    mark("LAP", hasLayerName("lap", "lapb", "lapd"))
    mark("NCP", hasLayerName("ncp", "ipcp", "ipv6cp", "ppp_ncp"))

    # PPP protocol field can reveal LCP/NCP even when sublayers are not decoded.
    pppProtocolHex = "N/A"
    pppProtocolName = "Unknown"
    if p.haslayer("PPP"):
        try:
            pppProtoVal = int(p["PPP"].proto)
            pppProtocolHex = f"0x{pppProtoVal:04x}"
            pppProtocolMap = {
                0x0021: "IPv4",
                0x0057: "IPv6",
                0x8021: "IPCP (NCP)",
                0x8057: "IPv6CP (NCP)",
                0x80FD: "CCP (NCP)",
                0xC021: "LCP",
                0xC023: "PAP (LCP Auth)",
                0xC223: "CHAP (LCP Auth)",
            }
            pppProtocolName = pppProtocolMap.get(pppProtoVal, f"0x{pppProtoVal:04x}")
            if pppProtoVal in (0xC021, 0xC023, 0xC223):
                mark("LCP", True)
            if pppProtoVal in (0x8021, 0x8057, 0x80FD):
                mark("NCP", True)
        except Exception:
            pass

    if not detectedProtocols:
        return None

    result = {
        "Detected Protocols": detectedProtocols,
        "wan.detected": detectedProtocols,
        "Layer Names": layerNames,
        "wan.layers": layerNames,
        "Primary WAN Protocol": detectedProtocols[0],
        "wan.primary": detectedProtocols[0],
        "link.proto": detectedProtocols[0].lower().replace(" ", "_"),
    }

    if pppProtocolHex != "N/A":
        result["PPP Protocol Field"] = f"{pppProtocolHex} ({pppProtocolName})"
        result["ppp.proto_field"] = f"{pppProtocolHex} ({pppProtocolName})"

    if hasLayerName("clip"):
        result["ATM Encapsulation"] = "Classical IP over ATM (CLIP)"
        result["atm.encapsulation"] = "Classical IP over ATM (CLIP)"
    elif hasLayerName("pppoatm", "pppoa"):
        result["ATM Encapsulation"] = "PPP over ATM (PPPoA)"
        result["atm.encapsulation"] = "PPP over ATM (PPPoA)"
    elif hasLayerName("aal5"):
        result["ATM Encapsulation"] = "ATM AAL5"
        result["atm.encapsulation"] = "ATM AAL5"

    for proto in detectedProtocols:
        protoKey = proto.lower().replace(" ", "_")
        result[f"wan.proto.{protoKey}"] = proto

    return result


SIGTRAN_PORT_PROTOCOLS = {
    2904: "M2UA",
    2905: "M3UA",
    2906: "SUA",
    3565: "M2PA",
    9900: "IUA",
}

SCTP_PORT_PROTOCOLS = {
    **SIGTRAN_PORT_PROTOCOLS,
    2944: "H.248/MEGACO",
    3868: "Diameter",
    3869: "Diameter",
}

SCTP_CHUNK_TYPE_NAMES = {
    0: "DATA",
    1: "INIT",
    2: "INIT ACK",
    3: "SACK",
    4: "HEARTBEAT",
    5: "HEARTBEAT ACK",
    6: "ABORT",
    7: "SHUTDOWN",
    8: "SHUTDOWN ACK",
    9: "ERROR",
    10: "COOKIE ECHO",
    11: "COOKIE ACK",
    12: "ECNE",
    13: "CWR",
    14: "SHUTDOWN COMPLETE",
}

M3UA_MESSAGE_CLASS_NAMES = {
    0: "Transfer Messages",
    1: "SS7 Signalling Network Management",
    2: "ASP State Maintenance",
    3: "ASP Traffic Maintenance",
    4: "Routing Key Management",
    5: "ASP Interface Management",
    6: "Error Messages",
    7: "Reserved",
    8: "Network Appearance Management",
}


def _decodeSctpChunks(chunkBytes):
    chunks = []
    firstDataPayload = None
    offset = 0

    while offset + 4 <= len(chunkBytes):
        chunkType = int(chunkBytes[offset])
        chunkFlags = int(chunkBytes[offset + 1])
        chunkLength = int.from_bytes(chunkBytes[offset + 2 : offset + 4], "big")
        if chunkLength < 4 or offset + chunkLength > len(chunkBytes):
            break

        chunkPayload = chunkBytes[offset + 4 : offset + chunkLength]
        chunkName = SCTP_CHUNK_TYPE_NAMES.get(chunkType, f"Type {chunkType}")
        chunkInfo = {
            "sctp.chunk.type": chunkType,
            "sctp.chunk.flags": chunkFlags,
            "sctp.chunk.length": chunkLength,
            "sctp.chunk.type_name": chunkName,
            "sctp.chunk.payload.len": len(chunkPayload),
        }
        if chunkPayload:
            preview = chunkPayload[:32].hex()
            chunkInfo["sctp.chunk.payload.preview"] = preview
        chunks.append(chunkInfo)
        if chunkType == 0 and firstDataPayload is None:
            firstDataPayload = chunkPayload

        offset += (chunkLength + 3) & ~3

    return chunks, firstDataPayload


def decodeSctpPacket(p):
    """
    Decode SCTP transport headers and rudimentary SIGTRAN/M3UA metadata.
    Returns a dict with SCTP header fields and, when present, a nested SIGTRAN section.
    """

    sctpLayer = None
    try:
        if p.haslayer("SCTP"):
            sctpLayer = p["SCTP"]
    except Exception:
        sctpLayer = None

    try:
        if sctpLayer is not None:
            sctpBytes = bytes(sctpLayer)
        else:
            sctpBytes = bytes(p["IP"].payload)
    except Exception:
        return None

    if len(sctpBytes) < 12:
        return None

    try:
        srcPort = int(getattr(sctpLayer, "sport", int.from_bytes(sctpBytes[0:2], "big")))
    except Exception:
        srcPort = int.from_bytes(sctpBytes[0:2], "big")
    try:
        dstPort = int(getattr(sctpLayer, "dport", int.from_bytes(sctpBytes[2:4], "big")))
    except Exception:
        dstPort = int.from_bytes(sctpBytes[2:4], "big")

    verificationTag = int.from_bytes(sctpBytes[4:8], "big")
    checksum = f"0x{sctpBytes[8:12].hex()}"
    chunkBytes = sctpBytes[12:]
    chunks, firstDataPayload = _decodeSctpChunks(chunkBytes)

    sigtranProto = SIGTRAN_PORT_PROTOCOLS.get(srcPort) or SIGTRAN_PORT_PROTOCOLS.get(dstPort)
    if sigtranProto is None and firstDataPayload and len(firstDataPayload) >= 8 and firstDataPayload[0] == 1:
        sigtranProto = "M3UA"

    sigtranSection = None
    if sigtranProto is not None:
        sigtranSection = {
            "sigtran.proto": sigtranProto,
            "sigtran.signaling": "SS7 over SCTP" if sigtranProto in ("M2UA", "M3UA", "SUA", "M2PA", "IUA") else "SCTP adaptation",
        }
        if sigtranProto == "M3UA" and firstDataPayload and len(firstDataPayload) >= 8 and firstDataPayload[0] == 1:
            messageClass = int(firstDataPayload[2])
            messageType = int(firstDataPayload[3])
            messageLength = int.from_bytes(firstDataPayload[4:8], "big")
            sigtranSection.update(
                {
                    "sigtran.version": int(firstDataPayload[0]),
                    "sigtran.reserved": int(firstDataPayload[1]),
                    "sigtran.message.class": messageClass,
                    "sigtran.message.type": messageType,
                    "sigtran.length": messageLength,
                    "sigtran.message.class_name": M3UA_MESSAGE_CLASS_NAMES.get(messageClass, f"Class {messageClass}"),
                }
            )
            if len(firstDataPayload) > 8:
                preview = firstDataPayload[8 : min(len(firstDataPayload), 40)].hex()
                sigtranSection["sigtran.payload.preview"] = preview
                sigtranSection["sigtran.payload.len"] = len(firstDataPayload) - 8
        elif firstDataPayload:
            preview = firstDataPayload[:32].hex()
            sigtranSection["sigtran.payload.len"] = len(firstDataPayload)
            sigtranSection["sigtran.payload.preview"] = preview

    section = {
        "sctp.src.port": srcPort,
        "sctp.dst.port": dstPort,
        "sctp.vtag": verificationTag,
        "sctp.chksum": checksum,
        "sctp.chunk.count": len(chunks),
        "sctp.chunks": [chunk["sctp.chunk.type_name"] for chunk in chunks],
        "wire.len": len(sctpBytes),
        "transport.len": len(sctpBytes),
        "transport.proto": "SCTP",
    }
    if chunks:
        section["sctp.chunk.details"] = chunks
    if sigtranSection is not None:
        section["SIGTRAN"] = sigtranSection

    return section


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


def decodeAddressResolutionPacket(p):
    """
    Decode ARP/RARP packet fields from a scapy packet.
    Returns a tuple of (protocolName, sectionDict, srcIp, dstIp) where protocolName
    is "ARP" or "RARP". Returns None when ARP layer data is unavailable.
    """
    arpClass = getattr(scapy, "ARP", None)
    hasArpLayer = bool(arpClass and p.haslayer(arpClass)) or p.haslayer("ARP")
    if not hasArpLayer:
        return None

    arpLayer = p[arpClass] if arpClass and p.haslayer(arpClass) else p["ARP"]

    opMap = {
        1: "Request",
        2: "Reply",
        3: "RARP Request",
        4: "RARP Reply",
        8: "InARP Request",
        9: "InARP Reply",
    }

    try:
        opCode = int(getattr(arpLayer, "op", 0))
    except Exception:
        opCode = 0
    opLabel = opMap.get(opCode, f"Opcode {opCode}")

    etherType = None
    if p.haslayer("Ether"):
        try:
            etherType = int(p["Ether"].type)
        except Exception:
            etherType = None

    isRarp = opCode in (3, 4) or etherType == 0x8035
    protocolName = "RARP" if isRarp else "ARP"

    srcIp = str(getattr(arpLayer, "psrc", "0.0.0.0") or "0.0.0.0")
    dstIp = str(getattr(arpLayer, "pdst", "0.0.0.0") or "0.0.0.0")
    srcMac = str(getattr(arpLayer, "hwsrc", "N/A") or "N/A")
    dstMac = str(getattr(arpLayer, "hwdst", "N/A") or "N/A")

    hwTypeVal = int(getattr(arpLayer, "hwtype", 0) or 0)
    protoTypeVal = int(getattr(arpLayer, "ptype", 0) or 0)
    hwSizeVal = int(getattr(arpLayer, "hwlen", 0) or 0)
    protoSizeVal = int(getattr(arpLayer, "plen", 0) or 0)

    section = {
        "Operation": opLabel,
        "arp.op": opLabel,
        "rarp.op": opLabel,
        "link.rarp": opLabel,
        "link.arp.op": opLabel,
        "Opcode": opCode,
        "arp.opcode": opCode,
        "rarp.opcode": opCode,
        "link.arp.opcode": opCode,
        "link.rarp.opcode": opCode,
        "Sender MAC": srcMac,
        "arp.src.mac": srcMac,
        "rarp.src.mac": srcMac,
        "link.arp.src.mac": srcMac,
        "link.rarp.src.mac": srcMac,
        "Target MAC": dstMac,
        "arp.dst.mac": dstMac,
        "rarp.dst.mac": dstMac,
        "link.arp.dst.mac": dstMac,
        "link.rarp.dst.mac": dstMac,
        "Sender IP": srcIp,
        "arp.src.ip": srcIp,
        "rarp.src.ip": srcIp,
        "link.arp.src.ip": srcIp,
        "link.rarp.src.ip": srcIp,
        "Target IP": dstIp,
        "arp.dst.ip": dstIp,
        "rarp.dst.ip": dstIp,
        "link.arp.dst.ip": dstIp,
        "link.rarp.dst.ip": dstIp,
        "Hardware Type": hwTypeVal,
        "arp.hw.type": hwTypeVal,
        "link.arp.hw.type": hwTypeVal,
        "rarp.hw.type": hwTypeVal,
        "link.rarp.hw.type": hwTypeVal,
        "Protocol Type": f"0x{protoTypeVal:04x}",
        "arp.proto.type": f"0x{protoTypeVal:04x}",
        "link.arp.proto.type": f"0x{protoTypeVal:04x}",
        "rarp.proto.type": f"0x{protoTypeVal:04x}",
        "link.rarp.proto.type": f"0x{protoTypeVal:04x}",
        "Hardware Size": hwSizeVal,
        "arp.hw.size": hwSizeVal,
        "link.arp.hw.size": hwSizeVal,
        "rarp.hw.size": hwSizeVal,
        "link.rarp.hw.size": hwSizeVal,
        "Protocol Size": protoSizeVal,
        "arp.proto.size": protoSizeVal,
        "link.arp.proto.size": protoSizeVal,
        "rarp.proto.size": protoSizeVal,
        "link.rarp.proto.size": protoSizeVal,
        "link.proto": "ARP" if not isRarp else "RARP",
    }

    return protocolName, section, srcIp, dstIp


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
    WebSocket (80/443/8080/8443/8765), NFS/RPC (2049/111), Kerberos (88), and
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
    srcMacAddr = p.src if hasattr(p, "src") else "N/A"
    dstMacAddr = p.dst if hasattr(p, "dst") else "N/A"
    srcMacVendor = macAddrToVendor(srcMacAddr) if srcMacAddr != "N/A" else "N/A"
    dstMacVendor = macAddrToVendor(dstMacAddr) if dstMacAddr != "N/A" else "N/A"
    isSSH = False
    wanLinkSection = decodeWanLinkProtocols(p)

    # Decode ARP/RARP packets that do not carry an IP layer.
    if not p.haslayer("IP"):
        arpDecoded = decodeAddressResolutionPacket(p)
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
                json.dumps(dataTypeInfo).encode(),
                json.dumps(packetInfo).encode(),
                dstIp if dstIp != "0.0.0.0" else srcIp,
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
            json.dumps(dataTypeInfo).encode(),
            json.dumps(packetInfo).encode(),
            "0.0.0.0",
        )

    isTcp = p.haslayer("TCP")
    isUdp = p.haslayer("UDP")
    isSctp = isSctpPacket(p)
    ipProtocolNumber = int(getattr(p["IP"], "proto", -1))
    isIgmp = p.haslayer("IGMP") or ipProtocolNumber == 2
    isIcmp = p.haslayer("ICMP")

    if isTcp:
        rawPayload = p["TCP"].payload.original
        srcPort = p["TCP"].sport
        dstPort = p["TCP"].dport
        transportProtocol = "tcp"
        initialDstPort = dstPort
        streamKey = getTcpStreamKey(p["IP"].src, srcPort, p["IP"].dst, dstPort)
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
        #dstPort = streamStabilzeProtocol(streamKey, dstPort)
        #srcPort = streamStabilzeProtocol(streamKey, srcPort)
    elif isUdp:
        rawPayload = p["UDP"].payload.original
        srcPort = p["UDP"].sport
        dstPort = p["UDP"].dport
        transportProtocol = "udp"
        dstPortStr = str(dstPort)
    elif isSctp:
        sctpLayer = p["SCTP"] if p.haslayer("SCTP") else None
        rawPayload = bytes(p["IP"].payload)
        srcPort = int(getattr(sctpLayer, "sport", int.from_bytes(rawPayload[0:2], "big")) or 0)
        dstPort = int(getattr(sctpLayer, "dport", int.from_bytes(rawPayload[2:4], "big")) or 0)
        transportProtocol = "sctp"
        dstPortStr = str(dstPort)
    elif isIgmp:
        rawPayload = bytes(p["IP"].payload)
        srcPort = 0
        dstPort = 0
        transportProtocol = "igmp"
        dstPortStr = "igmp"
    elif isIcmp:
        # ICMP: use the full ICMP layer bytes as the payload
        rawPayload = bytes(p["ICMP"])
        srcPort = 0
        dstPort = 0
        transportProtocol = "icmp"
        dstPortStr = "icmp"
    else:
        # Catch-all fallback for packets we can see but do not have a decoder for yet.
        ipPayload = bytes(p["IP"].payload)
        rawPayload = ipPayload if len(ipPayload) > 0 else bytes(p["IP"])
        srcPort = 0
        dstPort = 0
        transportProtocol = "ip"
        dstPortStr = "undecodable"

    if (srcPortFilter is None or srcPort == srcPortFilter) and (
        dstPortFilter is None or dstPort == dstPortFilter
    ):
        if rawPayload is not None and len(rawPayload) > 0:
            streamLabelPort = dstPort
            if isTcp:
                streamKey = getTcpStreamKey(p["IP"].src, srcPort, p["IP"].dst, dstPort)
                streamLabelPort = tcpStreamInitialDstPortMap.get(streamKey, dstPort)
            #writeTestcase(rawPayload, outputDir, dstPortStr, packetIndex)
            if transportProtocol == "ip":
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
                    p["IP"].src,
                    p["IP"].dst,
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
            srcGeoInfo = getGeoipInfo(p["IP"].src, "src")
            dstGeoInfo = getGeoipInfo(p["IP"].dst, "dst")
            isLocalNetwork = (
                srcGeoInfo.get("Location") == "Localnet"
                and dstGeoInfo.get("Location") == "Localnet"
            )

            if isTcp:
                # Build TCP flag string once
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
                    "tcp.chksum": hex(int(p["TCP"].chksum)),
                    "transport.tcp.chksum": hex(int(p["TCP"].chksum)),
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
                    "tcp.len": int(p["TCP"].dataofs * 4),
                    "transport.tcp.len": int(p["TCP"].dataofs * 4),
                    "Wire length": len(p["TCP"]),
                    "wire.len": len(p["TCP"]),
                    "wire.proto": "TCP",
                    "transport.proto": "TCP",
                }
                # Decode SIP on TCP ports 5060/5061
                if streamLabelPort in (5060, 5061) or srcPort in (5060, 5061):
                    sipSection = decodeSIP(rawPayload)
                    if sipSection is not None:
                        transportSection["SIP"] = sipSection
                # Decode SNMP on TCP port 161/162 (less common but valid)
                if streamLabelPort in (161, 162) or srcPort in (161, 162):
                    snmpSection = decodeSNMP(p)
                    if snmpSection is not None:
                        transportSection["SNMP"] = snmpSection
                # Decode HTTP on any TCP port — decodeHTTP() returns None for non-HTTP payloads
                httpSection = decodeHTTP(rawPayload)
                if httpSection is not None:
                    transportSection["HTTP"] = httpSection
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
                    http2Section = decodeHTTP2(rawPayload)
                    if http2Section is not None:
                        transportSection["HTTP2"] = http2Section
                # Decode FTP on TCP ports 20/21
                if streamLabelPort in (20, 21) or srcPort in (20, 21):
                    ftpSection = decodeFTP(rawPayload)
                    if ftpSection is not None:
                        transportSection["FTP"] = ftpSection
                # Decode SMTP on TCP ports 25/587/465
                if streamLabelPort in (25, 587, 465) or srcPort in (25, 587, 465):
                    smtpSection = decodeSMTP(rawPayload)
                    if smtpSection is not None:
                        transportSection["SMTP"] = smtpSection
                # Decode POP3/POP on TCP ports 110/995
                if streamLabelPort in (110, 995) or srcPort in (110, 995):
                    pop3Section = decodePOP3(rawPayload)
                    if pop3Section is not None:
                        transportSection["POP3"] = pop3Section
                # Decode IMAP/IMAP4 on TCP ports 143/993
                if streamLabelPort in (143, 993) or srcPort in (143, 993):
                    imapSection = decodeIMAP(rawPayload)
                    if imapSection is not None:
                        transportSection["IMAP"] = imapSection
                # Decode Telnet on TCP port 23
                if streamLabelPort == 23 or srcPort == 23:
                    telnetSection = decodeTelnet(rawPayload)
                    if telnetSection is not None:
                        transportSection["Telnet"] = telnetSection
                    # Also scan non-IAC data packets for cleartext credentials
                    telnetCreds = extractTelnetCredentials(rawPayload)
                    if telnetCreds:
                        if "Telnet" not in transportSection:
                            transportSection["Telnet"] = {}
                        transportSection["Telnet"].setdefault("Credentials", {}).update(
                            telnetCreds
                        )
                # Decode IRC on TCP ports 6667/6668/6669
                if streamLabelPort in (6667, 6668, 6669) or srcPort in (6667, 6668, 6669):
                    ircSection = decodeIRC(rawPayload)
                    if ircSection is not None:
                        transportSection["IRC"] = ircSection
                # Decode MTP/MMS on TCP port 1755
                if streamLabelPort == 1755 or srcPort == 1755:
                    mtpSection = decodeMTP(rawPayload)
                    if mtpSection is not None:
                        transportSection["MTP"] = mtpSection
                # Decode LDAP on TCP ports 389/636
                if streamLabelPort in (389, 636) or srcPort in (389, 636):
                    ldapSection = decodeLDAP(rawPayload)
                    if ldapSection is not None:
                        transportSection["LDAP"] = ldapSection
                # Decode MySQL on TCP port 3306
                if streamLabelPort == 3306 or srcPort == 3306:
                    mysqlSection = decodeMySQL(rawPayload)
                    if mysqlSection is not None:
                        transportSection["MySQL"] = mysqlSection
                # Decode PostgreSQL on TCP port 5432
                if streamLabelPort == 5432 or srcPort == 5432:
                    pgSection = decodePostgreSQL(rawPayload)
                    if pgSection is not None:
                        transportSection["PostgreSQL"] = pgSection
                # Decode XMPP on TCP ports 5222/5223
                if streamLabelPort in (5222, 5223) or srcPort in (5222, 5223):
                    xmppSection = decodeXMPP(rawPayload)
                    if xmppSection is not None:
                        transportSection["XMPP"] = xmppSection
                # Decode SMB on TCP ports 139/445
                if streamLabelPort in (139, 445) or srcPort in (139, 445):
                    smbSection = decodeSMB(rawPayload)
                    if smbSection is not None:
                        transportSection["SMB"] = smbSection
                # Decode MQTT on TCP ports 1883/8883
                if streamLabelPort in (1883, 8883) or srcPort in (1883, 8883):
                    mqttSection = decodeMQTT(rawPayload)
                    if mqttSection is not None:
                        transportSection["MQTT"] = mqttSection
                # Decode RTSP on TCP port 554
                if streamLabelPort == 554 or srcPort == 554:
                    rtspSection = decodeRTSP(rawPayload)
                    if rtspSection is not None:
                        transportSection["RTSP"] = rtspSection
                # Decode BGP on TCP port 179
                if streamLabelPort == 179 or srcPort == 179:
                    bgpSection = decodeBGP(rawPayload)
                    if bgpSection is not None:
                        transportSection["BGP"] = bgpSection
                # Decode NNTP on TCP port 119
                if streamLabelPort == 119 or srcPort == 119:
                    nntpSection = decodeNNTP(rawPayload)
                    if nntpSection is not None:
                        transportSection["NNTP"] = nntpSection
                # Decode RADIUS on TCP ports 1812/1813/1645/1646 (RFC 6614 defines RADIUS over TCP)
                if dstPort in (1812, 1813, 1645, 1646) or srcPort in (
                    1812,
                    1813,
                    1645,
                    1646,
                ):
                    radiusSection = decodeRADIUS(rawPayload)
                    if radiusSection is not None:
                        transportSection["RADIUS"] = radiusSection
                # Decode WebSocket on TCP ports 80/443/8080/8443/8765 (stream-following aware)
                if streamLabelPort in (80, 443, 8080, 8443, 8765) or srcPort in (80, 443, 8080, 8443, 8765):
                    wsSection = decodeWebSocket(rawPayload)
                    if wsSection is not None:
                        transportSection["WebSocket"] = wsSection
                # Decode NFS/RPC on TCP ports 2049/111
                if streamLabelPort in (2049, 111) or srcPort in (2049, 111):
                    nfsSection = decodeNFS(rawPayload)
                    if nfsSection is not None:
                        transportSection["NFS"] = nfsSection
                # Decode Kerberos on TCP port 88
                if streamLabelPort == 88 or srcPort == 88:
                    kerberosSection = decodeKerberos(rawPayload)
                    if kerberosSection is not None:
                        transportSection["Kerberos"] = kerberosSection
                # Decode SSH metadata on TCP ports 22/2222, or when payload starts with SSH banner
                if (
                    streamLabelPort in (22, 2222)
                    or srcPort in (22, 2222) or dstPort in (22, 2222)
                    or rawPayload.startswith(b"SSH-")
                ):
                    sshSection = decodeSSH(rawPayload, srcPort, dstPort)
                    if sshSection is not None:
                        transportSection["SSH"] = sshSection
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
                    "udp.chksum": hex(int(p["UDP"].chksum)),
                    "UDP length": int(p["UDP"].len),
                    "udp.len": int(p["UDP"].len),
                    "Wire length": len(p["UDP"]),
                    "wire.len": len(p["UDP"]),
                    "wire.proto": "UDP",
                    "transport.proto": "UDP",
                    "transport.udp.src.port": int(srcPort),
                    "transport.udp.dst.port": int(dstPort),
                    "transport.udp.chksum": hex(int(p["UDP"].chksum)),
                    "transport.udp.len": int(p["UDP"].len),
                    "transport.len": len(p["UDP"]),
                }
                if dnsSection is not None:
                    transportSection["DNS"] = dnsSection
                # Decode SNMP on UDP ports 161/162
                if dstPort in (161, 162) or srcPort in (161, 162):
                    snmpSection = decodeSNMP(p)
                    if snmpSection is not None:
                        transportSection["SNMP"] = snmpSection
                # Decode DHCP on UDP ports 67/68
                if dstPort in (67, 68) or srcPort in (67, 68):
                    dhcpSection = decodeDHCP(p)
                    if dhcpSection is not None:
                        transportSection["DHCP"] = dhcpSection
                # Decode NTP on UDP port 123
                if dstPort == 123 or srcPort == 123:
                    ntpSection = decodeNTP(p)
                    if ntpSection is not None:
                        transportSection["NTP"] = ntpSection
                # Decode SIP on UDP ports 5060/5061
                if dstPort in (5060, 5061) or srcPort in (5060, 5061):
                    sipSection = decodeSIP(rawPayload)
                    if sipSection is not None:
                        transportSection["SIP"] = sipSection
                # Decode TFTP on UDP port 69
                if dstPort == 69 or srcPort == 69:
                    tftpSection = decodeTFTP(rawPayload)
                    if tftpSection is not None:
                        transportSection["TFTP"] = tftpSection
                # Decode MQTT on UDP ports 1883/8883
                if dstPort in (1883, 8883) or srcPort in (1883, 8883):
                    mqttSection = decodeMQTT(rawPayload)
                    if mqttSection is not None:
                        transportSection["MQTT"] = mqttSection
                # Decode LDAP on UDP ports 389/636
                if dstPort in (389, 636) or srcPort in (389, 636):
                    ldapSection = decodeLDAP(rawPayload)
                    if ldapSection is not None:
                        transportSection["LDAP"] = ldapSection
                # Decode RADIUS on UDP ports 1812/1813/1645/1646
                if dstPort in (1812, 1813, 1645, 1646) or srcPort in (
                    1812,
                    1813,
                    1645,
                    1646,
                ):
                    radiusSection = decodeRADIUS(rawPayload)
                    if radiusSection is not None:
                        transportSection["RADIUS"] = radiusSection
                # Decode NFS/RPC on UDP ports 2049/111
                if dstPort in (2049, 111) or srcPort in (2049, 111):
                    nfsSection = decodeNFS(rawPayload)
                    if nfsSection is not None:
                        transportSection["NFS"] = nfsSection
                # Decode Kerberos on UDP port 88
                if dstPort == 88 or srcPort == 88:
                    kerberosSection = decodeKerberos(rawPayload)
                    if kerberosSection is not None:
                        transportSection["Kerberos"] = kerberosSection
                protocolKey = "UDP"
            elif isSctp:
                sctpSection = decodeSctpPacket(p)
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
                # ICMP transport section
                icmpLayer = p["ICMP"]
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
                    "Wire length": len(p["ICMP"]),
                    "wire.len": len(p["ICMP"]),
                    "transport.len": len(p["ICMP"]),
                    "transport.proto": "ICMP",
                }
                protocolKey = "ICMP"
            elif isIgmp:
                transportSection = decodeIGMP(p, rawPayload)
                protocolKey = "IGMP"
            else:
                ipProtoNum = int(getattr(p["IP"], "proto", 0))
                transportSection = {
                    "transport.src.port": int(srcPort),
                    "transport.dst.port": int(dstPort),
                    "IP Protocol Number": ipProtoNum,
                    "ip.proto.num": ipProtoNum,
                    "network.ip.proto.num": ipProtoNum,
                    "Wire length": len(p["IP"]),
                    "wire.len": len(p["IP"]),
                    "network.len": len(p["IP"]),
                    "network.proto": "IP",
                    "transport.proto": "Unknown protocol",
                }
                protocolKey = "Undecodable"

            packetInfo = {
                "packet.processed": int(packetIndex),
                "packet.timestamp": timestamp,
                "packet.proto": protocolKey,
                "link.proto": "Ethernet",
                # Include Ethernet MAC data when at least one IP is local (private),
                # so that mixed private+internet traffic still exposes the local device's MAC.
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
                    "ip.src.addr": str(p["IP"].src),
                    "network.ip.src.addr": str(p["IP"].src),
                    "ip.dst.addr": str(p["IP"].dst),
                    "network.ip.dst.addr": str(p["IP"].dst),
                    "ip.chksum": hex(int(p["IP"].chksum)),
                    "network.ip.chksum": hex(int(p["IP"].chksum)),
                    "ip.len": int(p["IP"].len),
                    "network.ip.len": int(p["IP"].len),
                    "network.proto": "IP",
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
                p["IP"].dst if dstGeoInfo.get("Location") != "Localnet" else p["IP"].src
            )
            mergedInfo = joinInfo(
                outputDir,
                dstPortStr,
                packetIndex,
                json.dumps(dataTypeInfo).encode(),
                json.dumps(packetInfo).encode(),
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
    return packetLoop(p, packetIndex, srcPortFilter, dstPortFilter, timeout)


def startThreading():
    """
    Process packets from the pre-loaded `packets` list using a
    ThreadPoolExecutor with chunked processing for reduced overhead.

    Rather than re-reading the pcap file in every thread (which was the old behaviour),
    this submits chunked tasks to reduce thread scheduling overhead. ThreadPoolExecutor
    handles work-stealing, so threads stay busy even if individual packets take different
    amounts of time (e.g. when active-recon network calls vary in latency).
    """
    # Always process when called; this function can be invoked from embedded/frozen contexts.
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

                    if processedPacketCount >= nextSnapshotPacketCount:
                        with allPacketInfoLock:
                            # Snapshot only when we are actually emitting progress,
                            # avoiding O(n) list copies on every completed batch.
                            allPacketInfoSnapshot = list(allPacketInfo)
                            processedPacketCount = len(allPacketInfoSnapshot)

                        while processedPacketCount >= nextSnapshotPacketCount:
                            snapshotStart = time.perf_counter()
                            if emitJsonSnapshots:
                                captureData = buildHostsPayload(allPacketInfoSnapshot, "")
                                emitBridgeProgress(
                                    f"in-memory://hosts-{nextSnapshotPacketCount}.json",
                                    nextSnapshotPacketCount,
                                    totalPackets,
                                    False,
                                    captureData,
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
                                )
                            perfSnapshotSeconds += time.perf_counter() - snapshotStart
                            perfSnapshotCount += 1
                            nextSnapshotPacketCount += hostChunkSize
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
    parser.add_argument("pcap_file", nargs="?", help="The .pcap file to parse.")
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
        help="Packet count per incremental hosts snapshot (default: 250).",
        type=int,
        default=250,
    )
    parser.add_argument(
        "--worker-threads",
        help="Number of backend worker threads (default: 2x CPU cores).",
        type=int,
        default=2 * (os.cpu_count() or 1),
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

    geoDbPath = scriptDir + "common/GeoLite2-City.mmdb"
    macVendorsPath = scriptDir + "common/mac-vendors-export.csv"
    icannCsvPath = scriptDir + "common/service-names-port-numbers.csv"

    if os.path.exists(geoDbPath):
        geoIpReader = geoip2.database.Reader(geoDbPath)
    else:
        print("[Main] Warning: GeoIP database not found at " + geoDbPath, file=sys.stderr)

    if os.path.exists(icannCsvPath):
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
            "[Main] Warning: ICANN port CSV not found at " + icannCsvPath,
            file=sys.stderr,
        )

    if os.path.exists(macVendorsPath):
        with open(macVendorsPath, newline="", encoding="utf-8") as csvFile:
            for csvRow in csv.DictReader(csvFile):
                if "Mac Prefix" in csvRow and "Vendor Name" in csvRow:
                    macVendorMap[csvRow["Mac Prefix"].upper()] = csvRow["Vendor Name"]
    else:
        print(
            "[Main] Warning: MAC vendor CSV not found at " + macVendorsPath,
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

    args = runArgs
    verbose = int(getattr(runArgs, "verbose", 0) or 0)
    hostChunkSize = max(1, int(getattr(runArgs, "host_chunk_size", 250) or 250))
    emitJsonSnapshots = bool(getattr(runArgs, "emit_json_snapshots", False))
    stopEvent.clear()

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

    processingCancelled = False
    try:
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
            emitBridgeProgress(
                "in-memory://hosts.json",
                len(finalPacketInfoSnapshot),
                totalPackets,
                True,
                captureData,
            )
        else:
            writeHostsSnapshot(outputDir, finalPacketInfoSnapshot, "", hostOutputFile)
            emitBridgeProgress(
                outputDir + "/" + hostOutputFile,
                len(finalPacketInfoSnapshot),
                totalPackets,
                True,
            )

    print(
        "[Main] Processing complete. Generated testcases and info files are located in: "
        + outputDir,
        file=sys.stderr,
    )

    return {
        "success": True,
        "cancelled": processingCancelled,
        "outputDir": outputDir,
        "processedPackets": len(finalPacketInfoSnapshot),
        "totalPackets": totalPackets,
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
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def beginNdjsonStream(self, statusCode=200):
        self.send_response(int(statusCode))
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
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

    def do_GET(self):
        parsedUrl = urlparse(self.path)
        queryParams = parse_qs(parsedUrl.query or "", keep_blank_values=False)

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
        self.sendJson(
            404,
            {
                "success": False,
                "error": "Not found",
            },
        )

    def do_POST(self):
        global progressEventCallback

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
                            "processing": processingLock.locked(),
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

            runArgs = argparse.Namespace(
                pcap_file=pcapPath,
                output=request.get("output") or "testcases",
                source_port=request.get("sourcePort"),
                dest_port=request.get("destPort"),
                timeout=int(request.get("timeout") or 3),
                active_recon=bool(request.get("activeRecon", True)),
                conf=request.get("conf"),
                host_chunk_size=int(
                    request.get("hostChunkSize") or _getRuntimeConfigSnapshot()["hostChunkSize"]
                ),
                worker_threads=int(
                    request.get("workerThreads") or _getRuntimeConfigSnapshot()["workerThreads"]
                ),
                emit_json_snapshots=bool(request.get("emitJsonSnapshots", False)),
                verbose=int(request.get("verbose") or 0),
                server=False,
                server_host="127.0.0.1",
                server_port=0,
            )

            progressQueue = queue.Queue()
            processingDone = threading.Event()
            resultHolder = {}

            def progressCallback(payload):
                progressQueue.put(
                    {
                        "type": "progress",
                        "path": payload.get("path"),
                        "processedPackets": payload.get("processedPackets", 0),
                        "totalPackets": payload.get("totalPackets", 0),
                        "complete": bool(payload.get("complete", False)),
                        "captureData": payload.get("captureData")
                        if isinstance(payload.get("captureData"), dict)
                        else None,
                    }
                )

            def workerRunCapture():
                global progressEventCallback
                try:
                    with processingLock:
                        previousProgressCallback = progressEventCallback
                        progressEventCallback = progressCallback
                        try:
                            resultHolder["result"] = runCaptureFromArgs(runArgs)
                        finally:
                            progressEventCallback = previousProgressCallback
                except Exception as runError:
                    resultHolder["error"] = runError
                    resultHolder["traceback"] = traceback.format_exc()
                finally:
                    processingDone.set()

            workerThread = threading.Thread(target=workerRunCapture, daemon=True)
            workerThread.start()

            self.beginNdjsonStream(200)

            while True:
                if processingDone.is_set() and progressQueue.empty():
                    break
                try:
                    progressEvent = progressQueue.get(timeout=0.2)
                except queue.Empty:
                    continue
                self.sendNdjsonLine(progressEvent)

            workerThread.join(timeout=0.1)

            if "error" in resultHolder:
                self.sendNdjsonLine(
                    {
                        "type": "error",
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
                    "success": bool(result.get("success")),
                    "cancelled": bool(result.get("cancelled", False)),
                    "error": result.get("error"),
                    "stdout": "",
                    "processedPackets": int(result.get("processedPackets") or 0),
                    "totalPackets": int(result.get("totalPackets") or 0),
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

    with ThreadedHttpServer((serverHost, int(serverPort)), SnitchHttpHandler) as server:
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
    finally:
        if geoIpReader is not None:
            try:
                geoIpReader.close()
            except Exception:
                pass

        logBackendShutdown(backendRuntimeMode, backendShutdownReason, exitCode)
    sys.exit(exitCode)
