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
from urllib.parse import parse_qs, urlparse
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

backendDir = os.path.dirname(os.path.realpath(__file__))
if backendDir not in sys.path:
    sys.path.insert(0, backendDir)

import decoders.address_resolution as dec_address_resolution
import decoders.bgp as dec_bgp
import decoders.dhcp as dec_dhcp
import decoders.ftp as dec_ftp
import decoders.http as dec_http
import decoders.http2 as dec_http2
import decoders.igmp as dec_igmp
import decoders.imap as dec_imap
import decoders.irc as dec_irc
import decoders.kerberos as dec_kerberos
import decoders.ldap as dec_ldap
import decoders.mqtt as dec_mqtt
import decoders.mtp as dec_mtp
import decoders.mysql as dec_mysql
import decoders.nfs as dec_nfs
import decoders.nntp as dec_nntp
import decoders.ntp as dec_ntp
import decoders.pop3 as dec_pop3
import decoders.postgresql as dec_postgresql
import decoders.radius as dec_radius
import decoders.rtsp as dec_rtsp
import decoders.sctp as dec_sctp
import decoders.sip as dec_sip
import decoders.smb as dec_smb
import decoders.smtp as dec_smtp
import decoders.snmp as dec_snmp
import decoders.ssh as dec_ssh
import decoders.telnet as dec_telnet
import decoders.tftp as dec_tftp
import decoders.wan_link as dec_wan_link
import decoders.websocket as dec_websocket
import decoders.xmpp as dec_xmpp

activeRecon = "False"
numWorkerThreads = 2 * (os.cpu_count() or 1)
isSSH = False
checkTor = True
torJsonData = {}
torNetworkIps = {}
# Shared result lists, protected by their respective locks so that threads
# can safely append results concurrently without data corruption.
allPacketInfo = []
allPacketInfoLock = threading.Lock()

hostOutputFile = "hosts.json"
DEFAULT_HOST_CHUNK_SIZE = 2000
hostChunkSize = DEFAULT_HOST_CHUNK_SIZE
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
        headers={
            "Accept": "application/json",
            "User-Agent": f"PacketSnitch/{PACKETSNITCH_VERSION}",
        },
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
            headers={
                "Accept": "application/json",
                "User-Agent": f"PacketSnitch/{PACKETSNITCH_VERSION}",
            },
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


def extractLinkLayerInfo(p):
    """
    Return normalized link-layer metadata for Ethernet and Linux cooked packets.
    Returns a dict with keys: linkProto, srcAddr, dstAddr, linuxCooked.
    """
    etherClass = getattr(scapy, "Ether", None)
    if (etherClass and p.haslayer(etherClass)) or p.haslayer("Ether"):
        etherLayer = p[etherClass] if etherClass and p.haslayer(etherClass) else p["Ether"]
        return {
            "linkProto": "Ethernet",
            "srcAddr": str(getattr(etherLayer, "src", "N/A") or "N/A"),
            "dstAddr": str(getattr(etherLayer, "dst", "N/A") or "N/A"),
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
    linkLayerInfo = extractLinkLayerInfo(p)
    linkProto = linkLayerInfo["linkProto"]
    srcMacAddr = linkLayerInfo["srcAddr"]
    dstMacAddr = linkLayerInfo["dstAddr"]
    linuxCookedSection = linkLayerInfo["linuxCooked"]
    srcMacVendor = macAddrToVendor(srcMacAddr) if srcMacAddr != "N/A" else "N/A"
    dstMacVendor = macAddrToVendor(dstMacAddr) if dstMacAddr != "N/A" else "N/A"
    isSSH = False
    wanLinkSection = dec_wan_link.decodeWanLinkProtocols(p)

    # Decode ARP/RARP packets that do not carry an IP layer.
    if not p.haslayer("IP"):
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
                    snmpSection = dec_snmp.decodeSNMP(p)
                    if snmpSection is not None:
                        transportSection["SNMP"] = snmpSection
                # Decode DHCP on UDP ports 67/68
                if dstPort in (67, 68) or srcPort in (67, 68):
                    dhcpSection = dec_dhcp.decodeDHCP(p)
                    if dhcpSection is not None:
                        transportSection["DHCP"] = dhcpSection
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
                transportSection = dec_igmp.decodeIGMP(p, rawPayload)
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

            if linuxCookedSection is not None:
                packetInfo["Linux Cooked"] = linuxCookedSection
            if checkTor:
                if p["IP"].dst in torNetworkIps:
                    torInfo = torNetworkIps[p["IP"].dst]
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
    global checkTor
    global torJsonData
    global torNetworkIps

    args = runArgs
    verbose = int(getattr(runArgs, "verbose", 0) or 0)
    hostChunkSize = _coercePositiveInt(
        getattr(runArgs, "host_chunk_size", DEFAULT_HOST_CHUNK_SIZE),
        DEFAULT_HOST_CHUNK_SIZE,
    )
    emitJsonSnapshots = bool(getattr(runArgs, "emit_json_snapshots", False))
    stopEvent.clear()

    checkTor = bool(getattr(args, "use_tor_check", True))
    torJsonData = {}
    torNetworkIps = {}
    if checkTor:
        try:
            torResponse = requests.get(
                "https://onionoo.torproject.org/details?running=true&flag=Exit&fields=nickname,or_addresses,platform",
                timeout=25,
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
                use_tor_check=bool(request.get("useTorCheck", True)),
                conf=request.get("conf"),
                host_chunk_size=_coercePositiveInt(
                    request.get("hostChunkSize"),
                    _getRuntimeConfigSnapshot()["hostChunkSize"],
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
