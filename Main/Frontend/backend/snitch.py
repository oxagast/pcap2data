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
# Summaries and final reports can be generated using a large language model (LLM).
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
#   - Summarizes results using LLM integration (Ollama).
#   - Outputs consolidated JSON and summary files.
#
# Usage:
#   python3 snitch.py <pcap_file> [options]
#   See command-line argument parser below for available options.
#
# Dependencies:
#   - scapy, numpy, requests, chardet, geoip2, magic, yaml, ollama, bs4, scipy, etc.
#
# Author: oxagast oxagast
# Import standard and third-party libraries for argument parsing, file handling, networking, compression, and data processing
import argparse
import csv
import json
import os
import shutil
import socket
import ssl
import sys
import textwrap
import threading
import time
import zlib
from datetime import datetime
from decimal import Decimal
from functools import lru_cache
import chardet
import geoip2.database
import magic
import numpy as np
import ollama
import requests
import yaml

# from tqdm import tqdm
import ipaddress
from bs4 import BeautifulSoup
from ollama import ResponseError
from scipy.stats import entropy
from concurrent.futures import ThreadPoolExecutor, as_completed

stopEvent = threading.Event()

try:
    import scapy.all as scapy
except ImportError:
    import scapy

activeRecon = "False"
numWorkerThreads = 2 * (os.cpu_count() or 1)
numLlmThreads = 5
llmResponseLength = 100
llmModelName = "minimax-m2.5:cloud"
useLlm = False

# Shared result lists, protected by their respective locks so that threads
# can safely append results concurrently without data corruption.
llmSummaries = []
llmSummariesLock = threading.Lock()
allPacketInfo = []
allPacketInfoLock = threading.Lock()

# Concurrency controls
llmCallLock = threading.Semaphore(numLlmThreads)  # cap simultaneous LLM calls

hostOutputFile = "hosts.json"
currentDir = os.getcwd()
scriptDir = os.path.dirname(os.path.realpath(__file__)) + "/"

# --- Lookup tables loaded once at startup (see init_lookup_tables()) ---
# Keyed (port_int, "tcp"/"udp") -> description string
portDescriptionMap: dict = {}
# Keyed by uppercase MAC macPrefix (e.g. "00:1A:2B") -> vendor name
macVendorMap: dict = {}

# --- GeoIP reader opened once and reused across all packets ---
# Protected by geoIpCacheLock for the cache; the Reader itself is thread-safe.
geoIpReader = None
geoIpCache: dict = {}
geoIpCacheLock = threading.Lock()

# --- Banner cache: (ip, port) -> banner dict, avoids redundant socket probes ---
cachedBanners: dict = {}
cachedBannersLock = threading.Lock()

# --- HTTP method set used by decodeHTTP() for request-line detection ---
HTTP_METHODS: set = {
    "GET", "POST", "HEAD", "PUT", "DELETE", "PATCH",
    "OPTIONS", "TRACE", "CONNECT",
}


def llmQuery(packetInfoStr):
    """
    Query a large language model (LLM) with packet information for summarization.
    Handles retries and concurrency limits. Appends responses to the global llmSummaries list.
    """
    with llmCallLock:
        try:
            if ollama and useLlm and packetInfoStr:
                # Attempt up to 2 times with exponential backoff; halve the payload on each retry
                for retryCount in range(2):
                    try:
                        llmResponse = ollama.generate(
                            model=llmModelName,
                            prompt=f"Tell me what you can about the following network capture (encoded in json, from pcap), its payload, and any interesting or unusual traits... respond with a single paragraph around {llmResponseLength} words: {packetInfoStr}",
                        )
                        if llmResponse and "response" in llmResponse:
                            # Protect list append from concurrent thread writes
                            with llmSummariesLock:
                                llmSummaries.append(llmResponse["response"])
                        else:
                            return {"Summary": ""}
                    except ResponseError as responseErr:
                        if verbose >= 2:
                            print(
                                f"LLM API response error (attempt {retryCount + 1}/3): {str(responseErr)}",
                                file=sys.stderr,
                            )
                        time.sleep(2**retryCount)  # Exponential backoff
                        packetInfoStr = packetInfoStr[
                            : int(len(packetInfoStr) / (2**retryCount))
                        ]
                        if verbose >= 1:
                            print(
                                f"Retrying with truncated (halved) string (attempt {retryCount + 1}/3)...",
                                file=sys.stderr,
                            )
            else:
                return {"Summary": "LLM integration not enabled"}
        except Exception as e:
            return {"Summary": "LLM integration error: " + str(e)}


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


def getServBanner(ip, port, timeout, hostname):
    """
    Retrieve the service banner, SSL certificate, and page title for a given IP and port.
    Uses a dict cache keyed by (ip, port) to avoid redundant network probes.
    Handles both HTTP and HTTPS. Returns a dict with banner, page title, and encryption data.
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
        if port == 443:
            pageTitle = getPageTitle("https://" + hostname + ":" + str(port), timeout)
        else:
            pageTitle = getPageTitle("http://" + hostname + ":" + str(port), timeout)
    except Exception:
        pageTitle = "N/A"
    # Try to fetch SSL certificate info (ignore errors; port may not support TLS)
    try:
        tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpSocket.settimeout(timeout)
        sslContext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        sslContext.check_hostname = False
        sslContext.verify_mode = ssl.CERT_NONE
        sslSocket = sslContext.wrap_socket(tcpSocket, server_hostname=ip)
        sslSocket.connect((ip, port))
        if sslSocket:
            sslCert = sslSocket.getpeercert()
            cipherInfo = sslSocket.cipher()
            sslVersion = sslSocket.version()
        tcpSocket.close()
    except Exception:
        pass
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
            print("Error: Nonfatal: Could not create minor dir.")
    with open(destDir + "/pcap.data_packet." + str(index) + ".dat", "wb") as out:
        out.write(data)


def joinInfo(outputDirPath, portDir, index, dataTypeJson, packetInfoJson, host):
    """
    Merge packet-level info with extra analysis info and write as a JSON file.
    Thread-safe: uses allPacketInfoLock when appending to the shared allPacketInfo list.
    """
    mergedJson = {
        "Packet Info": json.loads(packetInfoJson),
        "Extra Info": json.loads(dataTypeJson),
    }
    path = outputDirPath + "/" + portDir + "/pcap.info_packet." + str(index) + ".json"
    with open(path, "wb+") as out:
        out.write(json.dumps(mergedJson).encode())
    if verbose >= 2:
        print(json.dumps(mergedJson, indent=2))
    # Protect the shared list from concurrent thread writes
    with allPacketInfoLock:
        allPacketInfo.append({"Host": host, "Packet": mergedJson})
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
                p["Packet Info"]["Packet Timestamp"], "%Y-%m-%d %H:%M:%S.%f"
            )
        )

        # Add chronological index
        for i, pkt in enumerate(packets, start=1):
            pkt["Packet Info"]["Index"] = i

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
        host = entry.get("Host")
        if host not in packetsByHost:
            packetsByHost[host] = []
        # Always append — previously the first packet per host was lost
        packetsByHost[host].append(entry.get("Packet"))

    packetsByHost = sortAndIndexPackets(packetsByHost)

    # Write the consolidated hosts file; use a context manager to guarantee flush/close
    with open(outputDirPath + "/" + hostOutputFile, "w+", encoding="utf-8") as f:
        f.write(
            json.dumps({"Host": packetsByHost, "Final Summary": finalSummary}, indent=2)
        )


@lru_cache(maxsize=4096)
def getNetclass(ip):
    """
    Determine the network class (A, B, C, or Unknown) of an IPv4 address.
    Cached to avoid repeated parsing of the same IP addresses.
    """
    ipAddressObj = ipaddress.ip_address(ip)
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


def getDatatypes(data, dstPort, sourceIp, destIp, timeout, protocol="tcp"):
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
    traitData = getTraits(data, dstPort, sourceIp, destIp, timeout, protocol)
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
        return serviceName
    except Exception:
        return "Unknown"


def getTraits(data, dstPort, sourceIp, destIp, timeout, protocol="tcp"):
    """
    Analyze data for entropy, charsetType, encoding, and network/server traits.
    Returns a dictionary with entropy, network data, length, server info, and character info.
    The protocol parameter ("tcp" or "udp") is used for port-description lookups so that
    UDP service names and descriptions are resolved correctly.
    """

    byteCounts = np.bincount(list(data))
    shannonEntropy = entropy(byteCounts, base=2)
    dataLength = len(data)
    protoName = getServ(dstPort, protocol)
    charsetType = "ascii" if all(32 <= b <= 126 for b in data) else "binary"
    uniqueCharCount = len(set(data))
    uniqueCharsSet = set(data)
    if activeRecon:
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
            "Source IP": {
                "Class": srcNetClass,
                "ip.src.class": srcNetClass,
                "Location": srcGeoInfo,
                "ip.src.location": srcGeoInfo,
            },
            "Destination IP": {
                "Class": dstNetClass,
                "ip.dst.class": dstNetClass,
                "Location": dstGeoInfo,
                "ip.dst.location": dstGeoInfo,
            },
            "Port Protcol": protoName,
            "tcp.proto": protoName,
            "Port Description": portDesc,
            "tcp.desc": portDesc,
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


def decodeSIP(rawPayload):
    """
    Decode SIP message fields from raw payload bytes.
    Parses the first line and common headers (From, To, Call-ID).
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
        if isSipRequest:
            parts = firstLine.split(" ", 2)
            method = parts[0]
            requestUri = parts[1] if len(parts) > 1 else "Unknown"
            return {
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
        else:
            parts = firstLine.split(" ", 2)
            statusCode = parts[1] if len(parts) > 1 else "Unknown"
            statusMsg = parts[2] if len(parts) > 2 else "Unknown"
            return {
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
        isHttpRequest = firstLine.split(" ")[0] in HTTP_METHODS if " " in firstLine else False
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
            return {
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
        else:
            parts = firstLine.split(" ", 2)
            httpVersion = parts[0]
            statusCode = parts[1] if len(parts) > 1 else "Unknown"
            statusMessage = parts[2] if len(parts) > 2 else "Unknown"
            return {
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
    except Exception:
        return None


def decodeFTP(rawPayload):
    """
    Decode FTP commands and responses from raw payload bytes.
    Returns a dict with Type (Command/Response), command/status, and argument/message,
    or None if the payload is not recognisable as FTP traffic.
    """
    FTP_COMMANDS = {
        "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN",
        "PORT", "PASV", "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU",
        "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD",
        "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP",
        "NOOP", "FEAT", "OPTS", "MLST", "MLSD", "SIZE", "MDTM", "EPRT",
        "EPSV", "AUTH", "PBSZ", "PROT",
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
            if word == "PASS":
                arg = "***"
            return {
                "Type": "Command",
                "ftp.type": "Command",
                "Command": word,
                "ftp.command": word,
                "Argument": arg,
                "ftp.argument": arg,
            }
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
        "EHLO", "HELO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN",
        "HELP", "NOOP", "QUIT", "AUTH", "STARTTLS", "BDAT",
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
            if word == "AUTH" and "PLAIN" in arg.upper():
                arg = arg.split(" ")[0] + " ***"
            return {
                "Type": "Command",
                "smtp.type": "Command",
                "Command": word,
                "smtp.command": word,
                "Argument": arg,
                "smtp.argument": arg,
            }
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
        "USER", "PASS", "APOP", "QUIT", "STAT", "LIST", "RETR", "DELE",
        "NOOP", "RSET", "TOP", "UIDL", "CAPA", "AUTH", "STLS",
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
            if word == "PASS":
                arg = "***"
            return {
                "Type": "Command",
                "pop3.type": "Command",
                "Command": word,
                "pop3.command": word,
                "Argument": arg,
                "pop3.argument": arg,
            }
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
        "CAPABILITY", "NOOP", "LOGOUT", "AUTHENTICATE", "LOGIN", "SELECT",
        "EXAMINE", "CREATE", "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE",
        "LIST", "LSUB", "STATUS", "APPEND", "CHECK", "CLOSE", "EXPUNGE",
        "SEARCH", "FETCH", "STORE", "COPY", "UID", "IDLE", "NAMESPACE",
        "STARTTLS", "ENABLE",
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
                if word == "LOGIN" and arg:
                    argParts = arg.split(" ", 1)
                    arg = argParts[0] + " ***" if len(argParts) > 1 else arg
                return {
                    "Type": "Command",
                    "imap.type": "Command",
                    "Tag": tag,
                    "imap.tag": tag,
                    "Command": word,
                    "imap.command": word,
                    "Argument": arg,
                    "imap.argument": arg,
                }
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
        0xF0: "SE",   0xF1: "NOP",  0xF2: "Data Mark",  0xF3: "Break",
        0xF4: "Interrupt Process",  0xF5: "Abort Output",
        0xF6: "Are You There",      0xF7: "Erase Character",
        0xF8: "Erase Line",         0xF9: "Go Ahead",
        0xFA: "SB",   0xFB: "WILL", 0xFC: "WONT",
        0xFD: "DO",   0xFE: "DONT", 0xFF: "IAC",
    }
    TELNET_OPTIONS = {
        0: "Binary",        1: "Echo",           2: "Reconnection",
        3: "Suppress GA",   5: "Status",         6: "Timing Mark",
        24: "Terminal Type",31: "Window Size",   32: "Terminal Speed",
        33: "Remote Flow",  34: "Linemode",      36: "Environment",
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
        return {
            "Negotiations": negotiations,
            "telnet.negotiations": negotiations,
            "Printable Text": printableText[:200] if printableText else "",
            "telnet.text": printableText[:200] if printableText else "",
        }
    except Exception:
        return None


def decodeIRC(rawPayload):
    """
    Decode IRC protocol messages from raw payload bytes.
    Parses prefix, command, and parameters per RFC 1459.
    Returns a dict with the IRC command and parameters, or None if not recognisable.
    """
    IRC_COMMANDS = {
        "NICK", "USER", "JOIN", "PART", "PRIVMSG", "NOTICE", "QUIT",
        "PING", "PONG", "MODE", "TOPIC", "NAMES", "LIST", "INVITE",
        "KICK", "WHOIS", "WHO", "WHOWAS", "MOTD", "LUSERS", "VERSION",
        "STATS", "LINKS", "TIME", "CONNECT", "TRACE", "ADMIN", "INFO",
        "SERVLIST", "SQUERY", "KILL", "PASS", "OPER", "REHASH", "DIE",
        "RESTART", "AWAY", "USERHOST", "ISON", "CAP", "AUTHENTICATE",
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
                messages.append({"Prefix": prefix, "Command": command, "Parameters": params})
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
        0x60: "BindRequest",      0x61: "BindResponse",
        0x62: "UnbindRequest",    0x63: "SearchRequest",
        0x64: "SearchResEntry",   0x65: "SearchResDone",
        0x66: "SearchResRef",     0x67: "ModifyRequest",
        0x68: "ModifyResponse",   0x69: "AddRequest",
        0x6A: "AddResponse",      0x6B: "DelRequest",
        0x6C: "DelResponse",      0x6D: "ModDNRequest",
        0x6E: "ModDNResponse",    0x6F: "CompareRequest",
        0x70: "CompareResponse",  0x77: "ExtendedRequest",
        0x78: "ExtendedResponse", 0x79: "IntermediateResponse",
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
        msgId = int.from_bytes(rawPayload[idx + 2: idx + 2 + idxLen], "big")
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
        0x00: "Sleep",      0x01: "Quit",           0x02: "Init DB",
        0x03: "Query",      0x04: "Field List",      0x05: "Create DB",
        0x06: "Drop DB",    0x07: "Refresh",         0x08: "Shutdown",
        0x09: "Statistics", 0x0A: "Process Info",    0x0B: "Connect",
        0x0C: "Process Kill",0x0D: "Debug",          0x0E: "Ping",
        0x0F: "Time",       0x10: "Delayed Insert",  0x11: "Change User",
        0x16: "Stmt Prepare",0x17: "Stmt Execute",   0x19: "Stmt Close",
        0x1A: "Stmt Reset", 0x1C: "Set Option",      0x1D: "Stmt Fetch",
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
            version = payload[1:versionEnd].decode(errors="ignore") if versionEnd > 1 else "Unknown"
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
            errCode = struct.unpack_from("<H", payload, 1)[0] if len(payload) >= 3 else 0
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
            query = payload[1:].decode(errors="ignore")[:200] if len(payload) > 1 else ""
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
        b"R": "Authentication",  b"K": "BackendKeyData",
        b"2": "BindComplete",    b"3": "CloseComplete",
        b"C": "CommandComplete", b"d": "CopyData",
        b"c": "CopyDone",        b"f": "CopyFail",
        b"G": "CopyInResponse",  b"H": "CopyOutResponse",
        b"D": "DataRow",         b"I": "EmptyQueryResponse",
        b"E": "ErrorResponse",   b"V": "FunctionCallResponse",
        b"n": "NoData",          b"N": "NoticeResponse",
        b"A": "NotificationResponse", b"t": "ParameterDescription",
        b"S": "ParameterStatus", b"1": "ParseComplete",
        b"s": "PortalSuspended", b"Z": "ReadyForQuery",
        b"T": "RowDescription",
    }
    PG_FRONTEND_TYPES = {
        b"B": "Bind",    b"C": "Close",   b"d": "CopyData",
        b"c": "CopyDone",b"f": "CopyFail",b"D": "Describe",
        b"E": "Execute", b"H": "Flush",   b"F": "FunctionCall",
        b"P": "Parse",   b"p": "Password",b"Q": "Query",
        b"S": "Sync",    b"X": "Terminate",
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
            body = rawPayload[5:5 + min(msgLen - 4, 200)].decode(errors="ignore") if msgLen > 4 else ""
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
            text.startswith("<?xml") or
            "<stream:stream" in text or
            text.startswith("<message") or
            text.startswith("<presence") or
            text.startswith("<iq ") or
            text.startswith("<iq>") or
            "<message " in text or
            "<presence" in text
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
        0x00: "CREATE_DIRECTORY",    0x01: "DELETE_DIRECTORY",
        0x02: "OPEN",                0x03: "CREATE",
        0x04: "CLOSE",               0x05: "FLUSH",
        0x06: "DELETE",              0x07: "RENAME",
        0x08: "QUERY_INFORMATION",   0x09: "SET_INFORMATION",
        0x0A: "READ",                0x0B: "WRITE",
        0x24: "LOCKING_ANDX",        0x25: "TRANSACTION",
        0x2D: "OPEN_ANDX",           0x2E: "READ_ANDX",
        0x2F: "WRITE_ANDX",          0x32: "TRANSACTION2",
        0x70: "TREE_CONNECT",        0x71: "TREE_DISCONNECT",
        0x72: "NEGOTIATE",           0x73: "SESSION_SETUP_ANDX",
        0x74: "LOGOFF_ANDX",         0x75: "TREE_CONNECT_ANDX",
        0xA0: "NT_TRANSACT",         0xA2: "NT_CREATE_ANDX",
        0xA4: "NT_CANCEL",           0xFE: "INVALID",
        0xFF: "NO_ANDX",
    }
    SMB2_COMMANDS = {
        0x0000: "NEGOTIATE",         0x0001: "SESSION_SETUP",
        0x0002: "LOGOFF",            0x0003: "TREE_CONNECT",
        0x0004: "TREE_DISCONNECT",   0x0005: "CREATE",
        0x0006: "CLOSE",             0x0007: "FLUSH",
        0x0008: "READ",              0x0009: "WRITE",
        0x000A: "LOCK",              0x000B: "IOCTL",
        0x000C: "CANCEL",            0x000D: "ECHO",
        0x000E: "QUERY_DIRECTORY",   0x000F: "CHANGE_NOTIFY",
        0x0010: "QUERY_INFO",        0x0011: "SET_INFO",
        0x0012: "OPLOCK_BREAK",
    }
    try:
        if len(rawPayload) < 8:
            return None
        if rawPayload[:4] == b"\xFF\x53\x4D\x42":
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
        if rawPayload[:4] == b"\xFE\x53\x4D\x42":
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
        1: "CONNECT",     2: "CONNACK",    3: "PUBLISH",
        4: "PUBACK",      5: "PUBREC",     6: "PUBREL",
        7: "PUBCOMP",     8: "SUBSCRIBE",  9: "SUBACK",
        10: "UNSUBSCRIBE",11: "UNSUBACK",  12: "PINGREQ",
        13: "PINGRESP",   14: "DISCONNECT",
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
                topic = rawPayload[idx + 2: idx + 2 + topicLen].decode(errors="ignore")
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
        "OPTIONS", "DESCRIBE", "ANNOUNCE", "SETUP", "PLAY", "PAUSE",
        "RECORD", "TEARDOWN", "GET_PARAMETER", "SET_PARAMETER", "REDIRECT",
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
        isRtspRequest = firstLine.split(" ")[0].upper() in RTSP_METHODS if " " in firstLine else False
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
        0: "Not defined",         1: "File not found",
        2: "Access violation",    3: "Disk full",
        4: "Illegal operation",   5: "Unknown TID",
        6: "File already exists", 7: "No such user",
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
            filename = rest[:nullIdx].decode(errors="ignore") if nullIdx >= 0 else rest.decode(errors="ignore")
            modeStart = nullIdx + 1 if nullIdx >= 0 else len(rest)
            modeEnd = rest.find(b"\x00", modeStart)
            mode = rest[modeStart:modeEnd].decode(errors="ignore") if modeEnd > modeStart else "Unknown"
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
        1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH",
    }
    BGP_ERRORS = {
        1: "Message Header Error", 2: "OPEN Message Error",
        3: "UPDATE Message Error", 4: "Hold Timer Expired",
        5: "Finite State Machine Error", 6: "Cease",
    }
    try:
        if len(rawPayload) < 19:
            return None
        if rawPayload[:16] != b"\xFF" * 16:
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
        0x0: "DATA",        0x1: "HEADERS",      0x2: "PRIORITY",
        0x3: "RST_STREAM",  0x4: "SETTINGS",     0x5: "PUSH_PROMISE",
        0x6: "PING",        0x7: "GOAWAY",        0x8: "WINDOW_UPDATE",
        0x9: "CONTINUATION",
    }
    HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    try:
        if len(rawPayload) < 9:
            return None
        hasPreface = rawPayload.startswith(HTTP2_PREFACE)
        offset = len(HTTP2_PREFACE) if hasPreface else 0
        if offset + 9 > len(rawPayload):
            if hasPreface:
                return {
                    "Connection Preface": True,
                    "http2.preface": True,
                    "Frame Type": "N/A",
                    "http2.frame_type": "N/A",
                }
            return None
        frameLen = struct.unpack_from(">I", b"\x00" + rawPayload[offset:offset + 3])[0]
        frameType = rawPayload[offset + 3]
        frameFlags = rawPayload[offset + 4]
        streamId = struct.unpack_from(">I", rawPayload, offset + 5)[0] & 0x7FFFFFFF
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


def decodeNNTP(rawPayload):
    """
    Decode NNTP (Network News Transfer Protocol) commands and responses.
    Returns a dict with Type (Command/Response), command/status, and message,
    or None if the payload is not recognisable as NNTP traffic.
    """
    NNTP_COMMANDS = {
        "ARTICLE", "BODY", "DATE", "GROUP", "HDR", "HEAD",
        "HELP", "IHAVE", "LAST", "LIST", "LISTGROUP", "MODE",
        "NEWGROUPS", "NEWNEWS", "NEXT", "OVER", "POST", "QUIT",
        "READER", "STAT", "AUTHINFO", "COMPRESS",
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
        1: "Access-Request",      2: "Access-Accept",
        3: "Access-Reject",       4: "Accounting-Request",
        5: "Accounting-Response", 11: "Access-Challenge",
        12: "Status-Server",      13: "Status-Client",
        255: "Reserved",
    }
    RADIUS_ATTRIBUTES = {
        1: "User-Name",           2: "User-Password",
        3: "CHAP-Password",       4: "NAS-IP-Address",
        5: "NAS-Port",            6: "Service-Type",
        7: "Framed-Protocol",     8: "Framed-IP-Address",
        18: "Reply-Message",      24: "State",
        25: "Class",              26: "Vendor-Specific",
        27: "Session-Timeout",    28: "Idle-Timeout",
        30: "Called-Station-Id",  31: "Calling-Station-Id",
        32: "NAS-Identifier",     40: "Acct-Status-Type",
        41: "Acct-Delay-Time",    42: "Acct-Input-Octets",
        43: "Acct-Output-Octets", 44: "Acct-Session-Id",
        61: "NAS-Port-Type",      77: "Connect-Info",
        79: "EAP-Message",        80: "Message-Authenticator",
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
            attrValue = rawPayload[idx + 2: idx + attrLen]
            attrName = RADIUS_ATTRIBUTES.get(attrType, f"Attr-{attrType}")
            if attrType == 1:
                attrValueStr = attrValue.decode(errors="ignore")
            elif attrType in (4, 8):
                attrValueStr = ".".join(str(b) for b in attrValue) if len(attrValue) == 4 else attrValue.hex()
            elif attrType in (2, 3):
                attrValueStr = "***"
            else:
                attrValueStr = attrValue.decode(errors="ignore") if all(32 <= b <= 126 for b in attrValue) else attrValue.hex()
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


def packetLoop(p, packetIndex, srcPortFilter, dstPortFilter, timeout):
    """
    Process a single scapy packet: extract TCP, UDP, or ICMP payload, write the raw
    testcase file, gather analysis data (MIME, entropy, geoip, etc.) and merge
    everything into a single JSON output file.  For UDP packets on port 53 the DNS
    layer is decoded.  SNMP (161/162), DHCP (67/68), NTP/SNTP (123), and SIP (5060/5061)
    packets are also decoded and included in the output.  HTTP (any port whose payload
    looks like HTTP) and HTTP/2 (connection preface or binary frames) are decoded for
    both requests and responses.  FTP (20/21), SMTP (25/587/465), POP3/POP (110/995),
    IMAP/IMAP4 (143/993), Telnet (23), IRC (6667-6669), MTP (1755), LDAP (389/636),
    MySQL (3306), PostgreSQL (5432), XMPP (5222/5223), SMB (139/445), MQTT (1883/8883),
    RTSP (554), TFTP (UDP 69), BGP (179), NNTP (119), and RADIUS (1812/1813/1645/1646)
    are also decoded.  ICMP packets are fully supported as a separate transport type.

    packetIndex is the 0-based position of this packet in the full capture, used as
    the filename index so files from concurrent threads do not collide.
    Returns the merged info dict, or None if the packet should be skipped.
    """
    srcMacAddr = p.src if p.haslayer("Ethernet") else "N/A"
    dstMacAddr = p.dst if p.haslayer("Ethernet") else "N/A"
    srcMacVendor = macAddrToVendor(srcMacAddr) if srcMacAddr != "N/A" else "N/A"
    dstMacVendor = macAddrToVendor(dstMacAddr) if dstMacAddr != "N/A" else "N/A"
    if not p.haslayer("IP"):
        return None

    isTcp = p.haslayer("TCP")
    isUdp = p.haslayer("UDP")
    isIcmp = p.haslayer("ICMP")
    if not isTcp and not isUdp and not isIcmp:
        return None

    if isTcp:
        rawPayload = p["TCP"].payload.original
        srcPort = p["TCP"].sport
        dstPort = p["TCP"].dport
        transportProtocol = "tcp"
        dstPortStr = str(dstPort)
    elif isUdp:
        rawPayload = p["UDP"].payload.original
        srcPort = p["UDP"].sport
        dstPort = p["UDP"].dport
        transportProtocol = "udp"
        dstPortStr = str(dstPort)
    else:
        # ICMP: use the full ICMP layer bytes as the payload
        rawPayload = bytes(p["ICMP"])
        srcPort = 0
        dstPort = 0
        transportProtocol = "icmp"
        dstPortStr = "icmp"

    if (srcPortFilter is None or srcPort == srcPortFilter) and (
        dstPortFilter is None or dstPort == dstPortFilter
    ):
        if rawPayload is not None and len(rawPayload) > 0:
            writeTestcase(rawPayload, outputDir, dstPortStr, packetIndex)
            dataTypeInfo = getDatatypes(
                rawPayload,
                dstPort,
                p["IP"].src,
                p["IP"].dst,
                timeout,
                transportProtocol,
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
                    "Source port": int(srcPort),
                    "tcp.src.port": int(srcPort),
                    "Destination port": int(dstPort),
                    "tcp.dst.port": int(dstPort),
                    "TCP checksum": hex(int(p["TCP"].chksum)),
                    "tcp.chksum": hex(int(p["TCP"].chksum)),
                    "Urgent flag": bool(p["TCP"].urgptr),
                    "tcp.urgptr": bool(p["TCP"].urgptr),
                    "TCP Flag Data": {
                        "Flags": tcpFlags if tcpFlags else "None",
                        "tcp.flags": tcpFlags if tcpFlags else "None",
                    },
                    "Options": list(p["TCP"].options),
                    "tcp.options": list(p["TCP"].options),
                    "TCP layer length": int(p["TCP"].dataofs * 4),
                    "tcp.len": int(p["TCP"].dataofs * 4),
                    "Wire length": len(p["TCP"]),
                    "wire.len": len(p["TCP"]),
                }
                # Decode SIP on TCP ports 5060/5061
                if dstPort in (5060, 5061) or srcPort in (5060, 5061):
                    sipSection = decodeSIP(rawPayload)
                    if sipSection is not None:
                        transportSection["SIP"] = sipSection
                # Decode SNMP on TCP port 161/162 (less common but valid)
                if dstPort in (161, 162) or srcPort in (161, 162):
                    snmpSection = decodeSNMP(p)
                    if snmpSection is not None:
                        transportSection["SNMP"] = snmpSection
                # Decode HTTP on any TCP port — decodeHTTP() returns None for non-HTTP payloads
                httpSection = decodeHTTP(rawPayload)
                if httpSection is not None:
                    transportSection["HTTP"] = httpSection
                # Decode HTTP/2 on any TCP port (preface or binary frame detection)
                http2Section = decodeHTTP2(rawPayload)
                if http2Section is not None:
                    transportSection["HTTP2"] = http2Section
                # Decode FTP on TCP ports 20/21
                if dstPort in (20, 21) or srcPort in (20, 21):
                    ftpSection = decodeFTP(rawPayload)
                    if ftpSection is not None:
                        transportSection["FTP"] = ftpSection
                # Decode SMTP on TCP ports 25/587/465
                if dstPort in (25, 587, 465) or srcPort in (25, 587, 465):
                    smtpSection = decodeSMTP(rawPayload)
                    if smtpSection is not None:
                        transportSection["SMTP"] = smtpSection
                # Decode POP3/POP on TCP ports 110/995
                if dstPort in (110, 995) or srcPort in (110, 995):
                    pop3Section = decodePOP3(rawPayload)
                    if pop3Section is not None:
                        transportSection["POP3"] = pop3Section
                # Decode IMAP/IMAP4 on TCP ports 143/993
                if dstPort in (143, 993) or srcPort in (143, 993):
                    imapSection = decodeIMAP(rawPayload)
                    if imapSection is not None:
                        transportSection["IMAP"] = imapSection
                # Decode Telnet on TCP port 23
                if dstPort == 23 or srcPort == 23:
                    telnetSection = decodeTelnet(rawPayload)
                    if telnetSection is not None:
                        transportSection["Telnet"] = telnetSection
                # Decode IRC on TCP ports 6667/6668/6669
                if dstPort in (6667, 6668, 6669) or srcPort in (6667, 6668, 6669):
                    ircSection = decodeIRC(rawPayload)
                    if ircSection is not None:
                        transportSection["IRC"] = ircSection
                # Decode MTP/MMS on TCP port 1755
                if dstPort == 1755 or srcPort == 1755:
                    mtpSection = decodeMTP(rawPayload)
                    if mtpSection is not None:
                        transportSection["MTP"] = mtpSection
                # Decode LDAP on TCP ports 389/636
                if dstPort in (389, 636) or srcPort in (389, 636):
                    ldapSection = decodeLDAP(rawPayload)
                    if ldapSection is not None:
                        transportSection["LDAP"] = ldapSection
                # Decode MySQL on TCP port 3306
                if dstPort == 3306 or srcPort == 3306:
                    mysqlSection = decodeMySQL(rawPayload)
                    if mysqlSection is not None:
                        transportSection["MySQL"] = mysqlSection
                # Decode PostgreSQL on TCP port 5432
                if dstPort == 5432 or srcPort == 5432:
                    pgSection = decodePostgreSQL(rawPayload)
                    if pgSection is not None:
                        transportSection["PostgreSQL"] = pgSection
                # Decode XMPP on TCP ports 5222/5223
                if dstPort in (5222, 5223) or srcPort in (5222, 5223):
                    xmppSection = decodeXMPP(rawPayload)
                    if xmppSection is not None:
                        transportSection["XMPP"] = xmppSection
                # Decode SMB on TCP ports 139/445
                if dstPort in (139, 445) or srcPort in (139, 445):
                    smbSection = decodeSMB(rawPayload)
                    if smbSection is not None:
                        transportSection["SMB"] = smbSection
                # Decode MQTT on TCP ports 1883/8883
                if dstPort in (1883, 8883) or srcPort in (1883, 8883):
                    mqttSection = decodeMQTT(rawPayload)
                    if mqttSection is not None:
                        transportSection["MQTT"] = mqttSection
                # Decode RTSP on TCP port 554
                if dstPort == 554 or srcPort == 554:
                    rtspSection = decodeRTSP(rawPayload)
                    if rtspSection is not None:
                        transportSection["RTSP"] = rtspSection
                # Decode BGP on TCP port 179
                if dstPort == 179 or srcPort == 179:
                    bgpSection = decodeBGP(rawPayload)
                    if bgpSection is not None:
                        transportSection["BGP"] = bgpSection
                # Decode NNTP on TCP port 119
                if dstPort == 119 or srcPort == 119:
                    nntpSection = decodeNNTP(rawPayload)
                    if nntpSection is not None:
                        transportSection["NNTP"] = nntpSection
                # Decode RADIUS on TCP ports 1812/1813/1645/1646 (RFC 6614 defines RADIUS over TCP)
                if dstPort in (1812, 1813, 1645, 1646) or srcPort in (1812, 1813, 1645, 1646):
                    radiusSection = decodeRADIUS(rawPayload)
                    if radiusSection is not None:
                        transportSection["RADIUS"] = radiusSection
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
                    "Source port": int(srcPort),
                    "udp.src.port": int(srcPort),
                    "Destination port": int(dstPort),
                    "udp.dst.port": int(dstPort),
                    "UDP checksum": hex(int(p["UDP"].chksum)),
                    "udp.chksum": hex(int(p["UDP"].chksum)),
                    "UDP length": int(p["UDP"].len),
                    "udp.len": int(p["UDP"].len),
                    "Wire length": len(p["UDP"]),
                    "wire.len": len(p["UDP"]),
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
                if dstPort in (1812, 1813, 1645, 1646) or srcPort in (1812, 1813, 1645, 1646):
                    radiusSection = decodeRADIUS(rawPayload)
                    if radiusSection is not None:
                        transportSection["RADIUS"] = radiusSection
                protocolKey = "UDP"
            else:
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
                    "Wire length": len(p["ICMP"]),
                    "wire.len": len(p["ICMP"]),
                }
                protocolKey = "ICMP"

            packetInfo = {
                "Packet Processed": int(packetIndex),
                "Packet Timestamp": timestamp,
                "packet.timestamp": timestamp,
                "Protocol": protocolKey,
                "packet.proto": protocolKey,
                # Include Ethernet MAC data when at least one IP is local (private),
                # so that mixed private+internet traffic still exposes the local device's MAC.
                "Ethernet Frame": {
                    "MAC Source": srcMacAddr,
                    "ether.src.mac.addr": srcMacAddr,
                    "MAC Destination": dstMacAddr,
                    "ether.dst.mac.addr": dstMacAddr,
                    "MAC Source Vendor": srcMacVendor,
                    "ether.src.mac.vendor": srcMacVendor,
                    "MAC Destination Vendor": dstMacVendor,
                    "ether.dst.mac.vendor": dstMacVendor,
                }
                if (
                    srcGeoInfo.get("Location") == "Localnet"
                    or dstGeoInfo.get("Location") == "Localnet"
                )
                else "N/A",
                "IP": {
                    "Source IP": str(p["IP"].src),
                    "ip.src.addr": str(p["IP"].src),
                    "Destination IP": str(p["IP"].dst),
                    "ip.dst.addr": str(p["IP"].dst),
                    "IP Checksum": hex(int(p["IP"].chksum)),
                    "ip.chksum": hex(int(p["IP"].chksum)),
                    "IP layer length": int(p["IP"].len),
                    "ip.len": int(p["IP"].len),
                },
                protocolKey: transportSection,
                "Raw data": {
                    "Payload": {
                        "Hex Encoded": rawPayload.hex(),
                        "payload.hex": rawPayload.hex(),
                        "ASCII Encoded": rawPayload.decode(errors="ignore"),
                        "payload.ascii": rawPayload.decode(errors="ignore"),
                    },
                    "Packet": bytes(p).hex(),
                    "packet.hex": bytes(p).hex(),
                    "Payload Length": len(rawPayload),
                    "payload.len": len(rawPayload),
                },
            }
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


llmSummariesBatch = []


def infoDistiller(batchSize):
    """
    lines: iterable of input data
    worker_fn: function that takes a list (batch) and processes it
    batchSize: number of items per batch
    maxWorkers: number of threads
    """
    print("Starting LLM calls...")
    maxWorkers = 4
    jsonStack = allPacketInfo

    def chunker(iterable, size):
        for i in range(0, len(iterable), size):
            yield iterable[i : i + size]

    packetBatches = list(chunker(jsonStack, batchSize))
    results = []

    with ThreadPoolExecutor(max_workers=maxWorkers) as executor:
        taskFutures = [executor.submit(llmBrief, batch) for batch in packetBatches]

        for future in as_completed(taskFutures):
            try:
                results.append(future.result())
            except Exception as e:
                print(f"Batch failed: {e}")

    return results


def popDictKey(obj, keyToRemove):
    if isinstance(obj, dict):
        # Create a new dict to avoid modifying while iterating
        return {
            k: popDictKey(v, keyToRemove) for k, v in obj.items() if k != keyToRemove
        }
    elif isinstance(obj, list):
        return [popDictKey(item, keyToRemove) for item in obj]
    else:
        return obj


def llmBrief(jsonBatch):
    """
    Strip raw payload bytes (to keep the prompt short) and send a batch of packet
    metadata to the LLM for summarisation.  Appends the response to llmSummaries.
    """
    strippedJson = popDictKey(jsonBatch, "Raw data")
    packetInfoStr = json.dumps(strippedJson)
    llmResponse = ollama.generate(
        model=llmModelName,
        prompt="Provide a concise summary of the following packets, in paragraph form, limited to three paragraphs: "
        + packetInfoStr,
    )
    if llmResponse and "response" in llmResponse:
        with llmSummariesLock:
            llmSummaries.append(llmResponse["response"])
        return llmResponse["response"]


def startThreading():
    """
    Process all TCP, UDP, and ICMP packets from the pre-loaded `packets` list using a
    ThreadPoolExecutor with chunked processing for reduced overhead.

    Rather than re-reading the pcap file in every thread (which was the old behaviour),
    this submits chunked tasks to reduce thread scheduling overhead. ThreadPoolExecutor
    handles work-stealing, so threads stay busy even if individual packets take different
    amounts of time (e.g. when active-recon network calls vary in latency).
    """
    if __name__ == "__main__":
        print(
            f"Spooling up {numWorkerThreads} worker threads to process {totalPackets} packets...",
            file=sys.stderr,
        )
        # Build the list of packet indices that belong to TCP, UDP, or ICMP packets
        packetIndices = [
            i
            for i, p in enumerate(packets)
            if p.haslayer("TCP") or p.haslayer("UDP") or p.haslayer("ICMP")
        ]

        # Chunk packets to reduce thread scheduling overhead
        chunkSize = max(1, len(packetIndices) // (numWorkerThreads * 4))
        packetChunks = [
            packetIndices[i:i + chunkSize]
            for i in range(0, len(packetIndices), chunkSize)
        ]

        def processChunk(chunk):
            """Process a chunk of packet indices."""
            results = []
            for idx in chunk:
                if stopEvent.is_set():
                    break
                result = processPacketAtIndex(idx, args.source_port, args.dest_port, args.timeout)
                if result:
                    results.append(result)
            return results

        with ThreadPoolExecutor(max_workers=numWorkerThreads) as executor:
            taskFutures = {
                executor.submit(processChunk, chunk): chunk
                for chunk in packetChunks
            }
            for future in as_completed(taskFutures):
                if stopEvent.is_set():
                    break
                try:
                    future.result()
                except Exception as exc:
                    if verbose >= 1:
                        print(
                            f"Packet {taskFutures[future]} raised an exception: {exc}",
                            file=sys.stderr,
                        )


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
with additional network and server information.  A full capture summary is generated
using a large language model to provide insights into the data.
        Outputs:
          - Testcase files: outputDirPath/<dest_port>/pcap.data_packet.<index>.dat
          - Testcase info: outputDirPath/<dest_port>/pcap.info_packet.<index>.json
          - all_testcases_info.json: a consolidated file with info for the entire
            capture.
                                 """,
    ),
    epilog="Example usage: \n   python3 snitch.py traffic.pcap -o outputDirPath -s 80 -d 8080 -T 5 -a",
)  # ignore fstring
parser.add_argument("pcap_file", help="The .pcap file to parse.")
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
    "-v",
    "--verbose",
    help="Enable verbose output for debugging.",
    action="count",
    default=0,
)
parser.add_argument(
    "--nollm",
    help="Disable LLM summarisation regardless of configuration.",
    action="store_true",
)
verbose = parser.parse_args().verbose
args = parser.parse_args()  # parse once; verbose is needed by functions defined above
try:
    config = configLoader(args.conf if args.conf else "conf.yaml")
    # this next exception handles if ther is no config file
    # these are default opts that should work decently
except Exception:
    config = {
        "active_recon": True,
        "ollama": {
            "use_llm": True,
            "llm_brief": True,
            "model": "minimax-m2.5:cloud",
            "response_length": 340,
            "server_call_threads": 5,
            "batch_size": 65,
        },
        "threads": 16,
        "final_summary": True,
    }
pcapFilePath = args.pcap_file
geoDbPath = scriptDir + "common/GeoLite2-City.mmdb"
macVendorsPath = scriptDir + "common/mac-vendors-export.csv"
icannCsvPath = scriptDir + "common/service-names-port-numbers.csv"

# --- Open the GeoIP database once for the lifetime of the process.
# The geoip2 Reader is documented as thread-safe for concurrent city() calls.
if os.path.exists(geoDbPath):
    geoIpReader = geoip2.database.Reader(geoDbPath)
else:
    print("Warning: GeoIP database not found at " + geoDbPath, file=sys.stderr)

# --- Load ICANN port-description CSV into a dict for O(1) per-packet lookups.
# Without this, every call to getPortDescription() would scan the full CSV.
if os.path.exists(icannCsvPath):
    with open(icannCsvPath, newline="", encoding="utf-8") as csvFile:
        for csvRow in csv.DictReader(csvFile):
            try:
                portNum = int(csvRow.get("Port Number", ""))
                protoStr = csvRow.get("Transport Protocol", "").strip().lower()
                portDescription = csvRow.get("Description", "No description available")
                if portNum and protoStr:
                    portDescriptionMap[(portNum, protoStr)] = portDescription
            except (ValueError, TypeError):
                pass
else:
    print("Warning: ICANN port CSV not found at " + icannCsvPath, file=sys.stderr)

# --- Load MAC vendor CSV into a dict for O(1) per-packet lookups.
# Without this, every call to macAddrToVendor() would scan the full CSV.
if os.path.exists(macVendorsPath):
    with open(macVendorsPath, newline="", encoding="utf-8") as csvFile:
        for csvRow in csv.DictReader(csvFile):
            if "Mac Prefix" in csvRow and "Vendor Name" in csvRow:
                macVendorMap[csvRow["Mac Prefix"].upper()] = csvRow["Vendor Name"]
else:
    print("Warning: MAC vendor CSV not found at " + macVendorsPath, file=sys.stderr)

totalPackets = 0
packets = scapy.rdpcap(args.pcap_file)  # type: ignore
allPacketCount = len(packets)
llmBatchSize = 0
totalPackets = len(
    [p for p in packets if p.haslayer("TCP") or p.haslayer("UDP") or p.haslayer("ICMP")]
)
if totalPackets == 0:
    print("No TCP, UDP, or ICMP packets found in the capture.", file=sys.stderr)
    sys.exit(1)
if "threads" in config and config["threads"]:
    numWorkerThreads = config["threads"]
outputDir = currentDir + "/" + "testcases"
if args.output and args.output != "testcases":
    outputDir = args.output
    print("Using output directory: " + args.output, file=sys.stderr)
if "output_dir" in config:
    outputDir = currentDir + "/" + config["output_dir"]
    print("Using output directory from config: " + outputDir, file=sys.stderr)
if not args.active_recon:
    if config["active_recon"]:
        activeRecon = config["active_recon"]
    else:
        activeRecon = False
if "ollama" in config and config["ollama"].get("model"):
    if config["ollama"].get("use_llm", False) and verbose >= 1:
        print(
            "LLM integration enabled. Using model: " + config["ollama"]["model"] + ".",
            file=sys.stderr,
        )
        llmModelName = config["ollama"]["model"]
        if config["ollama"]["llm_brief"]:
            print(
                "LLM brief generation enabled. Only packet metadata will be sent through the LLM.",
                file=sys.stderr,
            )
        else:
            print(
                "LLM brief generation disabled. LLM will be used for full data packets!  This will take significantly more time, but will provide more detailed llmSummaries for each packet.",
                file=sys.stderr,
            )
    llmResponseLength = config["ollama"].get("response_length", 200)
    llmBatchSize = config["ollama"].get("batch_size", 65)
    useLlm = config["ollama"].get("use_llm", False)
if args.nollm:
    useLlm = False
    config = {
        "active_recon": True,
        "ollama": {
            "use_llm": False,
            "llm_brief": False,
        },
        "threads": 16,
        "final_summary": False,
    }


if llmModelName and useLlm:
    if llmModelName.endswith(":cloud"):
        if verbose >= 2:
            print(
                "Using cloud-based LLM model: "
                + "minimax-m2.5:cloud"  # doesn't need to be that fast, but has to look decent
                + ". Ensure you have network connectivity and API access.",
                file=sys.stderr,
            )
print(
    "Preparing to process "
    + str(totalPackets)
    + " TCP/UDP/ICMP packets with "
    + str(numWorkerThreads)
    + " threads.",
    file=sys.stderr,
)
if not os.path.exists(args.pcap_file):
    print("The .pcap file does not exist.", file=sys.stderr)
    sys.exit(1)
try:
    if os.path.isdir(outputDir):
        shutil.rmtree(outputDir, ignore_errors=True)
    # Small delay to ensure file system has completed deletions
    time.sleep(1)
    os.makedirs(outputDir, exist_ok=True)
    try:
        threadingResult = startThreading()
    except Exception as startErr:
        print(
            f"Warning: startThreading raised an exception ({startErr}); retrying.",
            file=sys.stderr,
        )
        threadingResult = startThreading()
finally:
    finalSummary = ""
    if config["ollama"]["llm_brief"] != True and useLlm:
        infoDistiller(llmBatchSize)
    else:
        # Strip raw payload bytes before sending to the LLM to keep the prompt small,
        # then restore the full allPacketInfo for the hosts.json output.
        allPacketInfoBackup = allPacketInfo.copy()
        strippedPacketInfo = popDictKey(allPacketInfo, "Raw data")
        allPacketInfo = strippedPacketInfo
        if allPacketInfo and useLlm:
            print("Generating LLM brief for batch of packets...")
            infoDistiller(50)
        allPacketInfo = allPacketInfoBackup

    if config.get("final_summary", True) and config["ollama"].get("use_llm", True):
        joinedSummaries = (
            " ".join(llmSummaries) if llmSummaries else "No LLM summaries generated."
        )
        try:
            finalLlmResponse = ollama.generate(
                model=llmModelName,
                prompt="Provide a concise summary of the following packets, in paragraph form, limited to three paragraphs: "
                + joinedSummaries,
            )
            finalSummary = finalLlmResponse["response"]
            with open(
                outputDir + "/final_summary.txt", "w", encoding="utf-8"
            ) as summaryFile:
                summaryFile.write(finalSummary)
            print("\n" + finalSummary)
            print("\nFinal summary saved to: " + outputDir + "/final_summary.txt")
        except Exception as e:
            print("\nLLM Final summary generation error: " + str(e))

    # Always write hosts.json so the frontend can load data regardless of
    # whether LLM summarisation was enabled or succeeded.
    byHost(outputDir, finalSummary)

    # Close the GeoIP reader now that all packets have been processed
    if geoIpReader is not None:
        geoIpReader.close()

    print(
        "Processing complete. Generated testcases and info files are located in: "
        + outputDir,
        file=sys.stderr,
    )

    sys.exit(0)
