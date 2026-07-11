import re
from urllib.parse import unquote_plus


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

# Matches common credential-related field names in HTTP query strings, POST bodies, etc.
CREDENTIAL_FIELD_RE = re.compile(
    r"^(?:.*[_\-.])?(?:pass(?:w(?:or)?d?)?|pw|secret|auth|auth_token|"
    r"credential|api[_\-.]?key|token|user(?:name)?|login|email)(?:[_\-.].*)?$",
    re.IGNORECASE,
)

_SENSITIVE_COOKIE_RE = re.compile(
    r"^(?:sess(?:ion)?(?:id)?|auth(?:_?token)?|access_token|refresh_token|"
    r"remember(?:_me)?(?:_token)?|jwt|bearer|csrf(?:_token)?|xsrf(?:_token)?|"
    r"sid|uid|user(?:id)?|login|pass(?:w(?:or)?d?)?|pw|secret|"
    r"PHPSESSID|ASP\.NET_SessionId|__Secure-.*|__Host-.*)$",
    re.IGNORECASE,
)

_CRED_KEYWORDS = (
    r"pass(?:w(?:or)?d?)?|pw|secret|auth|auth_token|credential|"
    r"api[_\-.]?key|token|user(?:name)?|login|email"
)
_JSON_CRED_RE = re.compile(
    r'"(?:(?:.*[_\-.])?' + r"(?:" + _CRED_KEYWORDS + r")" + r'(?:[_\-.].*)?)"'
    r'\s*:\s*"([^"]{1,512})"',
    re.IGNORECASE,
)

_TEXT_CRED_RE = re.compile(
    r"(?:^|[\s,{;&])"
    r"(?:(?:.*[_\-.])?(?:" + _CRED_KEYWORDS + r")(?:[_\-.].*)?)"
    r'(?:\s*[=:]\s*)([^\s&"\'<>,;]{1,512})',
    re.IGNORECASE | re.MULTILINE,
)


def _extractUrlCredentials(paramStr):
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


def _extractCookieCredentials(cookieHeader):
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
    if not setCookieHeader:
        return {}
    creds = {"set_cookie_raw": setCookieHeader}
    firstPair = setCookieHeader.split(";")[0].strip()
    if "=" in firstPair:
        name, _, value = firstPair.partition("=")
        name = name.strip()
        value = value.strip()
        if value:
            creds[f"cookie.{name}"] = value
    return creds


def _extractPostBodyCredentials(body, contentType):
    if not body or not body.strip():
        return {}
    creds = {}
    lowerContentType = contentType.lower()
    if "json" in lowerContentType:
        for match in _JSON_CRED_RE.finditer(body):
            val = match.group(1).strip()
            if val:
                fullMatch = match.group(0)
                keyEnd = fullMatch.index('"', 1)
                creds[fullMatch[1:keyEnd]] = val
    else:
        for match in _TEXT_CRED_RE.finditer(body):
            val = match.group(1).strip()
            if val:
                raw = match.group(0).lstrip(" \t,{;&")
                sep = next((i for i, c in enumerate(raw) if c in "=:"), len(raw))
                key = raw[:sep].strip()
                if key:
                    creds[key] = val
    return creds


def decodeHTTP(rawPayload):
    """
    Decode an HTTP request or response from raw payload bytes.
    """
    try:
        text = rawPayload.decode(errors="ignore")
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
            creds = {}
            if "?" in url:
                queryStr = url.split("?", 1)[1].split("#")[0]
                creds.update(_extractUrlCredentials(queryStr))
            authHeader = headers.get("authorization", "")
            if authHeader:
                creds["authorization"] = authHeader
            cookieHeader = headers.get("cookie", "")
            if cookieHeader:
                creds.update(_extractCookieCredentials(cookieHeader))
            contentType = headers.get("content-type", "")
            if method in ("POST", "PUT", "PATCH"):
                bodyStart = normalised.find("\n\n")
                if bodyStart != -1:
                    body = normalised[bodyStart + 2 :]
                    if body.strip():
                        if "urlencoded" in contentType.lower():
                            creds.update(_extractUrlCredentials(body))
                        else:
                            creds.update(_extractPostBodyCredentials(body, contentType))
            if creds:
                result["Credentials"] = creds
            return result

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
