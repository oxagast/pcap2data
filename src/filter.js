// Evaluates packet filter expressions and resolves frontend query aliases.



// Core constants and low-level utilities.
const threadName = "Filter";
const REGEX_IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const REGEX_HEX = /^0x[0-9a-fA-F]+$/;
const REGEX_MAC = /^([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}$/;
const REGEX_ASCII = /^[\x00-\x7F]*$/;
const wildcardCache = new Map();

function wildcardMatch(value, pattern) {
  let regex = wildcardCache.get(pattern);

  if (!regex) {
    const escaped = pattern.replace(
      /[.+?^${}()|[\]\\]/g,
      '\\$&',
    );

    regex = new RegExp(
      '^' +
      escaped
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.') +
      '$',
      'i',
    );

    wildcardCache.set(pattern, regex);
  }

  return regex.test(String(value));
}
function writeLogEntry(message) {
  console.log(message);
}

// Cache for normalized/original key maps per host.
const keyMapCache = new Map();

const operators = {
  '==': (a, b) => a == b,
  '!=': (a, b) => a != b,
  '>=': (a, b) => a >= b,
  '>': (a, b) => a > b,
  '<=': (a, b) => a <= b,
  '<': (a, b) => a < b,
};

const compare = (a, b, op) => (operators[op] || operators['=='])(a, b);

// Packet shape helpers: support both normalized and legacy session keys.
function getPacketInfo(packetItem) {
  return packetItem?.['packet.info'] ?? packetItem?.['Packet Info'] ?? {};
}

function getExtraInfo(packetItem) {
  return packetItem?.['extra.info'] ?? packetItem?.['Extra Info'] ?? {};
}

function getNetworkData(packetItem) {
  return getExtraInfo(packetItem)?.['Traits']?.['Network Data'] ?? {};
}

const getPacketKey = (p) => {
  const hostKey = Object.keys(p.Host)[0];
  const packetItem = p.Host[hostKey][0];
  const packetInfo = getPacketInfo(packetItem);
  return `${hostKey}-${packetInfo['packet.processed'] ?? packetInfo['Packet Processed']}`;
};

const unionBy = (arr, keyFn) => {
  const map = new Map();
  for (const item of arr) map.set(keyFn(item), item);
  return [...map.values()];
};

const intersectBy = (a, b, keyFn) => {
  const setB = new Set(b.map(keyFn));
  return a.filter((item) => setB.has(keyFn(item)));
};

const subtractBy = (source, excluded, keyFn) => {
  const excludedSet = new Set(excluded.map(keyFn));
  return source.filter((item) => !excludedSet.has(keyFn(item)));
};

function getAllPackets(data) {
  const parsedHosts = typeof data === 'string' ? JSON.parse(data) : data;
  const allPackets = [];
  if (!parsedHosts?.Host) return allPackets;

  for (const host in parsedHosts.Host) {
    const hostPackets = parsedHosts.Host[host];
    if (!Array.isArray(hostPackets)) continue;
    for (const packetItem of hostPackets) {
      allPackets.push({ Host: { [host]: [packetItem] } });
    }
  }

  return allPackets;
}

function getDataType(data) {
  if (REGEX_IPV4.test(data)) return 'IP';
  if (REGEX_HEX.test(data)) return 'HEX';
  if (REGEX_MAC.test(data)) return 'MAC';
  if (Number.isInteger(data)) return 'INT';
  if (typeof data === 'number') return 'FLOAT';
  if (typeof data === 'string' && REGEX_ASCII.test(data)) return 'ASCII';
  return 'BIN';
}

function searchFullKey(obj, targetKey) {
  for (const objKey in obj) {
    if (objKey === targetKey) return obj[objKey];
    const val = obj[objKey];
    if (val && typeof val === 'object') {
      const res = searchFullKey(val, targetKey);
      if (res !== undefined) return res;
    }
  }
}

function getLeafKeys(obj) {
  const result = [];
  const walk = (o) => {
    for (const objKey in o) {
      const val = o[objKey];

      if (val && typeof val === 'object' && !Array.isArray(val)) {
        walk(val);
      } else {
        result.push({
          [objKey]: objKey.toLowerCase().replace(/ /g, '-'),
          type: getDataType(val),
        });
      }
    }
  };

  walk(obj);
  return result;
}

function normalizeFilterKey(key) {
  return key.toLowerCase().replace(/[._\s-]+/g, '-');
}

function searchNormalizedKey(obj, normalizedTargetKey) {
  if (!obj || typeof obj !== 'object') return undefined;

  const stack = [obj];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;

    if (Array.isArray(current)) {
      for (const item of current) {
        if (item && typeof item === 'object') {
          stack.push(item);
        }
      }
      continue;
    }

    for (const [objKey, value] of Object.entries(current)) {
      if (normalizeFilterKey(objKey) === normalizedTargetKey) {
        return value;
      }
      if (value && typeof value === 'object') {
        stack.push(value);
      }
    }
  }

  return undefined;
}

function isUnknownLikeProtocolLabel(value) {
  const normalized = String(value ?? '').trim().toLowerCase();
  return (
    normalized === '' ||
    normalized === 'unknown' ||
    normalized === 'unknown protocol' ||
    normalized === 'n/a' ||
    normalized === 'na' ||
    normalized === 'none'
  );
}

// Alias resolution and key normalization for query expressions.
function getAliasedFieldValue(packetItem, normalizedKey) {
  const packetInfo = getPacketInfo(packetItem);
  const extraInfo = getExtraInfo(packetItem);
  const networkData = getNetworkData(packetItem);

  switch (normalizedKey) {
    case 'transport-proto': {
      const explicitTransport = searchFullKey(packetItem, 'transport.proto');
      if (
        explicitTransport !== undefined &&
        String(explicitTransport).trim() !== ''
      ) {
        return explicitTransport;
      }

      const explicitProtocol = packetInfo['packet.proto'] ?? packetInfo['Protocol'];
      if (typeof explicitProtocol === 'string' && explicitProtocol) {
        const normalizedProtocol = explicitProtocol.trim().toUpperCase();
        const isGenericProtocol =
          normalizedProtocol === 'FRAME' ||
          normalizedProtocol === 'UNKNOWN PROTOCOL' ||
          normalizedProtocol === 'UNKNOWN';
        if (!isGenericProtocol) {
          return explicitProtocol;
        }
      }
      if (packetInfo['TCP']) return 'TCP';
      if (packetInfo['UDP']) return 'UDP';
      if (packetInfo['SCTP']) return 'SCTP';
      if (packetInfo['ICMP']) return 'ICMP';
      if (packetInfo['IGMP']) return 'IGMP';
      return undefined;
    }
    case 'application-proto': {
      const explicitApplicationProtocol =
        searchFullKey(packetItem, 'application.proto') ??
        searchFullKey(packetItem, 'app.proto');
      const networkApplicationProtocol =
        networkData?.['Port Protocol'] ??
        networkData?.['Port Protcol'];

      const explicitNormalized = String(
        explicitApplicationProtocol ?? ''
      ).trim().toLowerCase();
      const networkNormalized = String(
        networkApplicationProtocol ?? ''
      ).trim().toLowerCase();

      if (
        !isUnknownLikeProtocolLabel(networkApplicationProtocol) &&
        !isUnknownLikeProtocolLabel(explicitApplicationProtocol) &&
        explicitNormalized &&
        networkNormalized &&
        explicitNormalized !== networkNormalized
      ) {
        // When legacy and explicit app-protocol labels disagree, prefer
        // network-layer protocol labeling used across Host Data/List views.
        return networkApplicationProtocol;
      }

      if (!isUnknownLikeProtocolLabel(explicitApplicationProtocol)) {
        return explicitApplicationProtocol;
      }
      if (!isUnknownLikeProtocolLabel(networkApplicationProtocol)) {
        return networkApplicationProtocol;
      }
      return explicitApplicationProtocol ?? networkApplicationProtocol;
    }
    case 'link-proto':
      return searchFullKey(packetItem, 'link.proto');
    case 'network-proto':
      return searchFullKey(packetItem, 'network.proto');
    case 'tcp-src-port':
      return (
        searchFullKey(packetItem, 'tcp.src.port') ??
        searchFullKey(packetItem, 'transport.tcp.src.port') ??
        packetInfo?.['TCP']?.['Source port']
      );
    case 'tcp-dst-port':
      return (
        searchFullKey(packetItem, 'tcp.dst.port') ??
        searchFullKey(packetItem, 'transport.tcp.dst.port') ??
        packetInfo?.['TCP']?.['Destination port']
      );
    case 'udp-src-port':
      return (
        searchFullKey(packetItem, 'udp.src.port') ??
        searchFullKey(packetItem, 'transport.udp.src.port') ??
        packetInfo?.['UDP']?.['Source port']
      );
    case 'udp-dst-port':
      return (
        searchFullKey(packetItem, 'udp.dst.port') ??
        searchFullKey(packetItem, 'transport.udp.dst.port') ??
        packetInfo?.['UDP']?.['Destination port']
      );
    case 'sctp-src-port':
      return (
        searchFullKey(packetItem, 'sctp.src.port') ??
        packetInfo?.['SCTP']?.['Source port']
      );
    case 'sctp-dst-port':
      return (
        searchFullKey(packetItem, 'sctp.dst.port') ??
        packetInfo?.['SCTP']?.['Destination port']
      );
    case 'loc-src-city':
      return (
        searchFullKey(packetItem, 'loc.src.city') ??
        networkData?.['ip.src']?.['Location']?.['City'] ??
        networkData?.['Source IP']?.['Location']?.['City']
      );
    case 'loc-dst-city':
      return (
        searchFullKey(packetItem, 'loc.dst.city') ??
        networkData?.['ip.dst']?.['Location']?.['City'] ??
        networkData?.['Destination IP']?.['Location']?.['City']
      );
    case 'loc-src-country':
      return (
        searchFullKey(packetItem, 'loc.src.country') ??
        networkData?.['ip.src']?.['Location']?.['Country'] ??
        networkData?.['Source IP']?.['Location']?.['Country']
      );
    case 'loc-dst-country':
      return (
        searchFullKey(packetItem, 'loc.dst.country') ??
        networkData?.['ip.dst']?.['Location']?.['Country'] ??
        networkData?.['Destination IP']?.['Location']?.['Country']
      );
    case 'loc-src-postal':
      return (
        searchFullKey(packetItem, 'loc.src.postal') ??
        networkData?.['ip.src']?.['Location']?.['Postal'] ??
        networkData?.['Source IP']?.['Location']?.['Postal']
      );
    case 'loc-dst-postal':
      return (
        searchFullKey(packetItem, 'loc.dst.postal') ??
        networkData?.['ip.dst']?.['Location']?.['Postal'] ??
        networkData?.['Destination IP']?.['Location']?.['Postal']
      );
    case 'loc-src-tz':
    case 'loc-src-timezone':
      return (
        searchFullKey(packetItem, 'loc.src.tz') ??
        searchFullKey(packetItem, 'loc.src.timezone') ??
        networkData?.['ip.src']?.['Location']?.['Time Zone'] ??
        networkData?.['Source IP']?.['Location']?.['Time Zone']
      );
    case 'loc-dst-tz':
    case 'loc-dst-timezone':
      return (
        searchFullKey(packetItem, 'loc.dst.tz') ??
        searchFullKey(packetItem, 'loc.dst.timezone') ??
        networkData?.['ip.dst']?.['Location']?.['Time Zone'] ??
        networkData?.['Destination IP']?.['Location']?.['Time Zone']
      );
    case 'wire-proto': {
      const explicitProtocol = packetInfo['packet.proto'] ?? packetInfo['Protocol'];
      if (typeof explicitProtocol === 'string') {
        return explicitProtocol.toLowerCase();
      }
      if (packetInfo['TCP']) return 'tcp';
      if (packetInfo['UDP']) return 'udp';
      if (packetInfo['ICMP']) return 'icmp';
      return undefined;
    }
    case 'eth-src-vendor':
      return (
        packetInfo?.['Ethernet Frame']?.['MAC Source Vendor'] ??
        packetInfo?.['Ethernet Frame']?.['ether.src.mac.vendor']
      );
    case 'mime-type':
      return (
        extraInfo?.['MIME Type'] ??
        extraInfo?.['payload.mime']
      );
    case 'dns-qname': {
      const aliasHostnames =
        networkData?.['Hostnames']?.['Hostnames'];
      const dnsQname = searchFullKey(packetItem, 'dns.qname');
      const dnsQnames = searchFullKey(packetItem, 'dns.qnames');
      return [aliasHostnames, dnsQname, dnsQnames]
        .flat()
        .filter((value) => typeof value === 'string');
    }
    case 'decoded-proto': {
      const decodedValues = new Set();
      const wireProto = packetInfo['packet.proto'] ?? packetInfo['Protocol'];
      if (typeof wireProto === 'string' && wireProto) decodedValues.add(wireProto);

      const decodedList =
        packetInfo['packet.decoded_protocols'] ||
        packetInfo['Decoded Protocols'] ||
        packetInfo?.['Link Control']?.['Detected Protocols'] ||
        packetInfo?.['Link Control']?.['wan.detected'];
      if (Array.isArray(decodedList)) {
        decodedList.forEach((value) => {
          if (typeof value === 'string' && value) decodedValues.add(value);
        });
      }

      const transportSections = ['TCP', 'UDP', 'SCTP', 'ICMP', 'IGMP', 'LINK'];
      transportSections.forEach((sectionName) => {
        const section = packetInfo?.[sectionName];
        if (!section || typeof section !== 'object') return;
        Object.entries(section).forEach(([fieldName, fieldValue]) => {
          if (fieldName.includes('.')) return;
          if (typeof fieldValue === 'object' && fieldValue !== null) {
            decodedValues.add(fieldName);
          }
        });
      });

      return [...decodedValues];
    }
    case 'arp-op':
      return searchFullKey(packetItem, 'arp.op') ?? searchFullKey(packetItem, 'rarp.op');
    case 'rarp-op':
      return searchFullKey(packetItem, 'rarp.op') ?? searchFullKey(packetItem, 'arp.op');
    case 'arp-src-ip':
      return searchFullKey(packetItem, 'arp.src.ip') ?? searchFullKey(packetItem, 'rarp.src.ip');
    case 'arp-dst-ip':
      return searchFullKey(packetItem, 'arp.dst.ip') ?? searchFullKey(packetItem, 'rarp.dst.ip');
    case 'arp-src-mac':
      return searchFullKey(packetItem, 'arp.src.mac') ?? searchFullKey(packetItem, 'rarp.src.mac');
    case 'arp-dst-mac':
      return searchFullKey(packetItem, 'arp.dst.mac') ?? searchFullKey(packetItem, 'rarp.dst.mac');
    default:
      return undefined;
  }
}

function filterChunk(data, filter) {
  const parsedHosts = typeof data === 'string' ? JSON.parse(data) : data;
  const matchedPackets = [];
  const comparisonOps = ['>=', '<=', '>', '<', '==', '!='];

  // Pre-parse filter once outside the loop
  if (!filter || !filter.includes(':')) return matchedPackets;
  const [filterKey, filterValRaw] = filter.split(':').map((s) => s.trim());
  const normalizedFilterKey = normalizeFilterKey(filterKey);
  const filterModifier = comparisonOps.find((m) => filterValRaw.includes(m));
  const filterValue = filterValRaw.replace(filterModifier, '').trim();
  const filterValueLower = filterValue.toLowerCase();
  const hasWildcard =
    filterValue.includes('*') ||
    filterValue.includes('?');
  const isStringFilter = ['ASCII', 'HEX', 'IP', 'MAC'].includes(getDataType(filterValue));

  for (const host in parsedHosts.Host) {
    const hostPackets = parsedHosts.Host[host];
    const firstPacket = hostPackets[0];

    // Use cached key maps per host to avoid recomputing
    let keyMap = keyMapCache.get(host);
    if (!keyMap) {
      const leafKeyList = getLeafKeys(firstPacket);
      keyMap = {
        normalized: leafKeyList.map((k) => Object.values(k)[0]),
        original: leafKeyList.map((k) => Object.keys(k)[0]),
      };
      keyMapCache.set(host, keyMap);
    }

    const targetIdx = keyMap.normalized.findIndex(
      (candidateKey) => normalizeFilterKey(candidateKey) === normalizedFilterKey,
    );
    const originalKey = targetIdx === -1 ? null : keyMap.original[targetIdx];

    for (const packetItem of hostPackets) {
      let fieldValue = getAliasedFieldValue(packetItem, normalizedFilterKey);
      if (fieldValue === undefined && originalKey) {
        fieldValue = searchFullKey(packetItem, originalKey);
      }
      if (fieldValue === undefined) {
        fieldValue = searchNormalizedKey(packetItem, normalizedFilterKey);
      }
      if (fieldValue === undefined) continue;

      let matched = false;

      /* if (
        !filterModifier &&
        ['dns-qname', 'eth-src-vendor', 'mime-type', 'decoded-proto', 'arp-op', 'rarp-op'].includes(normalizedFilterKey)
      ) {
        const textValues = Array.isArray(fieldValue) ? fieldValue : [fieldValue];
        matched = textValues.some(
          (value) =>
            typeof value === 'string' &&
            value.toLowerCase().includes(filterValueLower),
        );
      } else {
 */
      if (
        !filterModifier &&
        ['dns-qname', 'eth-src-vendor', 'mime-type', 'decoded-proto', 'arp-op', 'rarp-op']
          .includes(normalizedFilterKey)
      ) {
        const textValues = Array.isArray(fieldValue)
          ? fieldValue
          : [fieldValue];

        matched = textValues.some((value) => {
          if (typeof value !== 'string') return false;

          return hasWildcard
            ? wildcardMatch(value, filterValue)
            : value.toLowerCase().includes(filterValueLower);
        });
      } else {

        if (filterModifier) {
          matched = compare(fieldValue, filterValue, filterModifier);
        } else {
          //matched = compare(fieldValue, filterValue, '==');
          if (
            hasWildcard &&
            typeof fieldValue === 'string'
          ) {
            matched = wildcardMatch(fieldValue, filterValue);
          } else {
            matched = compare(fieldValue, filterValue, '==');
          }
        }
      }

      if (!matched && isStringFilter) {
        const type = getDataType(fieldValue);
        if (['ASCII', 'HEX', 'IP', 'MAC'].includes(type)) {
          matched = String(fieldValue).toLowerCase() === filterValueLower;
        }
      }

      if (matched) {
        matchedPackets.push({ Host: { [host]: [packetItem] } });
      }
    }
  }
  return matchedPackets;
}

// Query parser and validator.
function tokenizeQuery(query) {
  const tokenList = [];
  let i = 0;
  while (i < query.length) {
    if (/\s/.test(query[i])) {
      i++;
      continue;
    }
    if (query[i] === '(') {
      tokenList.push({ type: 'LPAREN' });
      i++;
      continue;
    }
    if (query[i] === ')') {
      tokenList.push({ type: 'RPAREN' });
      i++;
      continue;
    }
    if (query.startsWith('||', i)) {
      tokenList.push({ type: 'OR' });
      i += 2;
      continue;
    }
    if (query.startsWith('&&', i)) {
      tokenList.push({ type: 'AND' });
      i += 2;
      continue;
    }
    if (query[i] === '!' && query[i + 1] !== '=') {
      tokenList.push({ type: 'NOT' });
      i++;
      continue;
    }
    let exprEnd = i;
    while (
      exprEnd < query.length &&
      !query.startsWith('||', exprEnd) &&
      !query.startsWith('&&', exprEnd) &&
      !(query[exprEnd] === '!' && query[exprEnd + 1] !== '=') &&
      query[exprEnd] !== '(' &&
      query[exprEnd] !== ')'
    ) {
      exprEnd++;
    }
    const tokenExpr = query.slice(i, exprEnd).trim();
    if (tokenExpr) tokenList.push({ type: 'EXPR', value: tokenExpr });
    i = exprEnd;
  }
  return tokenList;
}

function validateFilterExpression(expression) {
  if (typeof expression !== 'string') {
    writeLogEntry(`[${threadName}] Invalid filter expression type: expected string but got ${typeof expression}`);
    throw new Error('Filter expression must be text');
  }

  const separatorIndex = expression.indexOf(':');
  if (separatorIndex === -1) {
    writeLogEntry(`[${threadName}] Missing ":" in expression "${expression.trim()}"`);
    throw new Error(`Missing ":" in expression "${expression.trim()}"`);
  }

  const filterKey = expression.slice(0, separatorIndex).trim();
  const filterValue = expression.slice(separatorIndex + 1).trim();

  if (!filterKey) {
    writeLogEntry(`[${threadName}] Missing filter field before ":" in "${expression.trim()}"`);
    throw new Error(`Missing filter field before ":" in "${expression.trim()}"`);
  }
  if (!filterValue) {
    writeLogEntry(`[${threadName}] Missing filter value after ":" in "${expression.trim()}"`);
    throw new Error(`Missing filter value after ":" in "${expression.trim()}"`);
  }
}

function validateFilterSyntax(query) {
  const normalizedQuery = typeof query === 'string' ? query.trim() : '';
  if (!normalizedQuery) return true;

  const tokenList = tokenizeQuery(normalizedQuery);
  let pos = 0;

  function peek() {
    return tokenList[pos];
  }

  function consume(type) {
    const currentToken = tokenList[pos];
    if (type && (!currentToken || currentToken.type !== type)) {
      writeLogEntry(`[${threadName}] Expected ${type} but got ${currentToken ? currentToken.type : 'EOF'}`);
      throw new Error(
        `Expected ${type} but got ${currentToken ? currentToken.type : 'EOF'}`,
      );
    }
    pos++;
    return currentToken;
  }

  function parseOr() {
    parseAnd();
    while (peek() && peek().type === 'OR') {
      consume('OR');
      parseAnd();
    }
  }

  function parseAnd() {
    parseTerm();
    while (peek() && peek().type === 'AND') {
      consume('AND');
      parseTerm();
    }
  }

  function parseTerm() {
    const currentToken = peek();
    if (!currentToken) {
      writeLogEntry(`[${threadName}] Unexpected end of query`);
      throw new Error('Unexpected end of query');
    }
    if (currentToken.type === 'NOT') {
      consume('NOT');
      if (!peek()) {
        writeLogEntry(`[${threadName}] Expected expression or group after !`);
        throw new Error('Expected expression or group after !');
      }
      parseTerm();
      return;
    }
    if (currentToken.type === 'LPAREN') {
      consume('LPAREN');
      if (peek()?.type === 'RPAREN') {
        writeLogEntry(`[${threadName}] Empty parentheses are not allowed`);
        throw new Error('Empty parentheses are not allowed');
      }
      parseOr();
      if (!peek() || peek().type !== 'RPAREN') {
        writeLogEntry(`[${threadName}] Missing closing parenthesis`);
        throw new Error('Missing closing parenthesis');
      }
      consume('RPAREN');
      return;
    }
    if (currentToken.type === 'EXPR') {
      consume('EXPR');
      validateFilterExpression(currentToken.value);
      return;
    }
    if (currentToken.type === 'RPAREN') {
      writeLogEntry(`[${threadName}] Unexpected closing parenthesis`);
      throw new Error('Unexpected closing parenthesis');
    }
    if (currentToken.type === 'AND' || currentToken.type === 'OR') {
      writeLogEntry(`[${threadName}] Unexpected operator ${currentToken.type}`);
      throw new Error(`Unexpected operator ${currentToken.type}`);
    }
    writeLogEntry(`[${threadName}] Unexpected token ${currentToken.type}`);
    throw new Error(`Unexpected token ${currentToken.type}`);
  }

  parseOr();
  if (pos < tokenList.length) {
    const remainingToken = tokenList[pos];
    if (remainingToken.type === 'RPAREN') {
      writeLogEntry(`[${threadName}] Unexpected closing parenthesis`);
      throw new Error('Unexpected closing parenthesis');
    }
    writeLogEntry(`[${threadName}] Unexpected token ${remainingToken.type}`);
    throw new Error(`Unexpected token ${remainingToken.type}`);
  }
  return true;
}

function runQuery(data, query) {
  const tokenList = tokenizeQuery(query);
  const allPackets = getAllPackets(data);
  let pos = 0;

  function peek() {
    return tokenList[pos];
  }
  function consume(type) {
    const currentToken = tokenList[pos];
    if (type && (!currentToken || currentToken.type !== type)) {
      writeLogEntry(`[${threadName}] Expected ${type} but got ${currentToken ? currentToken.type : 'EOF'}`);
      throw new Error(
        `Expected ${type} but got ${currentToken ? currentToken.type : 'EOF'}`,
      );
    }
    pos++;
    return currentToken;
  }

  function parseOr() {
    let result = parseAnd();
    while (peek() && peek().type === 'OR') {
      consume('OR');
      const rightResult = parseAnd();
      result = unionBy([...result, ...rightResult], getPacketKey);
    }
    return result;
  }

  function parseAnd() {
    let result = parseTerm();
    while (peek() && peek().type === 'AND') {
      consume('AND');
      const rightResult = parseTerm();
      result = intersectBy(result, rightResult, getPacketKey);
    }
    return result;
  }

  function parseTerm() {
    const currentToken = peek();
    if (currentToken && currentToken.type === 'NOT') {
      consume('NOT');
      if (!peek()) {
        writeLogEntry(`[${threadName}] Expected expression or group after !`);
        throw new Error('Expected expression or group after !');
      }
      const negatedResult = parseTerm();
      return subtractBy(allPackets, negatedResult, getPacketKey);
    }
    if (currentToken && currentToken.type === 'LPAREN') {
      consume('LPAREN');
      const result = parseOr();
      consume('RPAREN');
      return result;
    }
    if (currentToken && currentToken.type === 'EXPR') {
      consume('EXPR');
      return filterChunk(data, currentToken.value);
    }
    return [];
  }

  return parseOr();
}

// Public entry point.
function filterPackets(data, query) {
  let matchedPackets;
  if (query.trim() === '') {
    // dummy function so we can return all packets in the right format
    matchedPackets = runQuery(data, 'wire-length:>=0'); // dummy filter that matches all packets
  } else {
    validateFilterSyntax(query);
    matchedPackets = runQuery(data, query);
  }

  return matchedPackets.map((p) => {
    const hostKey = Object.keys(p.Host)[0];
    return p.Host[hostKey][0];
  });
}

module.exports = { filterPackets, getDataType, validateFilterSyntax };
