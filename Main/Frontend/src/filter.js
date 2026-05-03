// Pre-compiled regex patterns for getDataType (avoid recompilation on every call)
const REGEX_IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const REGEX_HEX = /^0x[0-9a-fA-F]+$/;
const REGEX_MAC = /^([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}$/;
const REGEX_ASCII = /^[\x00-\x7F]*$/;

// Memoization cache for getLeafKeys to avoid recomputing for same packet structures
const leafKeysCache = new Map();
// Cache for normalized/original key maps per host
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

const getPacketKey = (p) => {
  const hostKey = Object.keys(p.Host)[0];
  const packetItem = p.Host[hostKey][0];
  return `${hostKey}-${packetItem['Packet Info']['Packet Processed']}`;
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

function filterChunk(data, filter) {
  const parsedHosts = typeof data === 'string' ? JSON.parse(data) : data;
  const matchedPackets = [];
  const comparisonOps = ['>=', '<=', '>', '<', '==', '!='];

  // Pre-parse filter once outside the loop
  if (!filter || !filter.includes(':')) return matchedPackets;
  const [filterKey, filterValRaw] = filter.split(':').map((s) => s.trim());
  const filterModifier = comparisonOps.find((m) => filterValRaw.includes(m));
  const filterValue = filterValRaw.replace(filterModifier, '').trim();
  const filterValueLower = filterValue.toLowerCase();
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

    const targetIdx = keyMap.normalized.indexOf(filterKey);
    if (targetIdx === -1) continue;
    const originalKey = keyMap.original[targetIdx];

    for (const packetItem of hostPackets) {
      const fieldValue = searchFullKey(packetItem, originalKey);
      if (fieldValue === undefined) continue;

      let matched = false;
      if (filterModifier) {
        matched = compare(fieldValue, filterValue, filterModifier);
      } else {
        matched = compare(fieldValue, filterValue, '==');
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
    let exprEnd = i;
    while (
      exprEnd < query.length &&
      !query.startsWith('||', exprEnd) &&
      !query.startsWith('&&', exprEnd) &&
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

function runQuery(data, query) {
  const tokenList = tokenizeQuery(query);
  let pos = 0;

  function peek() {
    return tokenList[pos];
  }
  function consume(type) {
    const currentToken = tokenList[pos];
    if (type && (!currentToken || currentToken.type !== type)) {
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

function filterPackets(data, query) {
  let matchedPackets;
  if (query.trim() === '') {
    // dummy function so we can return all packets in the right format
    matchedPackets = runQuery(data, 'wire-length:>=0'); // dummy filter that matches all packets
  } else {
    matchedPackets = runQuery(data, query);
  }

  return matchedPackets.map((p) => {
    const hostKey = Object.keys(p.Host)[0];
    return p.Host[hostKey][0];
  });
}

module.exports = { filterPackets, getDataType };
