function dotField(data, dotKey, legacyKey, fallback = '—') {
  if (!data) return fallback;
  const value = data[dotKey] ?? (legacyKey ? data[legacyKey] : undefined);
  return value === undefined || value === null || value === '' ? fallback : value;
}

function createTable(data, headers, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  // Use DocumentFragment for batched DOM insertion
  const fragment = document.createDocumentFragment();

  const table = document.createElement('table');
  const headerRow = document.createElement('tr');
  for (let i = 0; i < headers.length; i++) {
    const th = document.createElement('th');
    th.textContent = headers[i];
    headerRow.appendChild(th);
  }
  table.appendChild(headerRow);

  // Build all rows first, then append once
  for (let i = 0; i < data.length; i++) {
    const item = data[i];
    const row = document.createElement('tr');
    const values = Object.values(item);
    for (let j = 0; j < values.length; j++) {
      const td = document.createElement('td');
      td.textContent = values[j];
      row.appendChild(td);
    }
    table.appendChild(row);
  }

  fragment.appendChild(table);
  container.appendChild(fragment);
}

module.exports = {
  dotField,
  createTable,
};
