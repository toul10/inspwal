const fs = require("fs");
const path = require("path");

const FILE = path.join(__dirname, "blob_index.json");

function loadIndex() {
  try {
    const raw = fs.readFileSync(FILE, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

function saveIndex(rows) {
  fs.writeFileSync(FILE, JSON.stringify(rows, null, 2));
}

async function saveRow(row) {
  const rows = loadIndex();
  if (!rows.find((r) => r.blob_id_decimal === row.blob_id_decimal)) {
    rows.push(row);
    saveIndex(rows);
  }
}

function lookupByBlobDecimal(blobIdDecimal) {
  const rows = loadIndex();
  return rows.find((r) => r.blob_id_decimal === blobIdDecimal) || null;
}

module.exports = { saveRow, lookupByBlobDecimal, loadIndex, saveIndex };
