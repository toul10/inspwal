const relatedContainer = document.getElementById("relatedPanels");

function makeCard(title, content) {
  const card = document.createElement("div");
  card.className = "card";

  const header = document.createElement("div");
  header.className = "card-header";
  header.innerHTML = `<div class="card-title">${title}</div>`;

  const body = document.createElement("div");
  body.className = "card-body";
  body.style.padding = "12px 16px";
  body.style.fontSize = "13px";
  body.style.lineHeight = "1.5";
  body.style.whiteSpace = "pre-wrap";

  if (typeof content === "string") {
    body.textContent = content;
  } else if (content instanceof Node) {
    body.appendChild(content);
  }

  card.appendChild(header);
  card.appendChild(body);
  return card;
}

function renderHashList(hashes) {
  if (!hashes) return "Unavailable";
  const entries = Object.entries(hashes).filter(([, v]) => !!v);
  if (!entries.length) return "Unavailable";
  return entries
    .map(([k, v]) => `${k.toUpperCase()}:\n${v}`)
    .join("\n\n");
}

function renderHeaders(headers) {
  if (!headers) return "Unavailable";
  const lines = Object.entries(headers).map(([k, v]) => `${k}: ${v}`);
  return lines.length ? lines.join("\n") : "Unavailable";
}

function renderTextSummary(textSummary) {
  if (!textSummary) return "Unavailable";
  const lines = [];
  if (textSummary.preview) lines.push(textSummary.preview);
  if (textSummary.isJson) {
    const keys = (textSummary.jsonKeys || []).join(", ");
    lines.push(`JSON detected${keys ? ` | keys: ${keys}` : ""}`);
  }
  if (typeof textSummary.printableRatio === "number") {
    lines.push(`Printable ratio: ${textSummary.printableRatio}`);
  }
  if (typeof textSummary.lines === "number") {
    lines.push(`Lines: ${textSummary.lines}`);
  }
  return lines.join("\n");
}

function renderEncryption(encryptionGuess) {
  if (!encryptionGuess) return "Unavailable";

  const lines = [];
  if (encryptionGuess.classification) {
    lines.push(`Classification: ${encryptionGuess.classification}`);
  }
  if (typeof encryptionGuess.likelyEncrypted === "boolean") {
    lines.push(
      `Likely encrypted: ${encryptionGuess.likelyEncrypted ? "Yes" : "No"}`
    );
  }
  if (typeof encryptionGuess.entropyBitsPerByte === "number") {
    lines.push(
      `Entropy bits per byte: ${encryptionGuess.entropyBitsPerByte.toFixed(3)}`
    );
  }
  if (encryptionGuess.reason) {
    lines.push(`Reason: ${encryptionGuess.reason}`);
  }

  return lines.length ? lines.join("\n") : "Unavailable";
}

function renderByteSample(sample) {
  if (!sample || !sample.hex) return "Unavailable";
  const len =
    typeof sample.length === "number" ? sample.length : sample.hex.length / 2;
  const lines = [];
  lines.push(`Hex: ${sample.hex}`);
  if (sample.base64) lines.push(`Base64: ${sample.base64}`);
  lines.push(`Length of sample: ${len} bytes`);
  return lines.join("\n");
}

function renderWalrusDetails(data) {
  const parts = [];
  if (data.walrusUrl) parts.push(`URL: ${data.walrusUrl}`);
  if (data.walrusStatus) parts.push(`Status: ${data.walrusStatus}`);
  if (data.walrusSnippet) {
    parts.push(`Snippet:\n${data.walrusSnippet}`);
  }
  if (data.note) parts.push(`Note: ${data.note}`);
  if (data.error) parts.push(`Error: ${data.error}`);
  return parts.length ? parts.join("\n\n") : "Unavailable";
}

function renderQuickSummary(data) {
  const parts = [];

  if (data.availability && data.availability !== "unknown") {
    parts.push(`Availability: ${data.availability}`);
  }

  if (typeof data.sizeBytes === "number") {
    parts.push(`Size in bytes: ${data.sizeBytes}`);
  }

  if (data.mimeType && data.mimeType !== "application/octet-stream") {
    parts.push(`Mime type: ${data.mimeType}`);
  }

  if (data.format) {
    parts.push(`Magic or format: ${data.format}`);
  }

  if (data.encryptionGuess && data.encryptionGuess.classification) {
    parts.push(
      `Classification: ${data.encryptionGuess.classification}`
    );
  }

  if (data.encryptionGuess && data.encryptionGuess.reason) {
    parts.push(`Encryption reason: ${data.encryptionGuess.reason}`);
  }

  return parts.length ? parts.join("\n") : "No extra summary available";
}

window.renderRelatedPanels = function renderRelatedPanels(data) {
  if (!relatedContainer) return;
  relatedContainer.innerHTML = "";

  const hashes = data.hashes || null;
  const headers = data.walrusHeaders || null;
  const textSummary = data.textSummary || null;
  const encryptionGuess = data.encryptionGuess || null;
  const byteSample = data.byteSample || null;

  const quickCard = makeCard("Quick summary", renderQuickSummary(data));
  const hashCard = makeCard("Hashes", renderHashList(hashes));
  const encryptionCard = makeCard(
    "Encryption and entropy",
    renderEncryption(encryptionGuess)
  );
  const sampleCard = makeCard("Byte sample", renderByteSample(byteSample));
  const headerCard = makeCard("Walrus headers", renderHeaders(headers));
  const walrusCard = makeCard("Walrus details", renderWalrusDetails(data));

  relatedContainer.appendChild(quickCard);
  relatedContainer.appendChild(hashCard);
  relatedContainer.appendChild(encryptionCard);
  relatedContainer.appendChild(sampleCard);
  relatedContainer.appendChild(headerCard);

  // only show text summary side card when there is real text
  if (
    textSummary &&
    (textSummary.preview ||
      textSummary.isJson ||
      typeof textSummary.lines === "number")
  ) {
    const textCard = makeCard(
      "Text summary",
      renderTextSummary(textSummary)
    );
    relatedContainer.appendChild(textCard);
  }

  relatedContainer.appendChild(walrusCard);
};
