const form = document.getElementById("inspectForm");
const idInput = document.getElementById("idInput");
const inspectButton = document.getElementById("inspectButton");
const statusPill = document.getElementById("statusPill");

const resultCard = document.getElementById("resultCard");
const resultTitle = document.getElementById("resultTitle");
const badgeNetwork = document.getElementById("badgeNetwork");
const badgeType = document.getElementById("badgeType");
const badgeAvailability = document.getElementById("badgeAvailability");
const badgeSeal = document.getElementById("badgeSeal");

const fieldId = document.getElementById("fieldId");
const fieldExists = document.getElementById("fieldExists");
const fieldMime = document.getElementById("fieldMime");
const fieldSize = document.getElementById("fieldSize");
const fieldOutcome = document.getElementById("fieldOutcome");
const fieldPreviewStatus = document.getElementById("fieldPreviewStatus");
const fieldSource = document.getElementById("fieldSource");
const fieldNote = document.getElementById("fieldNote");
const fieldWalrusUrl = document.getElementById("fieldWalrusUrl");
const fieldWalrusStatus = document.getElementById("fieldWalrusStatus");
const fieldEncryption = document.getElementById("fieldEncryption");
const fieldEntropy = document.getElementById("fieldEntropy");
const fieldSha256 = document.getElementById("fieldSha256");
const fieldSha512 = document.getElementById("fieldSha512");
const fieldBlake2b512 = document.getElementById("fieldBlake2b512");
const fieldSha1 = document.getElementById("fieldSha1");
const fieldMd5 = document.getElementById("fieldMd5");
const fieldByteSample = document.getElementById("fieldByteSample");
const fieldWalrusHeaders = document.getElementById("fieldWalrusHeaders");
const fieldFormat = document.getElementById("fieldFormat");
const fieldTextSummary = document.getElementById("fieldTextSummary");
const previewWrapper = document.getElementById("previewWrapper");
const jsonBox = document.getElementById("jsonBox");

// Sui card
const suiCard = document.getElementById("suiCard");
const badgeSuiNetwork = document.getElementById("badgeSuiNetwork");
const badgeSuiStatus = document.getElementById("badgeSuiStatus");
const suiObjectId = document.getElementById("suiObjectId");
const suiObjectType = document.getElementById("suiObjectType");
const suiOwner = document.getElementById("suiOwner");
const suiPrevTx = document.getElementById("suiPrevTx");
const suiStorageRebate = document.getElementById("suiStorageRebate");
const suiTxStatus = document.getElementById("suiTxStatus");
const suiGasUsed = document.getElementById("suiGasUsed");
const suiEventsCount = document.getElementById("suiEventsCount");
const suiObjectChanges = document.getElementById("suiObjectChanges");
const suiJsonBox = document.getElementById("suiJsonBox");
const suiEncodingType = document.getElementById("suiEncodingType");
const suiEpochs = document.getElementById("suiEpochs");
const suiBlobType = document.getElementById("suiBlobType");

function formatOwner(ownerVal) {
  if (!ownerVal) return "";
  if (typeof ownerVal === "string") return ownerVal;
  if (ownerVal.AddressOwner) return ownerVal.AddressOwner;
  if (ownerVal.ObjectOwner) return ownerVal.ObjectOwner;
  if (ownerVal.Shared) return "Shared";
  if (ownerVal.InitialSharedVersion) return `Shared v${ownerVal.InitialSharedVersion}`;
  return JSON.stringify(ownerVal);
}

function looksObjectId(val) {
  return /^0x[0-9a-fA-F]{64}$/.test(val);
}

async function fetchInspectWithFallback(rawId, resultType) {
  const endpoint = resultType === "object" ? "/inspect-object" : "/inspect";
  const paramName = resultType === "object" ? "objectId" : "id";
  const nets = ["mainnet", "testnet"];
  let lastErr = null;

  for (const net of nets) {
    try {
      const url =
        `${endpoint}?net=${encodeURIComponent(net)}&` +
        `${paramName}=${encodeURIComponent(rawId)}`;
      const resp = await fetch(url);
      const data = await resp.json().catch(() => null);
      if (!data) {
        lastErr = new Error("Empty response");
        continue;
      }
      if (!resp.ok || data.error) {
        lastErr = new Error(data.error || `HTTP ${resp.status}`);
        continue;
      }
      return { data, attemptedNet: net };
    } catch (err) {
      lastErr = err;
    }
  }

  throw lastErr || new Error("All networks failed");
}

function setStatus(text) {
  statusPill.textContent = text;
}

function setBadge(el, text, mode) {
  el.textContent = text;
  el.classList.remove("green", "red", "gray");
  if (mode === "green") el.classList.add("green");
  else if (mode === "red") el.classList.add("red");
  else el.classList.add("gray");
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const rawId = idInput.value.trim();
  if (!rawId) {
    setStatus("Please paste an id first");
    return;
  }

  if (suiCard) {
    suiCard.classList.add("hidden");
    suiJsonBox.textContent = "";
  }

  inspectButton.disabled = true;
  setStatus("Inspecting…");

  try {
    const resultType = looksObjectId(rawId) ? "object" : "blob";
    const { data, attemptedNet } = await fetchInspectWithFallback(
      rawId,
      resultType
    );

    resultCard.classList.remove("hidden");

    const effectiveNetwork = data.network || attemptedNet || "mainnet";
    const availability = data.availability || "unknown";
    const exists = data.existsOnWalrus;
    const hasSeal = data.hasSeal === true;
    const idShown = data.blobId || data.objectId || rawId;

    resultTitle.textContent = data.error ? "Result with error" : "Result";

    setBadge(
      badgeNetwork,
      effectiveNetwork === "mainnet" ? "Mainnet" : "Testnet",
      effectiveNetwork === "mainnet" ? "green" : "gray"
    );

    setBadge(
      badgeType,
      resultType === "object" ? "Sui object" : "Blob id",
      "gray"
    );

    let availLabel = availability;
    let availMode = "gray";
    if (availability === "present") {
      availLabel = "Present";
      availMode = "green";
    } else if (availability === "absent") {
      availLabel = "Absent";
      availMode = "red";
    }
    setBadge(badgeAvailability, `Availability: ${availLabel}`, availMode);

    setBadge(
      badgeSeal,
      hasSeal ? "Protected by Seal" : "Not protected by Seal",
      hasSeal ? "green" : "gray"
    );
    const isSeal = hasSeal;

    fieldId.textContent = idShown;
    if (exists === true) fieldExists.textContent = "Yes";
    else if (exists === false) fieldExists.textContent = "No";
    else fieldExists.textContent = "Unknown";

    fieldMime.textContent = data.mimeType || "Unknown";
    fieldSize.textContent =
      typeof data.sizeBytes === "number" ? String(data.sizeBytes) : "Unknown";

    const walrusUrl = data.walrusUrl || null;
    if (walrusUrl) {
      fieldWalrusUrl.innerHTML = `<a href="${walrusUrl}" target="_blank" rel="noreferrer noopener">${walrusUrl}</a>`;
    } else {
      fieldWalrusUrl.textContent = "Unknown";
    }

    const walrusStatusRaw =
      typeof data.walrusStatus === "number" ||
      typeof data.walrusStatus === "string"
        ? data.walrusStatus
        : null;
    if (walrusStatusRaw) {
      fieldWalrusStatus.textContent = walrusStatusRaw;
    } else if (availability === "present") {
      fieldWalrusStatus.textContent = "200 (ok)";
    } else if (availability === "absent") {
      fieldWalrusStatus.textContent = "404/absent";
    } else {
      fieldWalrusStatus.textContent = "Unknown";
    }

    const walrusHeaders = data.walrusHeaders || {};
    const headerEntries = Object.entries(walrusHeaders).map(
      ([k, v]) => `${k}: ${v}`
    );
    fieldWalrusHeaders.textContent = headerEntries.length
      ? headerEntries.join(" · ")
      : "Unavailable";

    const eg = data.encryptionGuess || {};
    const encClass = eg.classification || "unknown";
    if (eg.reason) {
      fieldEncryption.textContent = `${encClass} – ${eg.reason}`;
    } else {
      fieldEncryption.textContent = encClass;
    }

    fieldEntropy.textContent =
      typeof eg.entropyBitsPerByte === "number"
        ? eg.entropyBitsPerByte.toFixed(2)
        : "n/a";

    const hashes = data.hashes || {};
    fieldSha256.textContent = hashes.sha256 || "Unknown";
    fieldSha512.textContent = hashes.sha512 || "Unknown";
    fieldBlake2b512.textContent = hashes.blake2b512 || "Unknown";
    fieldSha1.textContent = hashes.sha1 || "Unknown";
    fieldMd5.textContent = hashes.md5 || "Unknown";

    const byteSample = data.byteSample || {};
    if (byteSample.hex) {
      const len =
        typeof byteSample.length === "number" ? byteSample.length : null;
      fieldByteSample.textContent = len
        ? `${byteSample.hex} (len ${len} bytes)`
        : byteSample.hex;
    } else {
      fieldByteSample.textContent = "Unavailable";
    }

    const format = data.format || null;
    fieldFormat.textContent = format || "Unknown";

    const textSummary = data.textSummary || null;
    if (textSummary && textSummary.preview) {
      const jsonInfo = textSummary.isJson
        ? `JSON keys: ${(textSummary.jsonKeys || []).join(", ")}`
        : "";
      const printableInfo =
        typeof textSummary.printableRatio === "number"
          ? `Printable ratio: ${textSummary.printableRatio}`
          : "";
      const linesInfo =
        typeof textSummary.lines === "number"
          ? `Lines: ${textSummary.lines}`
          : "";
      const parts = [jsonInfo, printableInfo, linesInfo].filter(Boolean);
      fieldTextSummary.textContent = `${textSummary.preview}${
        parts.length ? ` (${parts.join(" · ")})` : ""
      }`;
    } else {
      fieldTextSummary.textContent = "Unavailable";
    }

    const previewStatus = (() => {
      if (data.previewType === "image") return "Image preview";
      if (data.previewType === "video") return "Video preview";
      if (data.previewType === "audio") return "Audio preview";
      if (data.previewType === "text") return "Text preview";
      return "Preview unavailable";
    })();

    fieldPreviewStatus.textContent = previewStatus;

    const outcomeParts = [];
    if (availability === "present") outcomeParts.push("Present on Walrus");
    else if (availability === "absent") outcomeParts.push("Absent on Walrus");
    else outcomeParts.push("Availability unknown");

    if (eg.classification) {
      outcomeParts.push(eg.classification);
    } else if (data.previewType) {
      outcomeParts.push(`content: ${data.previewType}`);
    }

    if (isSeal) {
      fieldOutcome.textContent = "Present on Walrus · Seal protected content";
    } else {
      fieldOutcome.textContent = outcomeParts.join(" · ");
    }

    const notes = [];
    if (data.note) notes.push(data.note);
    if (data.error) notes.push(`Error: ${data.error}`);
    if (data.walrusStatus) notes.push(`Walrus status ${data.walrusStatus}`);
    if (data.walrusSnippet) {
      notes.push(`Walrus snippet: ${data.walrusSnippet}`);
    }
    if (eg.reason) {
      notes.push(`Encryption: ${eg.reason}`);
    }
    fieldNote.textContent = notes.join(" · ");

    const sourceLabel = `${resultType} (${data.walrusStatus || "n/a"})`;
    fieldSource.textContent = sourceLabel;

    previewWrapper.classList.add("hidden");
    previewWrapper.innerHTML = "";

    if (!isSeal) {
      if (data.previewType === "image" && data.mediaUrl) {
        previewWrapper.classList.remove("hidden");
        previewWrapper.innerHTML =
          `<img src="${data.mediaUrl}" style="max-width:100%;border-radius:8px;display:block;" />`;
      } else if (data.previewType === "video" && data.mediaUrl) {
        previewWrapper.classList.remove("hidden");
        const mime = data.mimeType || "video/mp4";
        previewWrapper.innerHTML =
          `<video controls style="max-width:100%;border-radius:8px;display:block;">` +
          `<source src="${data.mediaUrl}" type="${mime}" />` +
          `</video>`;
      } else if (data.previewType === "audio" && data.mediaUrl) {
        previewWrapper.classList.remove("hidden");
        const mime = data.mimeType || "audio/mpeg";
        previewWrapper.innerHTML =
          `<audio controls style="width:100%;">` +
          `<source src="${data.mediaUrl}" type="${mime}" />` +
          `</audio>`;
      } else if (data.preview) {
        previewWrapper.classList.remove("hidden");
        previewWrapper.textContent = data.preview;
      }
    }

    jsonBox.textContent = JSON.stringify(data, null, 2);

    if (data.error) {
      setStatus("Completed with error");
    } else if (availability === "present") {
      setStatus("Completed");
    } else {
      setStatus("Completed (not present on this net)");
    }

    if (typeof window.renderRelatedPanels === "function") {
      window.renderRelatedPanels(data);
    }

    const suiInfo = await fetchSuiDetails(idShown, effectiveNetwork);
    renderSui(suiInfo);
  } catch (err) {
    console.error(err);
    setStatus("Request failed");
  } finally {
    inspectButton.disabled = false;
  }
});

async function fetchSuiDetails(blobId, network) {
  try {
    const url =
      `/sui-from-blob?id=${encodeURIComponent(blobId)}&net=${encodeURIComponent(
        network
      )}`;
    const resp = await fetch(url);
    const data = await resp.json().catch(() => null);
    if (!data || !resp.ok || data.ok === false) {
      throw new Error(
        (data && data.error) || `Helper error ${resp.status || "n/a"}`
      );
    }
    return data;
  } catch (err) {
    console.error("[sui helper] failed", err);
    return { ok: false, error: err.message || "failed to fetch" };
  }
}

function renderSui(data) {
  if (!suiCard) return;

  if (!data || data.ok === false) {
    suiCard.classList.remove("hidden");
    badgeSuiNetwork.textContent = "";
    badgeSuiStatus.textContent = "Sui details unavailable";
    badgeSuiStatus.className = "badge red";
    suiObjectId.textContent = "";
    suiObjectType.textContent = "";
    suiOwner.textContent = "";
    suiPrevTx.textContent = "";
    suiStorageRebate.textContent = "";
    suiTxStatus.textContent = "";
    suiGasUsed.textContent = "";
    suiEventsCount.textContent = "";
    suiObjectChanges.textContent = "";
    suiEncodingType.textContent = "";
    suiEpochs.textContent = "";
    suiBlobType.textContent = "";
    suiJsonBox.textContent = data && data.error ? data.error : "";
    return;
  }

  const net = data.network || "mainnet";
  badgeSuiNetwork.textContent =
    net === "mainnet" ? "Sui mainnet" : "Sui testnet";
  badgeSuiNetwork.className = net === "mainnet" ? "badge green" : "badge gray";

  const obj = data.suiObject || {};
  const objData = obj.data || {};
  const tx = data.suiTransaction || {};
  const txEffects = tx.effects || {};
  const gasUsed = txEffects.gasUsed || {};
  const eventsCount = Array.isArray(tx.events) ? tx.events.length : null;
  const changesCount = Array.isArray(tx.objectChanges)
    ? tx.objectChanges.length
    : null;
  const summary = data.summary || {};
  let encodingType = summary.encodingType;
  let registeredEpoch = summary.registeredEpoch;
  let storageStart = summary.storageStart;
  let storageEnd = summary.storageEnd;

  const content =
    objData.content && objData.content.fields ? objData.content.fields : null;
  if (content) {
    if (encodingType === undefined && content.encoding_type !== undefined) {
      encodingType = content.encoding_type;
    }
    if (
      registeredEpoch === undefined &&
      content.registered_epoch !== undefined
    ) {
      registeredEpoch = content.registered_epoch;
    }
    if (!storageStart || !storageEnd) {
      const storage =
        content.storage && content.storage.fields
          ? content.storage.fields
          : null;
      if (storage) {
        if (storageStart === undefined && storage.start_epoch !== undefined) {
          storageStart = storage.start_epoch;
        }
        if (storageEnd === undefined && storage.end_epoch !== undefined) {
          storageEnd = storage.end_epoch;
        }
      }
    }
  }

  let blobType =
    summary.blobType ||
    (content && (content.blob_type || content.blobType)) ||
    null;
  if (!blobType && data.suiTransaction && data.suiTransaction.transaction) {
    const txInner = data.suiTransaction.transaction;
    const txInputs =
      txInner.data &&
      txInner.data.transaction &&
      Array.isArray(txInner.data.transaction.inputs)
        ? txInner.data.transaction.inputs
        : [];
    for (let i = 0; i < txInputs.length - 1; i++) {
      const cur = txInputs[i];
      const nxt = txInputs[i + 1];
      if (
        cur &&
        cur.valueType === "0x1::string::String" &&
        cur.value === "_walrusBlobType" &&
        nxt &&
        nxt.valueType === "0x1::string::String"
      ) {
        blobType = nxt.value;
        break;
      }
    }
  }

  badgeSuiStatus.textContent = "Sui details loaded";
  badgeSuiStatus.className = "badge green";

  suiCard.classList.remove("hidden");

  suiObjectId.textContent = data.objectId || summary.objectId || objData.objectId || "";
  suiObjectType.textContent =
    objData.type ||
    (objData.content && objData.content.type ? objData.content.type : "") ||
    (objData.objectType || "");

  const ownerRaw =
    summary.owner ||
    objData.owner ||
    (objData.owner && objData.owner.AddressOwner) ||
    (objData.owner && objData.owner.ObjectOwner) ||
    (objData.owner && objData.owner.Shared && "Shared") ||
    "";
  suiOwner.textContent = formatOwner(ownerRaw);

  const prevTx =
    summary.previousTransaction || objData.previousTransaction || "";
  suiPrevTx.textContent = prevTx;

  const storageRebate =
    objData.storageRebate !== undefined
      ? String(objData.storageRebate)
      : summary.storageRebate || "";
  suiStorageRebate.textContent = storageRebate;

  const txStatus =
    summary.txStatus ||
    (txEffects.status && (txEffects.status.status || "")) ||
    "";
  suiTxStatus.textContent = txStatus;

  const gasParts = [];
  const comp = summary.gasComputation || gasUsed.computationCost;
  const storage = summary.gasStorage || gasUsed.storageCost;
  const rebate = summary.gasRebate || gasUsed.storageRebate;
  if (comp) gasParts.push(`comp: ${comp}`);
  if (storage) gasParts.push(`storage: ${storage}`);
  if (rebate) gasParts.push(`rebate: ${rebate}`);
  suiGasUsed.textContent = gasParts.join(" · ");

  suiEventsCount.textContent =
    eventsCount !== null ? String(eventsCount) : "";
  suiObjectChanges.textContent =
    changesCount !== null ? String(changesCount) : "";

  if (suiEncodingType) {
    suiEncodingType.textContent =
      encodingType !== undefined && encodingType !== null
        ? String(encodingType)
        : "";
  }

  if (suiEpochs) {
    const reg =
      registeredEpoch !== undefined && registeredEpoch !== null
        ? String(registeredEpoch)
        : "?";
    const start =
      storageStart !== undefined && storageStart !== null
        ? String(storageStart)
        : "?";
    const end =
      storageEnd !== undefined && storageEnd !== null
        ? String(storageEnd)
        : "?";
    if (reg === "?" && start === "?" && end === "?") {
      suiEpochs.textContent = "";
    } else {
      suiEpochs.textContent = `registered: ${reg} storage: ${start} → ${end}`;
    }
  }

  if (suiBlobType) {
    suiBlobType.textContent = blobType || objData.type || "";
  }

  suiJsonBox.textContent = JSON.stringify(data, null, 2);
}

// expose helpers
window.fetchSuiDetails = fetchSuiDetails;
window.renderSui = renderSui;
