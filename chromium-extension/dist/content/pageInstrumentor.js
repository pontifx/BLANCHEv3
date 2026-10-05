"use strict";
(() => {
  // chromium-extension/src/content/pageInstrumentor.ts
  (() => {
    const globalKey = "__blancheBurpBridgeInstrumented";
    if (window[globalKey]) {
      return;
    }
    window[globalKey] = true;
    document.documentElement?.setAttribute("data-blanche-burp-bridge", "true");
    const maxInstrumentationEvents = 400;
    const state = {
      version: "0.3.0",
      startedAt: (/* @__PURE__ */ new Date()).toISOString(),
      events: [],
      warnings: [],
      droppedEventCount: 0,
      droppedEventsByReason: {}
    };
    const sanitizeObservedUrl = (rawUrl) => {
      if (rawUrl === void 0) {
        return void 0;
      }
      try {
        const parsed = new URL(String(rawUrl), location.href);
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          return `${parsed.protocol}${parsed.protocol === "blob:" ? "[redacted]" : ""}`;
        }
        parsed.username = "";
        parsed.password = "";
        parsed.hash = "";
        const names = [.../* @__PURE__ */ new Set([...parsed.searchParams.keys()])].sort();
        parsed.search = names.length > 0 ? `?${names.map((name) => `${encodeURIComponent(name)}=`).join("&")}` : "";
        parsed.pathname = parsed.pathname.replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, "{uuid}").replace(/\b[0-9a-f]{24,}\b/gi, "{hex}").replace(/\b\d{4,}\b/g, "{id}");
        return parsed.toString();
      } catch {
        return "[unparseable-url]";
      }
    };
    const sanitizeSensitiveText = (value, maxLength = 300) => {
      const text = String(value ?? "");
      return text.replace(/https?:\/\/[^\s"'<>]+/gi, (url) => sanitizeObservedUrl(url) ?? "[redacted-url]").replace(/(\/\/)[^/\s:@]+:[^@\s/]+@/g, "$1[redacted-credentials]@").replace(/([?&][A-Za-z0-9_.~%-]{1,100})=([^&#\s]*)/g, "$1=[redacted]").replace(/#[^\s"'<>]*/g, "#[redacted]").replace(/\b(bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]").replace(
        /\b(password|passwd|secret|access[-_]?token|refresh[-_]?token|authorization|api[-_]?key|session[-_]?id|cookie)\s*[:=]\s*[^\s,;]+/gi,
        "$1=[redacted]"
      ).slice(0, maxLength);
    };
    const isUrlLikeAttribute = (key) => {
      const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
      return normalized.endsWith("url") || normalized.endsWith("uri") || normalized.endsWith("href") || normalized.endsWith("src") || normalized === "endpoint" || normalized === "location" || normalized === "referrer" || normalized === "initiator";
    };
    const sanitizeEventAttributes = (attributes) => {
      const visit = (key, value, depth) => {
        if (value === void 0 || value === null) {
          return value;
        }
        if (isUrlLikeAttribute(key)) {
          if (Array.isArray(value)) {
            return value.slice(0, 100).map(
              (entry) => typeof entry === "string" || entry instanceof URL ? sanitizeObservedUrl(entry) ?? "[redacted-url]" : visit(key, entry, depth + 1)
            );
          }
          if (typeof value === "string" || value instanceof URL) {
            return sanitizeObservedUrl(value) ?? "[redacted-url]";
          }
        }
        if (depth >= 5) {
          return "[depth-limit]";
        }
        if (Array.isArray(value)) {
          return value.slice(0, 100).map((entry) => visit(key, entry, depth + 1));
        }
        if (typeof value === "object") {
          return Object.fromEntries(
            Object.entries(value).slice(0, 100).map(([childKey, entry]) => [childKey, visit(childKey, entry, depth + 1)])
          );
        }
        return value;
      };
      return Object.fromEntries(
        Object.entries(attributes).slice(0, 100).map(([key, value]) => [key, visit(key, value, 0)])
      );
    };
    const captureInitiator = () => {
      const stack = new Error().stack ?? "";
      for (const line of stack.split("\n").slice(2, 10)) {
        const match = line.match(/(https?:\/\/[^\s)]+?)(?::\d+){1,2}(?:\)?$|\s)/i);
        if (!match?.[1]) {
          continue;
        }
        return match[1];
      }
      return void 0;
    };
    const safeErrorSummary = (value) => {
      if (value instanceof Error) {
        const message2 = String(value.message ?? "");
        return {
          name: sanitizeSensitiveText(value.name || "Error", 80),
          message: message2 ? sanitizeSensitiveText(message2) : void 0,
          messageLength: message2.length
        };
      }
      const message = typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : "";
      return {
        name: typeof value,
        message: message ? sanitizeSensitiveText(message) : void 0,
        messageLength: message.length || void 0
      };
    };
    const featureObservationBudget = {
      eligibleResponseCount: 0,
      startedResponseCount: 0,
      observedResponseCount: 0,
      candidateEventCount: 0,
      capturedBytes: 0,
      reservedBytes: 0,
      droppedResponseCount: 0,
      truncatedResponseCount: 0,
      droppedByReason: {},
      truncatedByReason: {}
    };
    const maxObservedResponses = 40;
    const maxObservedResponseBytes = 32768;
    const maxObservedTotalBytes = 524288;
    const postBridgeMessage = (type, payload) => {
      window.postMessage(
        {
          __blanche: "burp-bridge",
          type,
          payload
        },
        "*"
      );
    };
    const pushEvent = (type, url, attributes) => {
      const event = {
        id: crypto.randomUUID(),
        type,
        observedAt: (/* @__PURE__ */ new Date()).toISOString(),
        pageUrl: sanitizeObservedUrl(location.href) ?? "[redacted-url]",
        frameHref: sanitizeObservedUrl(location.href) ?? "[redacted-url]",
        url: sanitizeObservedUrl(url),
        attributes: sanitizeEventAttributes(attributes)
      };
      state.events.unshift(event);
      if (state.events.length > maxInstrumentationEvents) {
        const dropped = state.events.length - maxInstrumentationEvents;
        state.events.length = maxInstrumentationEvents;
        state.droppedEventCount += dropped;
        state.droppedEventsByReason["event-buffer-limit"] = (state.droppedEventsByReason["event-buffer-limit"] ?? 0) + dropped;
      }
      postBridgeMessage("instrumentation-event", event);
    };
    const looksLikeFlagName = (value) => {
      return /(?:^|[-_.:/])(?:feature|features|flag|flags|experiment|experiments|variant|variation|rollout|beta|preview|labs?|gate|gates|toggle|toggles|enabled?|disabled?)(?:$|[-_.:/])/i.test(
        value
      ) || /(?:feature|flag|experiment|variant|variation|rollout|preview|beta|labs?|gate|toggle|enabled|disabled|new[A-Z]|legacy[A-Z])/.test(
        value
      );
    };
    const looksSensitive = (value) => {
      return /(?:^|[-_.:/])(?:auth|authorization|access[-_]?token|refresh[-_]?token|jwt|csrf|password|passwd|secret|credential|session[-_]?id|license|subscription|permission|role)(?:$|[-_.:/])/i.test(
        value
      );
    };
    const toggleValues = (value) => {
      if (value === true || value === false) {
        return {
          currentValue: value,
          suggestedValue: !value
        };
      }
      if (value === 0 || value === 1) {
        return {
          currentValue: value,
          suggestedValue: value === 0 ? 1 : 0
        };
      }
      if (typeof value !== "string") {
        return void 0;
      }
      const normalized = value.trim().toLowerCase();
      const pairs = {
        false: "true",
        true: "false",
        "0": "1",
        "1": "0",
        off: "on",
        on: "off",
        disabled: "enabled",
        enabled: "disabled",
        no: "yes",
        yes: "no",
        control: "treatment",
        treatment: "control"
      };
      const suggestedValue = pairs[normalized];
      return suggestedValue ? {
        currentValue: value,
        suggestedValue
      } : void 0;
    };
    const extractFeatureCandidates = (text) => {
      const candidates = /* @__PURE__ */ new Map();
      const observe = (candidate) => {
        const key = candidate.key.trim().slice(0, 180);
        if (key.length < 2 || looksSensitive(key)) {
          return;
        }
        const signature = key.toLowerCase().replace(/[^a-z0-9]+/g, "-");
        const existing = candidates.get(signature);
        if (!existing || existing.confidence !== "high" && candidate.confidence === "high") {
          candidates.set(signature, {
            ...candidate,
            key
          });
        }
      };
      try {
        const parsed = JSON.parse(text);
        let visited = 0;
        const visit = (value, inheritedFlagContext) => {
          if (visited >= 800 || candidates.size >= 80) {
            return;
          }
          visited += 1;
          if (Array.isArray(value)) {
            for (const entry of value.slice(0, 100)) {
              visit(entry, inheritedFlagContext);
            }
            return;
          }
          if (!value || typeof value !== "object") {
            return;
          }
          const record = value;
          const identity = ["featureKey", "flagKey", "key", "feature", "name", "id"].map((key) => record[key]).find((entry) => typeof entry === "string" && entry.length >= 2);
          const stateEntry = ["enabled", "isEnabled", "value", "variation", "variant", "state"].map((key) => [key, record[key]]).find((entry) => toggleValues(entry[1]) !== void 0);
          if (identity && stateEntry && !looksSensitive(identity)) {
            const toggle = toggleValues(stateEntry[1]);
            if (toggle) {
              observe({
                key: identity,
                ...toggle,
                confidence: "high",
                detail: `Feature record associates ${stateEntry[0]} with an explicit key in a response already delivered to the page.`
              });
            }
          }
          for (const [key, entry] of Object.entries(record).slice(0, 200)) {
            const flagContext = inheritedFlagContext || looksLikeFlagName(key);
            const toggle = toggleValues(entry);
            if (toggle && flagContext && (!identity || stateEntry?.[0] !== key)) {
              observe({
                key,
                ...toggle,
                confidence: looksLikeFlagName(key) ? "high" : "medium",
                detail: "Flag-shaped value in a response already delivered to the page."
              });
            }
            if (entry && typeof entry === "object") {
              visit(entry, flagContext);
            }
          }
        };
        visit(parsed, false);
      } catch {
      }
      const providerPattern = /(?:isEnabled|isFeatureEnabled|featureEnabled|hasFeature|useFeature|variation|getFeatureFlag|getBooleanValue|checkGate|isGateEnabled)\s*\(\s*["'`]([^"'`]{2,160})["'`]/g;
      for (const match of text.matchAll(providerPattern)) {
        if (match[1]) {
          observe({
            key: match[1],
            suggestedValue: true,
            confidence: "high",
            detail: "Flag-client callsite in an already-delivered response."
          });
        }
        if (candidates.size >= 80) {
          break;
        }
      }
      const pairPattern = /(?:["'`]([^"'`]{2,160})["'`]|([A-Za-z_$][\w$.-]{1,159}))\s*:\s*(true|false|!0|!1|0|1|["'`](?:enabled|disabled|on|off|control|treatment|yes|no)["'`])/g;
      for (const match of text.matchAll(pairPattern)) {
        const key = match[1] ?? match[2];
        const raw = (match[3] ?? "").replace(/^["'`]|["'`]$/g, "");
        const toggle = toggleValues(raw === "!0" ? true : raw === "!1" ? false : raw);
        const index = match.index ?? 0;
        const nearby = text.slice(Math.max(0, index - 100), index + 220);
        if (key && toggle && (looksLikeFlagName(key) || /feature|flag|experiment|gate/i.test(nearby))) {
          observe({
            key,
            ...toggle,
            confidence: looksLikeFlagName(key) ? "high" : "medium",
            detail: "Toggle-shaped key/value pair in an already-delivered response."
          });
        }
        if (candidates.size >= 80) {
          break;
        }
      }
      return [...candidates.values()].slice(0, 80);
    };
    const shouldInspectResponse = (contentType, responseUrl) => {
      return /json|javascript|ecmascript|text\/plain/i.test(contentType) || /(?:feature|flag|experiment|variant|rollout|bootstrap|config|settings|\.m?js|\.json)(?:$|[?#/])/i.test(
        responseUrl
      );
    };
    const incrementReason = (reasons, reason) => {
      reasons[reason] = (reasons[reason] ?? 0) + 1;
    };
    const beginResponseObservation = () => {
      featureObservationBudget.eligibleResponseCount += 1;
      if (featureObservationBudget.startedResponseCount >= maxObservedResponses) {
        featureObservationBudget.droppedResponseCount += 1;
        incrementReason(featureObservationBudget.droppedByReason, "response-count-limit");
        return void 0;
      }
      const remainingTotal = maxObservedTotalBytes - featureObservationBudget.capturedBytes - featureObservationBudget.reservedBytes;
      if (remainingTotal <= 0) {
        featureObservationBudget.droppedResponseCount += 1;
        incrementReason(featureObservationBudget.droppedByReason, "total-byte-limit");
        return void 0;
      }
      const byteAllowance = Math.min(maxObservedResponseBytes, remainingTotal);
      featureObservationBudget.startedResponseCount += 1;
      featureObservationBudget.reservedBytes += byteAllowance;
      return byteAllowance;
    };
    const finishResponseObservation = (input) => {
      featureObservationBudget.reservedBytes = Math.max(
        0,
        featureObservationBudget.reservedBytes - input.byteAllowance
      );
      featureObservationBudget.capturedBytes += Math.min(
        input.byteAllowance,
        Math.max(0, input.capturedBytes)
      );
      if (input.observed) {
        featureObservationBudget.observedResponseCount += 1;
      } else {
        featureObservationBudget.droppedResponseCount += 1;
        incrementReason(
          featureObservationBudget.droppedByReason,
          input.dropReason ?? "body-unavailable"
        );
      }
      if (input.truncated) {
        featureObservationBudget.truncatedResponseCount += 1;
        incrementReason(
          featureObservationBudget.truncatedByReason,
          input.byteAllowance < maxObservedResponseBytes ? "total-byte-limit" : "per-response-byte-limit"
        );
      }
    };
    const truncateUtf8 = (value, byteLimit) => {
      const encoded = new TextEncoder().encode(value);
      if (encoded.byteLength <= byteLimit) {
        return {
          text: value,
          bytes: encoded.byteLength,
          truncated: false
        };
      }
      let end = Math.max(0, Math.min(byteLimit, encoded.byteLength));
      while (end > 0 && end < encoded.byteLength && (encoded[end] & 192) === 128) {
        end -= 1;
      }
      return {
        text: new TextDecoder().decode(encoded.slice(0, end)),
        bytes: end,
        truncated: true
      };
    };
    const stringifyBoundedJson = (value, characterLimit) => {
      const chunks = [];
      const seen = /* @__PURE__ */ new WeakSet();
      let retainedCharacters = 0;
      let visitedNodes = 0;
      let truncated = false;
      const maxNodes = 1e3;
      const maxEntriesPerContainer = 100;
      const maxDepth = 6;
      const append = (text) => {
        const remaining = characterLimit - retainedCharacters;
        if (remaining <= 0) {
          truncated = true;
          return false;
        }
        if (text.length > remaining) {
          chunks.push(text.slice(0, remaining));
          retainedCharacters += remaining;
          truncated = true;
          return false;
        }
        chunks.push(text);
        retainedCharacters += text.length;
        return true;
      };
      const visit = (entry, depth) => {
        visitedNodes += 1;
        if (visitedNodes > maxNodes || depth > maxDepth) {
          truncated = true;
          return append("null");
        }
        if (entry === null || typeof entry === "boolean" || typeof entry === "number") {
          return append(JSON.stringify(entry));
        }
        if (typeof entry === "string") {
          const remaining = Math.max(0, characterLimit - retainedCharacters - 2);
          const bounded = entry.slice(0, remaining);
          if (bounded.length < entry.length) truncated = true;
          return append(JSON.stringify(bounded));
        }
        if (typeof entry !== "object") {
          return append("null");
        }
        if (seen.has(entry)) {
          truncated = true;
          return append("null");
        }
        seen.add(entry);
        if (Array.isArray(entry)) {
          if (!append("[")) return false;
          const limit = Math.min(entry.length, maxEntriesPerContainer);
          for (let index = 0; index < limit; index += 1) {
            if (index > 0 && !append(",")) return false;
            if (!visit(entry[index], depth + 1)) return false;
          }
          if (entry.length > limit) truncated = true;
          return append("]");
        }
        if (!append("{")) return false;
        let retainedEntries = 0;
        for (const key in entry) {
          if (!Object.prototype.hasOwnProperty.call(entry, key)) continue;
          if (retainedEntries >= maxEntriesPerContainer) {
            truncated = true;
            break;
          }
          if (retainedEntries > 0 && !append(",")) return false;
          const remaining = Math.max(0, characterLimit - retainedCharacters - 2);
          const boundedKey = key.slice(0, Math.min(200, remaining));
          if (boundedKey.length < key.length) truncated = true;
          if (!append(JSON.stringify(boundedKey)) || !append(":")) return false;
          let child;
          try {
            child = entry[key];
          } catch {
            truncated = true;
            child = null;
          }
          if (!visit(child, depth + 1)) return false;
          retainedEntries += 1;
        }
        return append("}");
      };
      visit(value, 0);
      return { text: chunks.join(""), truncated };
    };
    const inspectResponse = async (response, transport, fallbackUrl) => {
      const responseUrl = response.url || fallbackUrl || location.href;
      const contentType = response.headers.get("content-type") ?? "";
      if (!shouldInspectResponse(contentType, responseUrl)) {
        return;
      }
      const byteLimit = beginResponseObservation();
      if (byteLimit === void 0) {
        return;
      }
      const reader = response.body?.getReader();
      if (!reader) {
        finishResponseObservation({
          byteAllowance: byteLimit,
          capturedBytes: 0,
          observed: false,
          truncated: false,
          dropReason: "body-unavailable"
        });
        return;
      }
      const decoder = new TextDecoder();
      let text = "";
      let capturedBytes = 0;
      let truncated = false;
      try {
        while (capturedBytes < byteLimit) {
          const next = await reader.read();
          if (next.done) {
            break;
          }
          const remaining = byteLimit - capturedBytes;
          const accepted = next.value.byteLength > remaining ? next.value.slice(0, remaining) : next.value;
          capturedBytes += accepted.byteLength;
          text += decoder.decode(accepted, {
            stream: true
          });
          if (accepted.byteLength < next.value.byteLength) {
            truncated = true;
            await reader.cancel();
            break;
          }
        }
        text += decoder.decode();
        if (capturedBytes >= byteLimit) {
          truncated = true;
          await reader.cancel().catch(() => {
          });
        }
      } catch {
        finishResponseObservation({
          byteAllowance: byteLimit,
          capturedBytes: 0,
          observed: false,
          truncated: false,
          dropReason: "body-read-error"
        });
        return;
      }
      const boundedText = truncateUtf8(text, byteLimit);
      text = boundedText.text;
      capturedBytes = boundedText.bytes;
      truncated = truncated || boundedText.truncated;
      finishResponseObservation({
        byteAllowance: byteLimit,
        capturedBytes,
        observed: true,
        truncated
      });
      const candidates = extractFeatureCandidates(text);
      if (candidates.length === 0) {
        return;
      }
      featureObservationBudget.candidateEventCount += 1;
      pushEvent("feature-candidates-observed", responseUrl, {
        transport,
        responseUrl,
        status: response.status,
        contentType,
        capturedBytes,
        truncated,
        candidates
      });
    };
    const inspectXhr = (request) => {
      const responseUrl = request.responseURL || location.href;
      const contentType = request.getResponseHeader("content-type") ?? "";
      if (!shouldInspectResponse(contentType, responseUrl)) {
        return;
      }
      const byteLimit = beginResponseObservation();
      if (byteLimit === void 0) {
        return;
      }
      let text = "";
      let sourceTruncated = false;
      try {
        if (request.responseType === "" || request.responseType === "text") {
          const responseText = request.responseText;
          sourceTruncated = responseText.length > byteLimit;
          text = responseText.slice(0, byteLimit);
        } else if (request.responseType === "json") {
          const boundedJson = stringifyBoundedJson(request.response, byteLimit);
          text = boundedJson.text;
          sourceTruncated = boundedJson.truncated;
        }
      } catch {
        finishResponseObservation({
          byteAllowance: byteLimit,
          capturedBytes: 0,
          observed: false,
          truncated: false,
          dropReason: "body-read-error"
        });
        return;
      }
      if (!text) {
        finishResponseObservation({
          byteAllowance: byteLimit,
          capturedBytes: 0,
          observed: false,
          truncated: false,
          dropReason: "body-unavailable"
        });
        return;
      }
      const boundedText = truncateUtf8(text, byteLimit);
      finishResponseObservation({
        byteAllowance: byteLimit,
        capturedBytes: boundedText.bytes,
        observed: true,
        truncated: sourceTruncated || boundedText.truncated
      });
      const candidates = extractFeatureCandidates(boundedText.text);
      if (candidates.length === 0) {
        return;
      }
      featureObservationBudget.candidateEventCount += 1;
      pushEvent("feature-candidates-observed", responseUrl, {
        transport: "xhr",
        responseUrl,
        status: request.status,
        contentType,
        capturedBytes: boundedText.bytes,
        truncated: sourceTruncated || boundedText.truncated,
        candidates
      });
    };
    const describeNode = (node) => {
      const tagName = node.tagName.toLowerCase();
      if (tagName === "script") {
        return [
          {
            type: "script-added",
            url: node.src || void 0,
            attributes: {
              tagName,
              inline: !node.src,
              async: node.hasAttribute("async"),
              defer: node.hasAttribute("defer"),
              typeAttribute: node.getAttribute("type")
            }
          }
        ];
      }
      if (tagName === "link" && node.getAttribute("rel")?.includes("stylesheet")) {
        return [
          {
            type: "stylesheet-added",
            url: node.href || void 0,
            attributes: {
              tagName,
              rel: node.getAttribute("rel"),
              media: node.getAttribute("media")
            }
          }
        ];
      }
      if (tagName === "img") {
        return [
          {
            type: "image-added",
            url: node.currentSrc || node.src || void 0,
            attributes: {
              tagName,
              loading: node.getAttribute("loading")
            }
          }
        ];
      }
      if (tagName === "iframe" || tagName === "frame") {
        return [
          {
            type: "iframe-added",
            url: node.src || void 0,
            attributes: {
              tagName,
              sandbox: node.getAttribute("sandbox")
            }
          }
        ];
      }
      return [];
    };
    const recordElementTree = (node) => {
      if (!(node instanceof Element)) {
        return;
      }
      const maxVisitedElements = 200;
      const walker = node.ownerDocument.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
      let current = walker.currentNode;
      let visitedElements = 0;
      while (current && visitedElements < maxVisitedElements) {
        if (current instanceof Element) {
          for (const description of describeNode(current)) {
            pushEvent(description.type, description.url, description.attributes);
          }
        }
        visitedElements += 1;
        current = walker.nextNode();
      }
      if (current) {
        state.droppedEventCount += 1;
        state.droppedEventsByReason["mutation-subtree-node-limit"] = (state.droppedEventsByReason["mutation-subtree-node-limit"] ?? 0) + 1;
        if (!state.warnings.includes("A mutated DOM subtree exceeded the 200-element inspection cap.")) {
          state.warnings.push("A mutated DOM subtree exceeded the 200-element inspection cap.");
        }
      }
    };
    try {
      const originalCreateObjectUrl = URL.createObjectURL.bind(URL);
      URL.createObjectURL = (object) => {
        const createdUrl = originalCreateObjectUrl(object);
        pushEvent("blob-created", createdUrl, {
          objectType: object.constructor.name,
          type: "type" in object ? object.type : null,
          size: "size" in object ? object.size : null
        });
        return createdUrl;
      };
      const originalRevokeObjectUrl = URL.revokeObjectURL.bind(URL);
      URL.revokeObjectURL = (url) => {
        pushEvent("blob-revoked", url, {});
        originalRevokeObjectUrl(url);
      };
    } catch (error) {
      state.warnings.push(
        sanitizeSensitiveText(`Unable to patch URL blob APIs: ${String(error)}`, 500)
      );
    }
    try {
      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (...args) => {
        const requestUrl = typeof args[0] === "string" ? args[0] : args[0] instanceof URL ? args[0].href : args[0]?.url;
        const method = args[1]?.method ?? (typeof Request !== "undefined" && args[0] instanceof Request ? args[0].method : "GET");
        pushEvent("network-request", requestUrl, {
          transport: "fetch",
          method: String(method || "GET").toUpperCase().slice(0, 16),
          initiator: captureInitiator() ?? null
        });
        const response = await originalFetch(...args);
        try {
          void inspectResponse(response.clone(), "fetch", requestUrl);
        } catch {
        }
        return response;
      });
    } catch (error) {
      state.warnings.push(
        sanitizeSensitiveText(`Unable to observe fetch responses: ${String(error)}`, 500)
      );
    }
    try {
      const requestMetadata = /* @__PURE__ */ new WeakMap();
      const originalOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url, async = true, username, password) {
        requestMetadata.set(this, {
          method: String(method || "GET").toUpperCase().slice(0, 16),
          url: String(url)
        });
        Reflect.apply(originalOpen, this, [method, url, async, username, password]);
      };
      const originalSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.send = function(body) {
        const metadata = requestMetadata.get(this);
        pushEvent("network-request", metadata?.url, {
          transport: "xhr",
          method: metadata?.method ?? "GET",
          initiator: captureInitiator() ?? null
        });
        this.addEventListener(
          "loadend",
          () => {
            inspectXhr(this);
          },
          {
            once: true
          }
        );
        return originalSend.call(this, body);
      };
    } catch (error) {
      state.warnings.push(
        sanitizeSensitiveText(`Unable to observe XMLHttpRequest responses: ${String(error)}`, 500)
      );
    }
    if ("Worker" in window) {
      const OriginalWorker = Worker;
      window.Worker = class extends OriginalWorker {
        constructor(scriptUrl, options) {
          pushEvent("worker-constructed", String(scriptUrl), {
            type: options?.type ?? "classic",
            credentials: options?.credentials ?? null,
            name: options?.name ?? null,
            initiator: captureInitiator() ?? null
          });
          super(scriptUrl, options);
        }
      };
    }
    if ("SharedWorker" in window) {
      const OriginalSharedWorker = SharedWorker;
      window.SharedWorker = class extends OriginalSharedWorker {
        constructor(scriptUrl, options) {
          pushEvent("shared-worker-constructed", String(scriptUrl), {
            name: typeof options === "string" ? options : options?.name ?? null,
            initiator: captureInitiator() ?? null
          });
          super(scriptUrl, options);
        }
      };
    }
    if ("WebSocket" in window) {
      try {
        const OriginalWebSocket = WebSocket;
        window.WebSocket = class extends OriginalWebSocket {
          constructor(url, protocols) {
            pushEvent("websocket-constructed", String(url), {
              protocolCount: Array.isArray(protocols) ? protocols.length : protocols ? 1 : 0,
              initiator: captureInitiator() ?? null
            });
            super(url, protocols ?? []);
          }
        };
      } catch (error) {
        state.warnings.push(
          sanitizeSensitiveText(`Unable to observe WebSocket construction: ${String(error)}`, 500)
        );
      }
    }
    if ("EventSource" in window) {
      try {
        const OriginalEventSource = EventSource;
        window.EventSource = class extends OriginalEventSource {
          constructor(url, eventSourceInitDict) {
            pushEvent("eventsource-constructed", String(url), {
              withCredentials: eventSourceInitDict?.withCredentials === true,
              initiator: captureInitiator() ?? null
            });
            super(url, eventSourceInitDict);
          }
        };
      } catch (error) {
        state.warnings.push(
          sanitizeSensitiveText(`Unable to observe EventSource construction: ${String(error)}`, 500)
        );
      }
    }
    if (typeof navigator.sendBeacon === "function") {
      try {
        const originalSendBeacon = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = (url, data) => {
          const approximateBytes = typeof data === "string" ? data.length : data instanceof Blob ? data.size : data instanceof ArrayBuffer ? data.byteLength : ArrayBuffer.isView(data) ? data.byteLength : void 0;
          pushEvent("beacon-sent", String(url), {
            approximateBytes: approximateBytes ?? null,
            approximateBytesBasis: typeof data === "string" ? "utf16-code-units" : "binary-size",
            initiator: captureInitiator() ?? null
          });
          return originalSendBeacon(url, data);
        };
      } catch (error) {
        state.warnings.push(
          sanitizeSensitiveText(`Unable to observe beacon sends: ${String(error)}`, 500)
        );
      }
    }
    try {
      const originalSetItem = Storage.prototype.setItem;
      const originalRemoveItem = Storage.prototype.removeItem;
      const originalClear = Storage.prototype.clear;
      const storageArea = (target) => {
        try {
          if (target === window.localStorage) return "localStorage";
          if (target === window.sessionStorage) return "sessionStorage";
        } catch {
        }
        return "storage";
      };
      Storage.prototype.setItem = function(key, value) {
        pushEvent("storage-write", void 0, {
          area: storageArea(this),
          operation: "setItem",
          key: String(key).slice(0, 180),
          valueLength: String(value).length,
          initiator: captureInitiator() ?? null
        });
        originalSetItem.call(this, key, value);
      };
      Storage.prototype.removeItem = function(key) {
        pushEvent("storage-write", void 0, {
          area: storageArea(this),
          operation: "removeItem",
          key: String(key).slice(0, 180),
          initiator: captureInitiator() ?? null
        });
        originalRemoveItem.call(this, key);
      };
      Storage.prototype.clear = function() {
        pushEvent("storage-write", void 0, {
          area: storageArea(this),
          operation: "clear",
          initiator: captureInitiator() ?? null
        });
        originalClear.call(this);
      };
    } catch (error) {
      state.warnings.push(
        sanitizeSensitiveText(`Unable to observe browser storage writes: ${String(error)}`, 500)
      );
    }
    try {
      for (const methodName of ["pushState", "replaceState"]) {
        const original = history[methodName].bind(history);
        history[methodName] = ((data, unused, url) => {
          pushEvent("route-change", String(url ?? location.href), {
            operation: methodName,
            initiator: captureInitiator() ?? null
          });
          original(data, unused, url);
        });
      }
    } catch (error) {
      state.warnings.push(
        sanitizeSensitiveText(`Unable to observe history route changes: ${String(error)}`, 500)
      );
    }
    window.addEventListener("error", (event) => {
      pushEvent("runtime-error", event.filename || void 0, {
        ...safeErrorSummary(event.error ?? event.message),
        line: event.lineno || null,
        column: event.colno || null
      });
    });
    window.addEventListener("unhandledrejection", (event) => {
      pushEvent("unhandled-rejection", void 0, safeErrorSummary(event.reason));
    });
    let domMutationEventCount = 0;
    const observer = new MutationObserver((mutations) => {
      let addedNodes = 0;
      let removedNodes = 0;
      let attributeChanges = 0;
      for (const mutation of mutations) {
        addedNodes += mutation.addedNodes.length;
        removedNodes += mutation.removedNodes.length;
        attributeChanges += mutation.type === "attributes" ? 1 : 0;
        for (const addedNode of Array.from(mutation.addedNodes)) {
          recordElementTree(addedNode);
        }
      }
      if (domMutationEventCount < 50) {
        domMutationEventCount += 1;
        pushEvent("dom-mutation", void 0, {
          mutationCount: mutations.length,
          addedNodes,
          removedNodes,
          attributeChanges
        });
      } else {
        state.droppedEventCount += 1;
        state.droppedEventsByReason["dom-mutation-event-limit"] = (state.droppedEventsByReason["dom-mutation-event-limit"] ?? 0) + 1;
      }
    });
    if (document.documentElement) {
      observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true
      });
    } else {
      state.warnings.push("Document root was unavailable when MutationObserver started.");
    }
    document.addEventListener(
      "DOMContentLoaded",
      () => {
        pushEvent("lifecycle", void 0, {
          stage: "domcontentloaded"
        });
      },
      { once: true }
    );
    window.addEventListener(
      "load",
      () => {
        pushEvent("lifecycle", void 0, {
          stage: "load"
        });
      },
      { once: true }
    );
    const buildCoverage = () => ({
      eventBuffer: {
        limit: maxInstrumentationEvents,
        retainedEventCount: state.events.length,
        droppedEventCount: state.droppedEventCount,
        droppedByReason: { ...state.droppedEventsByReason }
      },
      responseObservation: {
        responseLimit: maxObservedResponses,
        perResponseByteLimit: maxObservedResponseBytes,
        totalByteLimit: maxObservedTotalBytes,
        eligibleResponseCount: featureObservationBudget.eligibleResponseCount,
        startedResponseCount: featureObservationBudget.startedResponseCount,
        observedResponseCount: featureObservationBudget.observedResponseCount,
        candidateEventCount: featureObservationBudget.candidateEventCount,
        capturedBytes: featureObservationBudget.capturedBytes,
        droppedResponseCount: featureObservationBudget.droppedResponseCount,
        truncatedResponseCount: featureObservationBudget.truncatedResponseCount,
        droppedByReason: { ...featureObservationBudget.droppedByReason },
        truncatedByReason: { ...featureObservationBudget.truncatedByReason }
      }
    });
    const formatReasonCounts = (reasons) => Object.entries(reasons).sort(([left], [right]) => left.localeCompare(right)).map(([reason, count]) => `${reason}=${count}`).join(", ");
    const buildCoverageWarnings = () => {
      const warnings = [];
      if (state.droppedEventCount > 0) {
        warnings.push(
          `Instrumentation coverage dropped ${state.droppedEventCount} event observation${state.droppedEventCount === 1 ? "" : "s"}: ${formatReasonCounts(state.droppedEventsByReason)}.`
        );
      }
      if (featureObservationBudget.droppedResponseCount > 0) {
        warnings.push(
          `Runtime response coverage dropped ${featureObservationBudget.droppedResponseCount} eligible body observation${featureObservationBudget.droppedResponseCount === 1 ? "" : "s"}: ${formatReasonCounts(featureObservationBudget.droppedByReason)}.`
        );
      }
      if (featureObservationBudget.truncatedResponseCount > 0) {
        warnings.push(
          `Runtime response coverage truncated ${featureObservationBudget.truncatedResponseCount} body observation${featureObservationBudget.truncatedResponseCount === 1 ? "" : "s"}: ${formatReasonCounts(featureObservationBudget.truncatedByReason)}.`
        );
      }
      return warnings;
    };
    window.addEventListener("message", (event) => {
      if (event.source !== window || !event.data || event.data.__blanche !== "burp-bridge") {
        return;
      }
      if (event.data.type !== "instrumentation-snapshot-request") {
        return;
      }
      postBridgeMessage("instrumentation-snapshot-response", {
        requestId: event.data.payload.requestId,
        snapshot: {
          version: state.version,
          startedAt: state.startedAt,
          pageUrl: sanitizeObservedUrl(location.href),
          events: [...state.events],
          warnings: [
            ...state.warnings.map((warning) => sanitizeSensitiveText(warning, 500)),
            ...buildCoverageWarnings()
          ].slice(0, 100),
          coverage: buildCoverage()
        }
      });
    });
    postBridgeMessage("instrumentation-ready", {
      startedAt: state.startedAt
    });
  })();
})();
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vLi4vc3JjL2NvbnRlbnQvcGFnZUluc3RydW1lbnRvci50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiKCgpID0+IHtcbiAgY29uc3QgZ2xvYmFsS2V5ID0gJ19fYmxhbmNoZUJ1cnBCcmlkZ2VJbnN0cnVtZW50ZWQnO1xuICBpZiAoKHdpbmRvdyBhcyBXaW5kb3cgJiB7IFtnbG9iYWxLZXldPzogYm9vbGVhbiB9KVtnbG9iYWxLZXldKSB7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgKHdpbmRvdyBhcyBXaW5kb3cgJiB7IFtnbG9iYWxLZXldPzogYm9vbGVhbiB9KVtnbG9iYWxLZXldID0gdHJ1ZTtcbiAgZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50Py5zZXRBdHRyaWJ1dGUoJ2RhdGEtYmxhbmNoZS1idXJwLWJyaWRnZScsICd0cnVlJyk7XG5cbiAgdHlwZSBJbnN0cnVtZW50YXRpb25FdmVudCA9IHtcbiAgICBpZDogc3RyaW5nO1xuICAgIHR5cGU6XG4gICAgICB8ICdibG9iLWNyZWF0ZWQnXG4gICAgICB8ICdibG9iLXJldm9rZWQnXG4gICAgICB8ICdzY3JpcHQtYWRkZWQnXG4gICAgICB8ICdzdHlsZXNoZWV0LWFkZGVkJ1xuICAgICAgfCAnaW1hZ2UtYWRkZWQnXG4gICAgICB8ICdpZnJhbWUtYWRkZWQnXG4gICAgICB8ICd3b3JrZXItY29uc3RydWN0ZWQnXG4gICAgICB8ICdzaGFyZWQtd29ya2VyLWNvbnN0cnVjdGVkJ1xuICAgICAgfCAnd2Vic29ja2V0LWNvbnN0cnVjdGVkJ1xuICAgICAgfCAnZXZlbnRzb3VyY2UtY29uc3RydWN0ZWQnXG4gICAgICB8ICduZXR3b3JrLXJlcXVlc3QnXG4gICAgICB8ICdiZWFjb24tc2VudCdcbiAgICAgIHwgJ3N0b3JhZ2Utd3JpdGUnXG4gICAgICB8ICdyb3V0ZS1jaGFuZ2UnXG4gICAgICB8ICdydW50aW1lLWVycm9yJ1xuICAgICAgfCAndW5oYW5kbGVkLXJlamVjdGlvbidcbiAgICAgIHwgJ2RvbS1tdXRhdGlvbidcbiAgICAgIHwgJ2ZlYXR1cmUtY2FuZGlkYXRlcy1vYnNlcnZlZCdcbiAgICAgIHwgJ2xpZmVjeWNsZSc7XG4gICAgb2JzZXJ2ZWRBdDogc3RyaW5nO1xuICAgIHBhZ2VVcmw6IHN0cmluZztcbiAgICBmcmFtZUhyZWY6IHN0cmluZztcbiAgICB1cmw/OiBzdHJpbmc7XG4gICAgYXR0cmlidXRlczogUmVjb3JkPHN0cmluZywgdW5rbm93bj47XG4gIH07XG5cbiAgdHlwZSBJbnN0cnVtZW50YXRpb25Db3ZlcmFnZSA9IHtcbiAgICBldmVudEJ1ZmZlcjoge1xuICAgICAgbGltaXQ6IG51bWJlcjtcbiAgICAgIHJldGFpbmVkRXZlbnRDb3VudDogbnVtYmVyO1xuICAgICAgZHJvcHBlZEV2ZW50Q291bnQ6IG51bWJlcjtcbiAgICAgIGRyb3BwZWRCeVJlYXNvbjogUmVjb3JkPHN0cmluZywgbnVtYmVyPjtcbiAgICB9O1xuICAgIHJlc3BvbnNlT2JzZXJ2YXRpb246IHtcbiAgICAgIHJlc3BvbnNlTGltaXQ6IG51bWJlcjtcbiAgICAgIHBlclJlc3BvbnNlQnl0ZUxpbWl0OiBudW1iZXI7XG4gICAgICB0b3RhbEJ5dGVMaW1pdDogbnVtYmVyO1xuICAgICAgZWxpZ2libGVSZXNwb25zZUNvdW50OiBudW1iZXI7XG4gICAgICBzdGFydGVkUmVzcG9uc2VDb3VudDogbnVtYmVyO1xuICAgICAgb2JzZXJ2ZWRSZXNwb25zZUNvdW50OiBudW1iZXI7XG4gICAgICBjYW5kaWRhdGVFdmVudENvdW50OiBudW1iZXI7XG4gICAgICBjYXB0dXJlZEJ5dGVzOiBudW1iZXI7XG4gICAgICBkcm9wcGVkUmVzcG9uc2VDb3VudDogbnVtYmVyO1xuICAgICAgdHJ1bmNhdGVkUmVzcG9uc2VDb3VudDogbnVtYmVyO1xuICAgICAgZHJvcHBlZEJ5UmVhc29uOiBSZWNvcmQ8c3RyaW5nLCBudW1iZXI+O1xuICAgICAgdHJ1bmNhdGVkQnlSZWFzb246IFJlY29yZDxzdHJpbmcsIG51bWJlcj47XG4gICAgfTtcbiAgfTtcblxuICBjb25zdCBtYXhJbnN0cnVtZW50YXRpb25FdmVudHMgPSA0MDA7XG5cbiAgY29uc3Qgc3RhdGUgPSB7XG4gICAgdmVyc2lvbjogJzAuMy4wJyxcbiAgICBzdGFydGVkQXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcbiAgICBldmVudHM6IFtdIGFzIEluc3RydW1lbnRhdGlvbkV2ZW50W10sXG4gICAgd2FybmluZ3M6IFtdIGFzIHN0cmluZ1tdLFxuICAgIGRyb3BwZWRFdmVudENvdW50OiAwLFxuICAgIGRyb3BwZWRFdmVudHNCeVJlYXNvbjoge30gYXMgUmVjb3JkPHN0cmluZywgbnVtYmVyPlxuICB9O1xuXG4gIGNvbnN0IHNhbml0aXplT2JzZXJ2ZWRVcmwgPSAocmF3VXJsOiBzdHJpbmcgfCBVUkwgfCB1bmRlZmluZWQpOiBzdHJpbmcgfCB1bmRlZmluZWQgPT4ge1xuICAgIGlmIChyYXdVcmwgPT09IHVuZGVmaW5lZCkge1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHBhcnNlZCA9IG5ldyBVUkwoU3RyaW5nKHJhd1VybCksIGxvY2F0aW9uLmhyZWYpO1xuICAgICAgaWYgKHBhcnNlZC5wcm90b2NvbCAhPT0gJ2h0dHA6JyAmJiBwYXJzZWQucHJvdG9jb2wgIT09ICdodHRwczonKSB7XG4gICAgICAgIHJldHVybiBgJHtwYXJzZWQucHJvdG9jb2x9JHtwYXJzZWQucHJvdG9jb2wgPT09ICdibG9iOicgPyAnW3JlZGFjdGVkXScgOiAnJ31gO1xuICAgICAgfVxuICAgICAgcGFyc2VkLnVzZXJuYW1lID0gJyc7XG4gICAgICBwYXJzZWQucGFzc3dvcmQgPSAnJztcbiAgICAgIHBhcnNlZC5oYXNoID0gJyc7XG4gICAgICBjb25zdCBuYW1lcyA9IFsuLi5uZXcgU2V0KFsuLi5wYXJzZWQuc2VhcmNoUGFyYW1zLmtleXMoKV0pXS5zb3J0KCk7XG4gICAgICBwYXJzZWQuc2VhcmNoID0gbmFtZXMubGVuZ3RoID4gMFxuICAgICAgICA/IGA/JHtuYW1lcy5tYXAoKG5hbWUpID0+IGAke2VuY29kZVVSSUNvbXBvbmVudChuYW1lKX09YCkuam9pbignJicpfWBcbiAgICAgICAgOiAnJztcbiAgICAgIHBhcnNlZC5wYXRobmFtZSA9IHBhcnNlZC5wYXRobmFtZVxuICAgICAgICAucmVwbGFjZSgvWzAtOWEtZl17OH0tWzAtOWEtZi1dezI3LH0vZ2ksICd7dXVpZH0nKVxuICAgICAgICAucmVwbGFjZSgvXFxiWzAtOWEtZl17MjQsfVxcYi9naSwgJ3toZXh9JylcbiAgICAgICAgLnJlcGxhY2UoL1xcYlxcZHs0LH1cXGIvZywgJ3tpZH0nKTtcbiAgICAgIHJldHVybiBwYXJzZWQudG9TdHJpbmcoKTtcbiAgICB9IGNhdGNoIHtcbiAgICAgIHJldHVybiAnW3VucGFyc2VhYmxlLXVybF0nO1xuICAgIH1cbiAgfTtcblxuICBjb25zdCBzYW5pdGl6ZVNlbnNpdGl2ZVRleHQgPSAodmFsdWU6IHVua25vd24sIG1heExlbmd0aCA9IDMwMCk6IHN0cmluZyA9PiB7XG4gICAgY29uc3QgdGV4dCA9IFN0cmluZyh2YWx1ZSA/PyAnJyk7XG4gICAgcmV0dXJuIHRleHRcbiAgICAgIC5yZXBsYWNlKC9odHRwcz86XFwvXFwvW15cXHNcIic8Pl0rL2dpLCAodXJsKSA9PiBzYW5pdGl6ZU9ic2VydmVkVXJsKHVybCkgPz8gJ1tyZWRhY3RlZC11cmxdJylcbiAgICAgIC5yZXBsYWNlKC8oXFwvXFwvKVteL1xcczpAXSs6W15AXFxzL10rQC9nLCAnJDFbcmVkYWN0ZWQtY3JlZGVudGlhbHNdQCcpXG4gICAgICAucmVwbGFjZSgvKFs/Jl1bQS1aYS16MC05Xy5+JS1dezEsMTAwfSk9KFteJiNcXHNdKikvZywgJyQxPVtyZWRhY3RlZF0nKVxuICAgICAgLnJlcGxhY2UoLyNbXlxcc1wiJzw+XSovZywgJyNbcmVkYWN0ZWRdJylcbiAgICAgIC5yZXBsYWNlKC9cXGIoYmVhcmVyKVxccytbQS1aYS16MC05Ll9+Ky89LV0rL2dpLCAnJDEgW3JlZGFjdGVkXScpXG4gICAgICAucmVwbGFjZShcbiAgICAgICAgL1xcYihwYXNzd29yZHxwYXNzd2R8c2VjcmV0fGFjY2Vzc1stX10/dG9rZW58cmVmcmVzaFstX10/dG9rZW58YXV0aG9yaXphdGlvbnxhcGlbLV9dP2tleXxzZXNzaW9uWy1fXT9pZHxjb29raWUpXFxzKls6PV1cXHMqW15cXHMsO10rL2dpLFxuICAgICAgICAnJDE9W3JlZGFjdGVkXSdcbiAgICAgIClcbiAgICAgIC5zbGljZSgwLCBtYXhMZW5ndGgpO1xuICB9O1xuXG4gIGNvbnN0IGlzVXJsTGlrZUF0dHJpYnV0ZSA9IChrZXk6IHN0cmluZyk6IGJvb2xlYW4gPT4ge1xuICAgIGNvbnN0IG5vcm1hbGl6ZWQgPSBrZXkudG9Mb3dlckNhc2UoKS5yZXBsYWNlKC9bXmEtejAtOV0vZywgJycpO1xuICAgIHJldHVybiAoXG4gICAgICBub3JtYWxpemVkLmVuZHNXaXRoKCd1cmwnKSB8fFxuICAgICAgbm9ybWFsaXplZC5lbmRzV2l0aCgndXJpJykgfHxcbiAgICAgIG5vcm1hbGl6ZWQuZW5kc1dpdGgoJ2hyZWYnKSB8fFxuICAgICAgbm9ybWFsaXplZC5lbmRzV2l0aCgnc3JjJykgfHxcbiAgICAgIG5vcm1hbGl6ZWQgPT09ICdlbmRwb2ludCcgfHxcbiAgICAgIG5vcm1hbGl6ZWQgPT09ICdsb2NhdGlvbicgfHxcbiAgICAgIG5vcm1hbGl6ZWQgPT09ICdyZWZlcnJlcicgfHxcbiAgICAgIG5vcm1hbGl6ZWQgPT09ICdpbml0aWF0b3InXG4gICAgKTtcbiAgfTtcblxuICBjb25zdCBzYW5pdGl6ZUV2ZW50QXR0cmlidXRlcyA9IChcbiAgICBhdHRyaWJ1dGVzOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPlxuICApOiBSZWNvcmQ8c3RyaW5nLCB1bmtub3duPiA9PiB7XG4gICAgY29uc3QgdmlzaXQgPSAoa2V5OiBzdHJpbmcsIHZhbHVlOiB1bmtub3duLCBkZXB0aDogbnVtYmVyKTogdW5rbm93biA9PiB7XG4gICAgICBpZiAodmFsdWUgPT09IHVuZGVmaW5lZCB8fCB2YWx1ZSA9PT0gbnVsbCkge1xuICAgICAgICByZXR1cm4gdmFsdWU7XG4gICAgICB9XG4gICAgICBpZiAoaXNVcmxMaWtlQXR0cmlidXRlKGtleSkpIHtcbiAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkodmFsdWUpKSB7XG4gICAgICAgICAgcmV0dXJuIHZhbHVlXG4gICAgICAgICAgICAuc2xpY2UoMCwgMTAwKVxuICAgICAgICAgICAgLm1hcCgoZW50cnkpID0+XG4gICAgICAgICAgICAgIHR5cGVvZiBlbnRyeSA9PT0gJ3N0cmluZycgfHwgZW50cnkgaW5zdGFuY2VvZiBVUkxcbiAgICAgICAgICAgICAgICA/IHNhbml0aXplT2JzZXJ2ZWRVcmwoZW50cnkpID8/ICdbcmVkYWN0ZWQtdXJsXSdcbiAgICAgICAgICAgICAgICA6IHZpc2l0KGtleSwgZW50cnksIGRlcHRoICsgMSlcbiAgICAgICAgICAgICk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycgfHwgdmFsdWUgaW5zdGFuY2VvZiBVUkwpIHtcbiAgICAgICAgICByZXR1cm4gc2FuaXRpemVPYnNlcnZlZFVybCh2YWx1ZSkgPz8gJ1tyZWRhY3RlZC11cmxdJztcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgaWYgKGRlcHRoID49IDUpIHtcbiAgICAgICAgcmV0dXJuICdbZGVwdGgtbGltaXRdJztcbiAgICAgIH1cbiAgICAgIGlmIChBcnJheS5pc0FycmF5KHZhbHVlKSkge1xuICAgICAgICByZXR1cm4gdmFsdWUuc2xpY2UoMCwgMTAwKS5tYXAoKGVudHJ5KSA9PiB2aXNpdChrZXksIGVudHJ5LCBkZXB0aCArIDEpKTtcbiAgICAgIH1cbiAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdvYmplY3QnKSB7XG4gICAgICAgIHJldHVybiBPYmplY3QuZnJvbUVudHJpZXMoXG4gICAgICAgICAgT2JqZWN0LmVudHJpZXModmFsdWUgYXMgUmVjb3JkPHN0cmluZywgdW5rbm93bj4pXG4gICAgICAgICAgICAuc2xpY2UoMCwgMTAwKVxuICAgICAgICAgICAgLm1hcCgoW2NoaWxkS2V5LCBlbnRyeV0pID0+IFtjaGlsZEtleSwgdmlzaXQoY2hpbGRLZXksIGVudHJ5LCBkZXB0aCArIDEpXSlcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiB2YWx1ZTtcbiAgICB9O1xuXG4gICAgcmV0dXJuIE9iamVjdC5mcm9tRW50cmllcyhcbiAgICAgIE9iamVjdC5lbnRyaWVzKGF0dHJpYnV0ZXMpXG4gICAgICAgIC5zbGljZSgwLCAxMDApXG4gICAgICAgIC5tYXAoKFtrZXksIHZhbHVlXSkgPT4gW2tleSwgdmlzaXQoa2V5LCB2YWx1ZSwgMCldKVxuICAgICk7XG4gIH07XG5cbiAgY29uc3QgY2FwdHVyZUluaXRpYXRvciA9ICgpOiBzdHJpbmcgfCB1bmRlZmluZWQgPT4ge1xuICAgIGNvbnN0IHN0YWNrID0gbmV3IEVycm9yKCkuc3RhY2sgPz8gJyc7XG4gICAgZm9yIChjb25zdCBsaW5lIG9mIHN0YWNrLnNwbGl0KCdcXG4nKS5zbGljZSgyLCAxMCkpIHtcbiAgICAgIGNvbnN0IG1hdGNoID0gbGluZS5tYXRjaCgvKGh0dHBzPzpcXC9cXC9bXlxccyldKz8pKD86OlxcZCspezEsMn0oPzpcXCk/JHxcXHMpL2kpO1xuICAgICAgaWYgKCFtYXRjaD8uWzFdKSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgcmV0dXJuIG1hdGNoWzFdO1xuICAgIH1cbiAgICByZXR1cm4gdW5kZWZpbmVkO1xuICB9O1xuXG4gIGNvbnN0IHNhZmVFcnJvclN1bW1hcnkgPSAoXG4gICAgdmFsdWU6IHVua25vd25cbiAgKTogeyBuYW1lOiBzdHJpbmc7IG1lc3NhZ2U/OiBzdHJpbmc7IG1lc3NhZ2VMZW5ndGg/OiBudW1iZXIgfSA9PiB7XG4gICAgaWYgKHZhbHVlIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSBTdHJpbmcodmFsdWUubWVzc2FnZSA/PyAnJyk7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBuYW1lOiBzYW5pdGl6ZVNlbnNpdGl2ZVRleHQodmFsdWUubmFtZSB8fCAnRXJyb3InLCA4MCksXG4gICAgICAgIG1lc3NhZ2U6IG1lc3NhZ2UgPyBzYW5pdGl6ZVNlbnNpdGl2ZVRleHQobWVzc2FnZSkgOiB1bmRlZmluZWQsXG4gICAgICAgIG1lc3NhZ2VMZW5ndGg6IG1lc3NhZ2UubGVuZ3RoXG4gICAgICB9O1xuICAgIH1cbiAgICBjb25zdCBtZXNzYWdlID1cbiAgICAgIHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycgfHwgdHlwZW9mIHZhbHVlID09PSAnbnVtYmVyJyB8fCB0eXBlb2YgdmFsdWUgPT09ICdib29sZWFuJ1xuICAgICAgICA/IFN0cmluZyh2YWx1ZSlcbiAgICAgICAgOiAnJztcbiAgICByZXR1cm4ge1xuICAgICAgbmFtZTogdHlwZW9mIHZhbHVlLFxuICAgICAgbWVzc2FnZTogbWVzc2FnZSA/IHNhbml0aXplU2Vuc2l0aXZlVGV4dChtZXNzYWdlKSA6IHVuZGVmaW5lZCxcbiAgICAgIG1lc3NhZ2VMZW5ndGg6IG1lc3NhZ2UubGVuZ3RoIHx8IHVuZGVmaW5lZFxuICAgIH07XG4gIH07XG5cbiAgdHlwZSBPYnNlcnZlZEZlYXR1cmVDYW5kaWRhdGUgPSB7XG4gICAga2V5OiBzdHJpbmc7XG4gICAgY3VycmVudFZhbHVlPzogYm9vbGVhbiB8IG51bWJlciB8IHN0cmluZyB8IG51bGw7XG4gICAgc3VnZ2VzdGVkVmFsdWU/OiBib29sZWFuIHwgbnVtYmVyIHwgc3RyaW5nIHwgbnVsbDtcbiAgICBjb25maWRlbmNlOiAnaGlnaCcgfCAnbWVkaXVtJyB8ICdsb3cnO1xuICAgIGRldGFpbDogc3RyaW5nO1xuICB9O1xuXG4gIGNvbnN0IGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldCA9IHtcbiAgICBlbGlnaWJsZVJlc3BvbnNlQ291bnQ6IDAsXG4gICAgc3RhcnRlZFJlc3BvbnNlQ291bnQ6IDAsXG4gICAgb2JzZXJ2ZWRSZXNwb25zZUNvdW50OiAwLFxuICAgIGNhbmRpZGF0ZUV2ZW50Q291bnQ6IDAsXG4gICAgY2FwdHVyZWRCeXRlczogMCxcbiAgICByZXNlcnZlZEJ5dGVzOiAwLFxuICAgIGRyb3BwZWRSZXNwb25zZUNvdW50OiAwLFxuICAgIHRydW5jYXRlZFJlc3BvbnNlQ291bnQ6IDAsXG4gICAgZHJvcHBlZEJ5UmVhc29uOiB7fSBhcyBSZWNvcmQ8c3RyaW5nLCBudW1iZXI+LFxuICAgIHRydW5jYXRlZEJ5UmVhc29uOiB7fSBhcyBSZWNvcmQ8c3RyaW5nLCBudW1iZXI+XG4gIH07XG4gIGNvbnN0IG1heE9ic2VydmVkUmVzcG9uc2VzID0gNDA7XG4gIGNvbnN0IG1heE9ic2VydmVkUmVzcG9uc2VCeXRlcyA9IDMyNzY4O1xuICBjb25zdCBtYXhPYnNlcnZlZFRvdGFsQnl0ZXMgPSA1MjQyODg7XG5cbiAgY29uc3QgcG9zdEJyaWRnZU1lc3NhZ2UgPSAodHlwZTogc3RyaW5nLCBwYXlsb2FkOiB1bmtub3duKSA9PiB7XG4gICAgd2luZG93LnBvc3RNZXNzYWdlKFxuICAgICAge1xuICAgICAgICBfX2JsYW5jaGU6ICdidXJwLWJyaWRnZScsXG4gICAgICAgIHR5cGUsXG4gICAgICAgIHBheWxvYWRcbiAgICAgIH0sXG4gICAgICAnKidcbiAgICApO1xuICB9O1xuXG4gIGNvbnN0IHB1c2hFdmVudCA9IChcbiAgICB0eXBlOiBJbnN0cnVtZW50YXRpb25FdmVudFsndHlwZSddLFxuICAgIHVybDogc3RyaW5nIHwgdW5kZWZpbmVkLFxuICAgIGF0dHJpYnV0ZXM6IFJlY29yZDxzdHJpbmcsIHVua25vd24+XG4gICkgPT4ge1xuICAgIGNvbnN0IGV2ZW50OiBJbnN0cnVtZW50YXRpb25FdmVudCA9IHtcbiAgICAgIGlkOiBjcnlwdG8ucmFuZG9tVVVJRCgpLFxuICAgICAgdHlwZSxcbiAgICAgIG9ic2VydmVkQXQ6IG5ldyBEYXRlKCkudG9JU09TdHJpbmcoKSxcbiAgICAgIHBhZ2VVcmw6IHNhbml0aXplT2JzZXJ2ZWRVcmwobG9jYXRpb24uaHJlZikgPz8gJ1tyZWRhY3RlZC11cmxdJyxcbiAgICAgIGZyYW1lSHJlZjogc2FuaXRpemVPYnNlcnZlZFVybChsb2NhdGlvbi5ocmVmKSA/PyAnW3JlZGFjdGVkLXVybF0nLFxuICAgICAgdXJsOiBzYW5pdGl6ZU9ic2VydmVkVXJsKHVybCksXG4gICAgICBhdHRyaWJ1dGVzOiBzYW5pdGl6ZUV2ZW50QXR0cmlidXRlcyhhdHRyaWJ1dGVzKVxuICAgIH07XG5cbiAgICBzdGF0ZS5ldmVudHMudW5zaGlmdChldmVudCk7XG4gICAgaWYgKHN0YXRlLmV2ZW50cy5sZW5ndGggPiBtYXhJbnN0cnVtZW50YXRpb25FdmVudHMpIHtcbiAgICAgIGNvbnN0IGRyb3BwZWQgPSBzdGF0ZS5ldmVudHMubGVuZ3RoIC0gbWF4SW5zdHJ1bWVudGF0aW9uRXZlbnRzO1xuICAgICAgc3RhdGUuZXZlbnRzLmxlbmd0aCA9IG1heEluc3RydW1lbnRhdGlvbkV2ZW50cztcbiAgICAgIHN0YXRlLmRyb3BwZWRFdmVudENvdW50ICs9IGRyb3BwZWQ7XG4gICAgICBzdGF0ZS5kcm9wcGVkRXZlbnRzQnlSZWFzb25bJ2V2ZW50LWJ1ZmZlci1saW1pdCddID1cbiAgICAgICAgKHN0YXRlLmRyb3BwZWRFdmVudHNCeVJlYXNvblsnZXZlbnQtYnVmZmVyLWxpbWl0J10gPz8gMCkgKyBkcm9wcGVkO1xuICAgIH1cbiAgICBwb3N0QnJpZGdlTWVzc2FnZSgnaW5zdHJ1bWVudGF0aW9uLWV2ZW50JywgZXZlbnQpO1xuICB9O1xuXG4gIGNvbnN0IGxvb2tzTGlrZUZsYWdOYW1lID0gKHZhbHVlOiBzdHJpbmcpOiBib29sZWFuID0+IHtcbiAgICByZXR1cm4gKFxuICAgICAgLyg/Ol58Wy1fLjovXSkoPzpmZWF0dXJlfGZlYXR1cmVzfGZsYWd8ZmxhZ3N8ZXhwZXJpbWVudHxleHBlcmltZW50c3x2YXJpYW50fHZhcmlhdGlvbnxyb2xsb3V0fGJldGF8cHJldmlld3xsYWJzP3xnYXRlfGdhdGVzfHRvZ2dsZXx0b2dnbGVzfGVuYWJsZWQ/fGRpc2FibGVkPykoPzokfFstXy46L10pL2kudGVzdChcbiAgICAgICAgdmFsdWVcbiAgICAgICkgfHxcbiAgICAgIC8oPzpmZWF0dXJlfGZsYWd8ZXhwZXJpbWVudHx2YXJpYW50fHZhcmlhdGlvbnxyb2xsb3V0fHByZXZpZXd8YmV0YXxsYWJzP3xnYXRlfHRvZ2dsZXxlbmFibGVkfGRpc2FibGVkfG5ld1tBLVpdfGxlZ2FjeVtBLVpdKS8udGVzdChcbiAgICAgICAgdmFsdWVcbiAgICAgIClcbiAgICApO1xuICB9O1xuXG4gIGNvbnN0IGxvb2tzU2Vuc2l0aXZlID0gKHZhbHVlOiBzdHJpbmcpOiBib29sZWFuID0+IHtcbiAgICByZXR1cm4gLyg/Ol58Wy1fLjovXSkoPzphdXRofGF1dGhvcml6YXRpb258YWNjZXNzWy1fXT90b2tlbnxyZWZyZXNoWy1fXT90b2tlbnxqd3R8Y3NyZnxwYXNzd29yZHxwYXNzd2R8c2VjcmV0fGNyZWRlbnRpYWx8c2Vzc2lvblstX10/aWR8bGljZW5zZXxzdWJzY3JpcHRpb258cGVybWlzc2lvbnxyb2xlKSg/OiR8Wy1fLjovXSkvaS50ZXN0KFxuICAgICAgdmFsdWVcbiAgICApO1xuICB9O1xuXG4gIGNvbnN0IHRvZ2dsZVZhbHVlcyA9IChcbiAgICB2YWx1ZTogdW5rbm93blxuICApOlxuICAgIHwge1xuICAgICAgICBjdXJyZW50VmFsdWU6IGJvb2xlYW4gfCBudW1iZXIgfCBzdHJpbmc7XG4gICAgICAgIHN1Z2dlc3RlZFZhbHVlOiBib29sZWFuIHwgbnVtYmVyIHwgc3RyaW5nO1xuICAgICAgfVxuICAgIHwgdW5kZWZpbmVkID0+IHtcbiAgICBpZiAodmFsdWUgPT09IHRydWUgfHwgdmFsdWUgPT09IGZhbHNlKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBjdXJyZW50VmFsdWU6IHZhbHVlLFxuICAgICAgICBzdWdnZXN0ZWRWYWx1ZTogIXZhbHVlXG4gICAgICB9O1xuICAgIH1cbiAgICBpZiAodmFsdWUgPT09IDAgfHwgdmFsdWUgPT09IDEpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGN1cnJlbnRWYWx1ZTogdmFsdWUsXG4gICAgICAgIHN1Z2dlc3RlZFZhbHVlOiB2YWx1ZSA9PT0gMCA/IDEgOiAwXG4gICAgICB9O1xuICAgIH1cbiAgICBpZiAodHlwZW9mIHZhbHVlICE9PSAnc3RyaW5nJykge1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG4gICAgY29uc3Qgbm9ybWFsaXplZCA9IHZhbHVlLnRyaW0oKS50b0xvd2VyQ2FzZSgpO1xuICAgIGNvbnN0IHBhaXJzOiBSZWNvcmQ8c3RyaW5nLCBzdHJpbmc+ID0ge1xuICAgICAgZmFsc2U6ICd0cnVlJyxcbiAgICAgIHRydWU6ICdmYWxzZScsXG4gICAgICAnMCc6ICcxJyxcbiAgICAgICcxJzogJzAnLFxuICAgICAgb2ZmOiAnb24nLFxuICAgICAgb246ICdvZmYnLFxuICAgICAgZGlzYWJsZWQ6ICdlbmFibGVkJyxcbiAgICAgIGVuYWJsZWQ6ICdkaXNhYmxlZCcsXG4gICAgICBubzogJ3llcycsXG4gICAgICB5ZXM6ICdubycsXG4gICAgICBjb250cm9sOiAndHJlYXRtZW50JyxcbiAgICAgIHRyZWF0bWVudDogJ2NvbnRyb2wnXG4gICAgfTtcbiAgICBjb25zdCBzdWdnZXN0ZWRWYWx1ZSA9IHBhaXJzW25vcm1hbGl6ZWRdO1xuICAgIHJldHVybiBzdWdnZXN0ZWRWYWx1ZVxuICAgICAgPyB7XG4gICAgICAgICAgY3VycmVudFZhbHVlOiB2YWx1ZSxcbiAgICAgICAgICBzdWdnZXN0ZWRWYWx1ZVxuICAgICAgICB9XG4gICAgICA6IHVuZGVmaW5lZDtcbiAgfTtcblxuICBjb25zdCBleHRyYWN0RmVhdHVyZUNhbmRpZGF0ZXMgPSAodGV4dDogc3RyaW5nKTogT2JzZXJ2ZWRGZWF0dXJlQ2FuZGlkYXRlW10gPT4ge1xuICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBuZXcgTWFwPHN0cmluZywgT2JzZXJ2ZWRGZWF0dXJlQ2FuZGlkYXRlPigpO1xuICAgIGNvbnN0IG9ic2VydmUgPSAoY2FuZGlkYXRlOiBPYnNlcnZlZEZlYXR1cmVDYW5kaWRhdGUpID0+IHtcbiAgICAgIGNvbnN0IGtleSA9IGNhbmRpZGF0ZS5rZXkudHJpbSgpLnNsaWNlKDAsIDE4MCk7XG4gICAgICBpZiAoa2V5Lmxlbmd0aCA8IDIgfHwgbG9va3NTZW5zaXRpdmUoa2V5KSkge1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjb25zdCBzaWduYXR1cmUgPSBrZXkudG9Mb3dlckNhc2UoKS5yZXBsYWNlKC9bXmEtejAtOV0rL2csICctJyk7XG4gICAgICBjb25zdCBleGlzdGluZyA9IGNhbmRpZGF0ZXMuZ2V0KHNpZ25hdHVyZSk7XG4gICAgICBpZiAoIWV4aXN0aW5nIHx8IChleGlzdGluZy5jb25maWRlbmNlICE9PSAnaGlnaCcgJiYgY2FuZGlkYXRlLmNvbmZpZGVuY2UgPT09ICdoaWdoJykpIHtcbiAgICAgICAgY2FuZGlkYXRlcy5zZXQoc2lnbmF0dXJlLCB7XG4gICAgICAgICAgLi4uY2FuZGlkYXRlLFxuICAgICAgICAgIGtleVxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHBhcnNlZCA9IEpTT04ucGFyc2UodGV4dCkgYXMgdW5rbm93bjtcbiAgICAgIGxldCB2aXNpdGVkID0gMDtcbiAgICAgIGNvbnN0IHZpc2l0ID0gKHZhbHVlOiB1bmtub3duLCBpbmhlcml0ZWRGbGFnQ29udGV4dDogYm9vbGVhbikgPT4ge1xuICAgICAgICBpZiAodmlzaXRlZCA+PSA4MDAgfHwgY2FuZGlkYXRlcy5zaXplID49IDgwKSB7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIHZpc2l0ZWQgKz0gMTtcbiAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkodmFsdWUpKSB7XG4gICAgICAgICAgZm9yIChjb25zdCBlbnRyeSBvZiB2YWx1ZS5zbGljZSgwLCAxMDApKSB7XG4gICAgICAgICAgICB2aXNpdChlbnRyeSwgaW5oZXJpdGVkRmxhZ0NvbnRleHQpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCF2YWx1ZSB8fCB0eXBlb2YgdmFsdWUgIT09ICdvYmplY3QnKSB7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHJlY29yZCA9IHZhbHVlIGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xuICAgICAgICBjb25zdCBpZGVudGl0eSA9IFsnZmVhdHVyZUtleScsICdmbGFnS2V5JywgJ2tleScsICdmZWF0dXJlJywgJ25hbWUnLCAnaWQnXVxuICAgICAgICAgIC5tYXAoKGtleSkgPT4gcmVjb3JkW2tleV0pXG4gICAgICAgICAgLmZpbmQoKGVudHJ5KTogZW50cnkgaXMgc3RyaW5nID0+IHR5cGVvZiBlbnRyeSA9PT0gJ3N0cmluZycgJiYgZW50cnkubGVuZ3RoID49IDIpO1xuICAgICAgICBjb25zdCBzdGF0ZUVudHJ5ID0gWydlbmFibGVkJywgJ2lzRW5hYmxlZCcsICd2YWx1ZScsICd2YXJpYXRpb24nLCAndmFyaWFudCcsICdzdGF0ZSddXG4gICAgICAgICAgLm1hcCgoa2V5KSA9PiBba2V5LCByZWNvcmRba2V5XV0gYXMgY29uc3QpXG4gICAgICAgICAgLmZpbmQoKGVudHJ5KSA9PiB0b2dnbGVWYWx1ZXMoZW50cnlbMV0pICE9PSB1bmRlZmluZWQpO1xuICAgICAgICBpZiAoaWRlbnRpdHkgJiYgc3RhdGVFbnRyeSAmJiAhbG9va3NTZW5zaXRpdmUoaWRlbnRpdHkpKSB7XG4gICAgICAgICAgY29uc3QgdG9nZ2xlID0gdG9nZ2xlVmFsdWVzKHN0YXRlRW50cnlbMV0pO1xuICAgICAgICAgIGlmICh0b2dnbGUpIHtcbiAgICAgICAgICAgIG9ic2VydmUoe1xuICAgICAgICAgICAgICBrZXk6IGlkZW50aXR5LFxuICAgICAgICAgICAgICAuLi50b2dnbGUsXG4gICAgICAgICAgICAgIGNvbmZpZGVuY2U6ICdoaWdoJyxcbiAgICAgICAgICAgICAgZGV0YWlsOiBgRmVhdHVyZSByZWNvcmQgYXNzb2NpYXRlcyAke3N0YXRlRW50cnlbMF19IHdpdGggYW4gZXhwbGljaXQga2V5IGluIGEgcmVzcG9uc2UgYWxyZWFkeSBkZWxpdmVyZWQgdG8gdGhlIHBhZ2UuYFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZm9yIChjb25zdCBba2V5LCBlbnRyeV0gb2YgT2JqZWN0LmVudHJpZXMocmVjb3JkKS5zbGljZSgwLCAyMDApKSB7XG4gICAgICAgICAgY29uc3QgZmxhZ0NvbnRleHQgPSBpbmhlcml0ZWRGbGFnQ29udGV4dCB8fCBsb29rc0xpa2VGbGFnTmFtZShrZXkpO1xuICAgICAgICAgIGNvbnN0IHRvZ2dsZSA9IHRvZ2dsZVZhbHVlcyhlbnRyeSk7XG4gICAgICAgICAgaWYgKHRvZ2dsZSAmJiBmbGFnQ29udGV4dCAmJiAoIWlkZW50aXR5IHx8IHN0YXRlRW50cnk/LlswXSAhPT0ga2V5KSkge1xuICAgICAgICAgICAgb2JzZXJ2ZSh7XG4gICAgICAgICAgICAgIGtleSxcbiAgICAgICAgICAgICAgLi4udG9nZ2xlLFxuICAgICAgICAgICAgICBjb25maWRlbmNlOiBsb29rc0xpa2VGbGFnTmFtZShrZXkpID8gJ2hpZ2gnIDogJ21lZGl1bScsXG4gICAgICAgICAgICAgIGRldGFpbDogJ0ZsYWctc2hhcGVkIHZhbHVlIGluIGEgcmVzcG9uc2UgYWxyZWFkeSBkZWxpdmVyZWQgdG8gdGhlIHBhZ2UuJ1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmIChlbnRyeSAmJiB0eXBlb2YgZW50cnkgPT09ICdvYmplY3QnKSB7XG4gICAgICAgICAgICB2aXNpdChlbnRyeSwgZmxhZ0NvbnRleHQpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfTtcbiAgICAgIHZpc2l0KHBhcnNlZCwgZmFsc2UpO1xuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gSmF2YVNjcmlwdCBhbmQgbm9uLUpTT04gY29uZmlndXJhdGlvbiBhcmUgaGFuZGxlZCBieSB0aGUgY29tcGFjdC1zb3VyY2UgcGF0dGVybnMgYmVsb3cuXG4gICAgfVxuXG4gICAgY29uc3QgcHJvdmlkZXJQYXR0ZXJuID1cbiAgICAgIC8oPzppc0VuYWJsZWR8aXNGZWF0dXJlRW5hYmxlZHxmZWF0dXJlRW5hYmxlZHxoYXNGZWF0dXJlfHVzZUZlYXR1cmV8dmFyaWF0aW9ufGdldEZlYXR1cmVGbGFnfGdldEJvb2xlYW5WYWx1ZXxjaGVja0dhdGV8aXNHYXRlRW5hYmxlZClcXHMqXFwoXFxzKltcIidgXShbXlwiJ2BdezIsMTYwfSlbXCInYF0vZztcbiAgICBmb3IgKGNvbnN0IG1hdGNoIG9mIHRleHQubWF0Y2hBbGwocHJvdmlkZXJQYXR0ZXJuKSkge1xuICAgICAgaWYgKG1hdGNoWzFdKSB7XG4gICAgICAgIG9ic2VydmUoe1xuICAgICAgICAgIGtleTogbWF0Y2hbMV0sXG4gICAgICAgICAgc3VnZ2VzdGVkVmFsdWU6IHRydWUsXG4gICAgICAgICAgY29uZmlkZW5jZTogJ2hpZ2gnLFxuICAgICAgICAgIGRldGFpbDogJ0ZsYWctY2xpZW50IGNhbGxzaXRlIGluIGFuIGFscmVhZHktZGVsaXZlcmVkIHJlc3BvbnNlLidcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICBpZiAoY2FuZGlkYXRlcy5zaXplID49IDgwKSB7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgIH1cblxuICAgIGNvbnN0IHBhaXJQYXR0ZXJuID1cbiAgICAgIC8oPzpbXCInYF0oW15cIidgXXsyLDE2MH0pW1wiJ2BdfChbQS1aYS16XyRdW1xcdyQuLV17MSwxNTl9KSlcXHMqOlxccyoodHJ1ZXxmYWxzZXwhMHwhMXwwfDF8W1wiJ2BdKD86ZW5hYmxlZHxkaXNhYmxlZHxvbnxvZmZ8Y29udHJvbHx0cmVhdG1lbnR8eWVzfG5vKVtcIidgXSkvZztcbiAgICBmb3IgKGNvbnN0IG1hdGNoIG9mIHRleHQubWF0Y2hBbGwocGFpclBhdHRlcm4pKSB7XG4gICAgICBjb25zdCBrZXkgPSBtYXRjaFsxXSA/PyBtYXRjaFsyXTtcbiAgICAgIGNvbnN0IHJhdyA9IChtYXRjaFszXSA/PyAnJykucmVwbGFjZSgvXltcIidgXXxbXCInYF0kL2csICcnKTtcbiAgICAgIGNvbnN0IHRvZ2dsZSA9IHRvZ2dsZVZhbHVlcyhyYXcgPT09ICchMCcgPyB0cnVlIDogcmF3ID09PSAnITEnID8gZmFsc2UgOiByYXcpO1xuICAgICAgY29uc3QgaW5kZXggPSBtYXRjaC5pbmRleCA/PyAwO1xuICAgICAgY29uc3QgbmVhcmJ5ID0gdGV4dC5zbGljZShNYXRoLm1heCgwLCBpbmRleCAtIDEwMCksIGluZGV4ICsgMjIwKTtcbiAgICAgIGlmIChrZXkgJiYgdG9nZ2xlICYmIChsb29rc0xpa2VGbGFnTmFtZShrZXkpIHx8IC9mZWF0dXJlfGZsYWd8ZXhwZXJpbWVudHxnYXRlL2kudGVzdChuZWFyYnkpKSkge1xuICAgICAgICBvYnNlcnZlKHtcbiAgICAgICAgICBrZXksXG4gICAgICAgICAgLi4udG9nZ2xlLFxuICAgICAgICAgIGNvbmZpZGVuY2U6IGxvb2tzTGlrZUZsYWdOYW1lKGtleSkgPyAnaGlnaCcgOiAnbWVkaXVtJyxcbiAgICAgICAgICBkZXRhaWw6ICdUb2dnbGUtc2hhcGVkIGtleS92YWx1ZSBwYWlyIGluIGFuIGFscmVhZHktZGVsaXZlcmVkIHJlc3BvbnNlLidcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICBpZiAoY2FuZGlkYXRlcy5zaXplID49IDgwKSB7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiBbLi4uY2FuZGlkYXRlcy52YWx1ZXMoKV0uc2xpY2UoMCwgODApO1xuICB9O1xuXG4gIGNvbnN0IHNob3VsZEluc3BlY3RSZXNwb25zZSA9IChjb250ZW50VHlwZTogc3RyaW5nLCByZXNwb25zZVVybDogc3RyaW5nKTogYm9vbGVhbiA9PiB7XG4gICAgcmV0dXJuIChcbiAgICAgIC9qc29ufGphdmFzY3JpcHR8ZWNtYXNjcmlwdHx0ZXh0XFwvcGxhaW4vaS50ZXN0KGNvbnRlbnRUeXBlKSB8fFxuICAgICAgLyg/OmZlYXR1cmV8ZmxhZ3xleHBlcmltZW50fHZhcmlhbnR8cm9sbG91dHxib290c3RyYXB8Y29uZmlnfHNldHRpbmdzfFxcLm0/anN8XFwuanNvbikoPzokfFs/Iy9dKS9pLnRlc3QoXG4gICAgICAgIHJlc3BvbnNlVXJsXG4gICAgICApXG4gICAgKTtcbiAgfTtcblxuICBjb25zdCBpbmNyZW1lbnRSZWFzb24gPSAocmVhc29uczogUmVjb3JkPHN0cmluZywgbnVtYmVyPiwgcmVhc29uOiBzdHJpbmcpOiB2b2lkID0+IHtcbiAgICByZWFzb25zW3JlYXNvbl0gPSAocmVhc29uc1tyZWFzb25dID8/IDApICsgMTtcbiAgfTtcblxuICBjb25zdCBiZWdpblJlc3BvbnNlT2JzZXJ2YXRpb24gPSAoKTogbnVtYmVyIHwgdW5kZWZpbmVkID0+IHtcbiAgICBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQuZWxpZ2libGVSZXNwb25zZUNvdW50ICs9IDE7XG4gICAgaWYgKGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC5zdGFydGVkUmVzcG9uc2VDb3VudCA+PSBtYXhPYnNlcnZlZFJlc3BvbnNlcykge1xuICAgICAgZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmRyb3BwZWRSZXNwb25zZUNvdW50ICs9IDE7XG4gICAgICBpbmNyZW1lbnRSZWFzb24oZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmRyb3BwZWRCeVJlYXNvbiwgJ3Jlc3BvbnNlLWNvdW50LWxpbWl0Jyk7XG4gICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgIH1cblxuICAgIGNvbnN0IHJlbWFpbmluZ1RvdGFsID1cbiAgICAgIG1heE9ic2VydmVkVG90YWxCeXRlcyAtXG4gICAgICBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQuY2FwdHVyZWRCeXRlcyAtXG4gICAgICBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQucmVzZXJ2ZWRCeXRlcztcbiAgICBpZiAocmVtYWluaW5nVG90YWwgPD0gMCkge1xuICAgICAgZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmRyb3BwZWRSZXNwb25zZUNvdW50ICs9IDE7XG4gICAgICBpbmNyZW1lbnRSZWFzb24oZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmRyb3BwZWRCeVJlYXNvbiwgJ3RvdGFsLWJ5dGUtbGltaXQnKTtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgY29uc3QgYnl0ZUFsbG93YW5jZSA9IE1hdGgubWluKG1heE9ic2VydmVkUmVzcG9uc2VCeXRlcywgcmVtYWluaW5nVG90YWwpO1xuICAgIGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC5zdGFydGVkUmVzcG9uc2VDb3VudCArPSAxO1xuICAgIGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC5yZXNlcnZlZEJ5dGVzICs9IGJ5dGVBbGxvd2FuY2U7XG4gICAgcmV0dXJuIGJ5dGVBbGxvd2FuY2U7XG4gIH07XG5cbiAgY29uc3QgZmluaXNoUmVzcG9uc2VPYnNlcnZhdGlvbiA9IChpbnB1dDoge1xuICAgIGJ5dGVBbGxvd2FuY2U6IG51bWJlcjtcbiAgICBjYXB0dXJlZEJ5dGVzOiBudW1iZXI7XG4gICAgb2JzZXJ2ZWQ6IGJvb2xlYW47XG4gICAgdHJ1bmNhdGVkOiBib29sZWFuO1xuICAgIGRyb3BSZWFzb24/OiBzdHJpbmc7XG4gIH0pOiB2b2lkID0+IHtcbiAgICBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQucmVzZXJ2ZWRCeXRlcyA9IE1hdGgubWF4KFxuICAgICAgMCxcbiAgICAgIGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC5yZXNlcnZlZEJ5dGVzIC0gaW5wdXQuYnl0ZUFsbG93YW5jZVxuICAgICk7XG4gICAgZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmNhcHR1cmVkQnl0ZXMgKz0gTWF0aC5taW4oXG4gICAgICBpbnB1dC5ieXRlQWxsb3dhbmNlLFxuICAgICAgTWF0aC5tYXgoMCwgaW5wdXQuY2FwdHVyZWRCeXRlcylcbiAgICApO1xuICAgIGlmIChpbnB1dC5vYnNlcnZlZCkge1xuICAgICAgZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0Lm9ic2VydmVkUmVzcG9uc2VDb3VudCArPSAxO1xuICAgIH0gZWxzZSB7XG4gICAgICBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQuZHJvcHBlZFJlc3BvbnNlQ291bnQgKz0gMTtcbiAgICAgIGluY3JlbWVudFJlYXNvbihcbiAgICAgICAgZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmRyb3BwZWRCeVJlYXNvbixcbiAgICAgICAgaW5wdXQuZHJvcFJlYXNvbiA/PyAnYm9keS11bmF2YWlsYWJsZSdcbiAgICAgICk7XG4gICAgfVxuICAgIGlmIChpbnB1dC50cnVuY2F0ZWQpIHtcbiAgICAgIGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC50cnVuY2F0ZWRSZXNwb25zZUNvdW50ICs9IDE7XG4gICAgICBpbmNyZW1lbnRSZWFzb24oXG4gICAgICAgIGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC50cnVuY2F0ZWRCeVJlYXNvbixcbiAgICAgICAgaW5wdXQuYnl0ZUFsbG93YW5jZSA8IG1heE9ic2VydmVkUmVzcG9uc2VCeXRlc1xuICAgICAgICAgID8gJ3RvdGFsLWJ5dGUtbGltaXQnXG4gICAgICAgICAgOiAncGVyLXJlc3BvbnNlLWJ5dGUtbGltaXQnXG4gICAgICApO1xuICAgIH1cbiAgfTtcblxuICBjb25zdCB0cnVuY2F0ZVV0ZjggPSAoXG4gICAgdmFsdWU6IHN0cmluZyxcbiAgICBieXRlTGltaXQ6IG51bWJlclxuICApOiB7IHRleHQ6IHN0cmluZzsgYnl0ZXM6IG51bWJlcjsgdHJ1bmNhdGVkOiBib29sZWFuIH0gPT4ge1xuICAgIGNvbnN0IGVuY29kZWQgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodmFsdWUpO1xuICAgIGlmIChlbmNvZGVkLmJ5dGVMZW5ndGggPD0gYnl0ZUxpbWl0KSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICB0ZXh0OiB2YWx1ZSxcbiAgICAgICAgYnl0ZXM6IGVuY29kZWQuYnl0ZUxlbmd0aCxcbiAgICAgICAgdHJ1bmNhdGVkOiBmYWxzZVxuICAgICAgfTtcbiAgICB9XG5cbiAgICBsZXQgZW5kID0gTWF0aC5tYXgoMCwgTWF0aC5taW4oYnl0ZUxpbWl0LCBlbmNvZGVkLmJ5dGVMZW5ndGgpKTtcbiAgICB3aGlsZSAoZW5kID4gMCAmJiBlbmQgPCBlbmNvZGVkLmJ5dGVMZW5ndGggJiYgKGVuY29kZWRbZW5kXSEgJiAweGMwKSA9PT0gMHg4MCkge1xuICAgICAgZW5kIC09IDE7XG4gICAgfVxuICAgIHJldHVybiB7XG4gICAgICB0ZXh0OiBuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUoZW5jb2RlZC5zbGljZSgwLCBlbmQpKSxcbiAgICAgIGJ5dGVzOiBlbmQsXG4gICAgICB0cnVuY2F0ZWQ6IHRydWVcbiAgICB9O1xuICB9O1xuXG4gIGNvbnN0IHN0cmluZ2lmeUJvdW5kZWRKc29uID0gKFxuICAgIHZhbHVlOiB1bmtub3duLFxuICAgIGNoYXJhY3RlckxpbWl0OiBudW1iZXJcbiAgKTogeyB0ZXh0OiBzdHJpbmc7IHRydW5jYXRlZDogYm9vbGVhbiB9ID0+IHtcbiAgICBjb25zdCBjaHVua3M6IHN0cmluZ1tdID0gW107XG4gICAgY29uc3Qgc2VlbiA9IG5ldyBXZWFrU2V0PG9iamVjdD4oKTtcbiAgICBsZXQgcmV0YWluZWRDaGFyYWN0ZXJzID0gMDtcbiAgICBsZXQgdmlzaXRlZE5vZGVzID0gMDtcbiAgICBsZXQgdHJ1bmNhdGVkID0gZmFsc2U7XG4gICAgY29uc3QgbWF4Tm9kZXMgPSAxXzAwMDtcbiAgICBjb25zdCBtYXhFbnRyaWVzUGVyQ29udGFpbmVyID0gMTAwO1xuICAgIGNvbnN0IG1heERlcHRoID0gNjtcbiAgICBjb25zdCBhcHBlbmQgPSAodGV4dDogc3RyaW5nKTogYm9vbGVhbiA9PiB7XG4gICAgICBjb25zdCByZW1haW5pbmcgPSBjaGFyYWN0ZXJMaW1pdCAtIHJldGFpbmVkQ2hhcmFjdGVycztcbiAgICAgIGlmIChyZW1haW5pbmcgPD0gMCkge1xuICAgICAgICB0cnVuY2F0ZWQgPSB0cnVlO1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG4gICAgICBpZiAodGV4dC5sZW5ndGggPiByZW1haW5pbmcpIHtcbiAgICAgICAgY2h1bmtzLnB1c2godGV4dC5zbGljZSgwLCByZW1haW5pbmcpKTtcbiAgICAgICAgcmV0YWluZWRDaGFyYWN0ZXJzICs9IHJlbWFpbmluZztcbiAgICAgICAgdHJ1bmNhdGVkID0gdHJ1ZTtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuICAgICAgY2h1bmtzLnB1c2godGV4dCk7XG4gICAgICByZXRhaW5lZENoYXJhY3RlcnMgKz0gdGV4dC5sZW5ndGg7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9O1xuICAgIGNvbnN0IHZpc2l0ID0gKGVudHJ5OiB1bmtub3duLCBkZXB0aDogbnVtYmVyKTogYm9vbGVhbiA9PiB7XG4gICAgICB2aXNpdGVkTm9kZXMgKz0gMTtcbiAgICAgIGlmICh2aXNpdGVkTm9kZXMgPiBtYXhOb2RlcyB8fCBkZXB0aCA+IG1heERlcHRoKSB7XG4gICAgICAgIHRydW5jYXRlZCA9IHRydWU7XG4gICAgICAgIHJldHVybiBhcHBlbmQoJ251bGwnKTtcbiAgICAgIH1cbiAgICAgIGlmIChlbnRyeSA9PT0gbnVsbCB8fCB0eXBlb2YgZW50cnkgPT09ICdib29sZWFuJyB8fCB0eXBlb2YgZW50cnkgPT09ICdudW1iZXInKSB7XG4gICAgICAgIHJldHVybiBhcHBlbmQoSlNPTi5zdHJpbmdpZnkoZW50cnkpKTtcbiAgICAgIH1cbiAgICAgIGlmICh0eXBlb2YgZW50cnkgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIGNvbnN0IHJlbWFpbmluZyA9IE1hdGgubWF4KDAsIGNoYXJhY3RlckxpbWl0IC0gcmV0YWluZWRDaGFyYWN0ZXJzIC0gMik7XG4gICAgICAgIGNvbnN0IGJvdW5kZWQgPSBlbnRyeS5zbGljZSgwLCByZW1haW5pbmcpO1xuICAgICAgICBpZiAoYm91bmRlZC5sZW5ndGggPCBlbnRyeS5sZW5ndGgpIHRydW5jYXRlZCA9IHRydWU7XG4gICAgICAgIHJldHVybiBhcHBlbmQoSlNPTi5zdHJpbmdpZnkoYm91bmRlZCkpO1xuICAgICAgfVxuICAgICAgaWYgKHR5cGVvZiBlbnRyeSAhPT0gJ29iamVjdCcpIHtcbiAgICAgICAgcmV0dXJuIGFwcGVuZCgnbnVsbCcpO1xuICAgICAgfVxuICAgICAgaWYgKHNlZW4uaGFzKGVudHJ5KSkge1xuICAgICAgICB0cnVuY2F0ZWQgPSB0cnVlO1xuICAgICAgICByZXR1cm4gYXBwZW5kKCdudWxsJyk7XG4gICAgICB9XG4gICAgICBzZWVuLmFkZChlbnRyeSk7XG4gICAgICBpZiAoQXJyYXkuaXNBcnJheShlbnRyeSkpIHtcbiAgICAgICAgaWYgKCFhcHBlbmQoJ1snKSkgcmV0dXJuIGZhbHNlO1xuICAgICAgICBjb25zdCBsaW1pdCA9IE1hdGgubWluKGVudHJ5Lmxlbmd0aCwgbWF4RW50cmllc1BlckNvbnRhaW5lcik7XG4gICAgICAgIGZvciAobGV0IGluZGV4ID0gMDsgaW5kZXggPCBsaW1pdDsgaW5kZXggKz0gMSkge1xuICAgICAgICAgIGlmIChpbmRleCA+IDAgJiYgIWFwcGVuZCgnLCcpKSByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgaWYgKCF2aXNpdChlbnRyeVtpbmRleF0sIGRlcHRoICsgMSkpIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZW50cnkubGVuZ3RoID4gbGltaXQpIHRydW5jYXRlZCA9IHRydWU7XG4gICAgICAgIHJldHVybiBhcHBlbmQoJ10nKTtcbiAgICAgIH1cbiAgICAgIGlmICghYXBwZW5kKCd7JykpIHJldHVybiBmYWxzZTtcbiAgICAgIGxldCByZXRhaW5lZEVudHJpZXMgPSAwO1xuICAgICAgZm9yIChjb25zdCBrZXkgaW4gZW50cnkgYXMgUmVjb3JkPHN0cmluZywgdW5rbm93bj4pIHtcbiAgICAgICAgaWYgKCFPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwoZW50cnksIGtleSkpIGNvbnRpbnVlO1xuICAgICAgICBpZiAocmV0YWluZWRFbnRyaWVzID49IG1heEVudHJpZXNQZXJDb250YWluZXIpIHtcbiAgICAgICAgICB0cnVuY2F0ZWQgPSB0cnVlO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGlmIChyZXRhaW5lZEVudHJpZXMgPiAwICYmICFhcHBlbmQoJywnKSkgcmV0dXJuIGZhbHNlO1xuICAgICAgICBjb25zdCByZW1haW5pbmcgPSBNYXRoLm1heCgwLCBjaGFyYWN0ZXJMaW1pdCAtIHJldGFpbmVkQ2hhcmFjdGVycyAtIDIpO1xuICAgICAgICBjb25zdCBib3VuZGVkS2V5ID0ga2V5LnNsaWNlKDAsIE1hdGgubWluKDIwMCwgcmVtYWluaW5nKSk7XG4gICAgICAgIGlmIChib3VuZGVkS2V5Lmxlbmd0aCA8IGtleS5sZW5ndGgpIHRydW5jYXRlZCA9IHRydWU7XG4gICAgICAgIGlmICghYXBwZW5kKEpTT04uc3RyaW5naWZ5KGJvdW5kZWRLZXkpKSB8fCAhYXBwZW5kKCc6JykpIHJldHVybiBmYWxzZTtcbiAgICAgICAgbGV0IGNoaWxkOiB1bmtub3duO1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGNoaWxkID0gKGVudHJ5IGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+KVtrZXldO1xuICAgICAgICB9IGNhdGNoIHtcbiAgICAgICAgICB0cnVuY2F0ZWQgPSB0cnVlO1xuICAgICAgICAgIGNoaWxkID0gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIXZpc2l0KGNoaWxkLCBkZXB0aCArIDEpKSByZXR1cm4gZmFsc2U7XG4gICAgICAgIHJldGFpbmVkRW50cmllcyArPSAxO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGFwcGVuZCgnfScpO1xuICAgIH07XG4gICAgdmlzaXQodmFsdWUsIDApO1xuICAgIHJldHVybiB7IHRleHQ6IGNodW5rcy5qb2luKCcnKSwgdHJ1bmNhdGVkIH07XG4gIH07XG5cbiAgY29uc3QgaW5zcGVjdFJlc3BvbnNlID0gYXN5bmMgKFxuICAgIHJlc3BvbnNlOiBSZXNwb25zZSxcbiAgICB0cmFuc3BvcnQ6ICdmZXRjaCcgfCAneGhyJyxcbiAgICBmYWxsYmFja1VybD86IHN0cmluZ1xuICApID0+IHtcbiAgICBjb25zdCByZXNwb25zZVVybCA9IHJlc3BvbnNlLnVybCB8fCBmYWxsYmFja1VybCB8fCBsb2NhdGlvbi5ocmVmO1xuICAgIGNvbnN0IGNvbnRlbnRUeXBlID0gcmVzcG9uc2UuaGVhZGVycy5nZXQoJ2NvbnRlbnQtdHlwZScpID8/ICcnO1xuICAgIGlmICghc2hvdWxkSW5zcGVjdFJlc3BvbnNlKGNvbnRlbnRUeXBlLCByZXNwb25zZVVybCkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBieXRlTGltaXQgPSBiZWdpblJlc3BvbnNlT2JzZXJ2YXRpb24oKTtcbiAgICBpZiAoYnl0ZUxpbWl0ID09PSB1bmRlZmluZWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgY29uc3QgcmVhZGVyID0gcmVzcG9uc2UuYm9keT8uZ2V0UmVhZGVyKCk7XG4gICAgaWYgKCFyZWFkZXIpIHtcbiAgICAgIGZpbmlzaFJlc3BvbnNlT2JzZXJ2YXRpb24oe1xuICAgICAgICBieXRlQWxsb3dhbmNlOiBieXRlTGltaXQsXG4gICAgICAgIGNhcHR1cmVkQnl0ZXM6IDAsXG4gICAgICAgIG9ic2VydmVkOiBmYWxzZSxcbiAgICAgICAgdHJ1bmNhdGVkOiBmYWxzZSxcbiAgICAgICAgZHJvcFJlYXNvbjogJ2JvZHktdW5hdmFpbGFibGUnXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBkZWNvZGVyID0gbmV3IFRleHREZWNvZGVyKCk7XG4gICAgbGV0IHRleHQgPSAnJztcbiAgICBsZXQgY2FwdHVyZWRCeXRlcyA9IDA7XG4gICAgbGV0IHRydW5jYXRlZCA9IGZhbHNlO1xuICAgIHRyeSB7XG4gICAgICB3aGlsZSAoY2FwdHVyZWRCeXRlcyA8IGJ5dGVMaW1pdCkge1xuICAgICAgICBjb25zdCBuZXh0ID0gYXdhaXQgcmVhZGVyLnJlYWQoKTtcbiAgICAgICAgaWYgKG5leHQuZG9uZSkge1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHJlbWFpbmluZyA9IGJ5dGVMaW1pdCAtIGNhcHR1cmVkQnl0ZXM7XG4gICAgICAgIGNvbnN0IGFjY2VwdGVkID1cbiAgICAgICAgICBuZXh0LnZhbHVlLmJ5dGVMZW5ndGggPiByZW1haW5pbmcgPyBuZXh0LnZhbHVlLnNsaWNlKDAsIHJlbWFpbmluZykgOiBuZXh0LnZhbHVlO1xuICAgICAgICBjYXB0dXJlZEJ5dGVzICs9IGFjY2VwdGVkLmJ5dGVMZW5ndGg7XG4gICAgICAgIHRleHQgKz0gZGVjb2Rlci5kZWNvZGUoYWNjZXB0ZWQsIHtcbiAgICAgICAgICBzdHJlYW06IHRydWVcbiAgICAgICAgfSk7XG4gICAgICAgIGlmIChhY2NlcHRlZC5ieXRlTGVuZ3RoIDwgbmV4dC52YWx1ZS5ieXRlTGVuZ3RoKSB7XG4gICAgICAgICAgdHJ1bmNhdGVkID0gdHJ1ZTtcbiAgICAgICAgICBhd2FpdCByZWFkZXIuY2FuY2VsKCk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHRleHQgKz0gZGVjb2Rlci5kZWNvZGUoKTtcbiAgICAgIGlmIChjYXB0dXJlZEJ5dGVzID49IGJ5dGVMaW1pdCkge1xuICAgICAgICB0cnVuY2F0ZWQgPSB0cnVlO1xuICAgICAgICBhd2FpdCByZWFkZXIuY2FuY2VsKCkuY2F0Y2goKCkgPT4ge30pO1xuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgZmluaXNoUmVzcG9uc2VPYnNlcnZhdGlvbih7XG4gICAgICAgIGJ5dGVBbGxvd2FuY2U6IGJ5dGVMaW1pdCxcbiAgICAgICAgY2FwdHVyZWRCeXRlczogMCxcbiAgICAgICAgb2JzZXJ2ZWQ6IGZhbHNlLFxuICAgICAgICB0cnVuY2F0ZWQ6IGZhbHNlLFxuICAgICAgICBkcm9wUmVhc29uOiAnYm9keS1yZWFkLWVycm9yJ1xuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgYm91bmRlZFRleHQgPSB0cnVuY2F0ZVV0ZjgodGV4dCwgYnl0ZUxpbWl0KTtcbiAgICB0ZXh0ID0gYm91bmRlZFRleHQudGV4dDtcbiAgICBjYXB0dXJlZEJ5dGVzID0gYm91bmRlZFRleHQuYnl0ZXM7XG4gICAgdHJ1bmNhdGVkID0gdHJ1bmNhdGVkIHx8IGJvdW5kZWRUZXh0LnRydW5jYXRlZDtcbiAgICBmaW5pc2hSZXNwb25zZU9ic2VydmF0aW9uKHtcbiAgICAgIGJ5dGVBbGxvd2FuY2U6IGJ5dGVMaW1pdCxcbiAgICAgIGNhcHR1cmVkQnl0ZXMsXG4gICAgICBvYnNlcnZlZDogdHJ1ZSxcbiAgICAgIHRydW5jYXRlZFxuICAgIH0pO1xuICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBleHRyYWN0RmVhdHVyZUNhbmRpZGF0ZXModGV4dCk7XG4gICAgaWYgKGNhbmRpZGF0ZXMubGVuZ3RoID09PSAwKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC5jYW5kaWRhdGVFdmVudENvdW50ICs9IDE7XG4gICAgcHVzaEV2ZW50KCdmZWF0dXJlLWNhbmRpZGF0ZXMtb2JzZXJ2ZWQnLCByZXNwb25zZVVybCwge1xuICAgICAgdHJhbnNwb3J0LFxuICAgICAgcmVzcG9uc2VVcmwsXG4gICAgICBzdGF0dXM6IHJlc3BvbnNlLnN0YXR1cyxcbiAgICAgIGNvbnRlbnRUeXBlLFxuICAgICAgY2FwdHVyZWRCeXRlcyxcbiAgICAgIHRydW5jYXRlZCxcbiAgICAgIGNhbmRpZGF0ZXNcbiAgICB9KTtcbiAgfTtcblxuICBjb25zdCBpbnNwZWN0WGhyID0gKHJlcXVlc3Q6IFhNTEh0dHBSZXF1ZXN0KSA9PiB7XG4gICAgY29uc3QgcmVzcG9uc2VVcmwgPSByZXF1ZXN0LnJlc3BvbnNlVVJMIHx8IGxvY2F0aW9uLmhyZWY7XG4gICAgY29uc3QgY29udGVudFR5cGUgPSByZXF1ZXN0LmdldFJlc3BvbnNlSGVhZGVyKCdjb250ZW50LXR5cGUnKSA/PyAnJztcbiAgICBpZiAoIXNob3VsZEluc3BlY3RSZXNwb25zZShjb250ZW50VHlwZSwgcmVzcG9uc2VVcmwpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgYnl0ZUxpbWl0ID0gYmVnaW5SZXNwb25zZU9ic2VydmF0aW9uKCk7XG4gICAgaWYgKGJ5dGVMaW1pdCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgbGV0IHRleHQgPSAnJztcbiAgICBsZXQgc291cmNlVHJ1bmNhdGVkID0gZmFsc2U7XG4gICAgdHJ5IHtcbiAgICAgIGlmIChyZXF1ZXN0LnJlc3BvbnNlVHlwZSA9PT0gJycgfHwgcmVxdWVzdC5yZXNwb25zZVR5cGUgPT09ICd0ZXh0Jykge1xuICAgICAgICBjb25zdCByZXNwb25zZVRleHQgPSByZXF1ZXN0LnJlc3BvbnNlVGV4dDtcbiAgICAgICAgc291cmNlVHJ1bmNhdGVkID0gcmVzcG9uc2VUZXh0Lmxlbmd0aCA+IGJ5dGVMaW1pdDtcbiAgICAgICAgdGV4dCA9IHJlc3BvbnNlVGV4dC5zbGljZSgwLCBieXRlTGltaXQpO1xuICAgICAgfSBlbHNlIGlmIChyZXF1ZXN0LnJlc3BvbnNlVHlwZSA9PT0gJ2pzb24nKSB7XG4gICAgICAgIGNvbnN0IGJvdW5kZWRKc29uID0gc3RyaW5naWZ5Qm91bmRlZEpzb24ocmVxdWVzdC5yZXNwb25zZSwgYnl0ZUxpbWl0KTtcbiAgICAgICAgdGV4dCA9IGJvdW5kZWRKc29uLnRleHQ7XG4gICAgICAgIHNvdXJjZVRydW5jYXRlZCA9IGJvdW5kZWRKc29uLnRydW5jYXRlZDtcbiAgICAgIH1cbiAgICB9IGNhdGNoIHtcbiAgICAgIGZpbmlzaFJlc3BvbnNlT2JzZXJ2YXRpb24oe1xuICAgICAgICBieXRlQWxsb3dhbmNlOiBieXRlTGltaXQsXG4gICAgICAgIGNhcHR1cmVkQnl0ZXM6IDAsXG4gICAgICAgIG9ic2VydmVkOiBmYWxzZSxcbiAgICAgICAgdHJ1bmNhdGVkOiBmYWxzZSxcbiAgICAgICAgZHJvcFJlYXNvbjogJ2JvZHktcmVhZC1lcnJvcidcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAoIXRleHQpIHtcbiAgICAgIGZpbmlzaFJlc3BvbnNlT2JzZXJ2YXRpb24oe1xuICAgICAgICBieXRlQWxsb3dhbmNlOiBieXRlTGltaXQsXG4gICAgICAgIGNhcHR1cmVkQnl0ZXM6IDAsXG4gICAgICAgIG9ic2VydmVkOiBmYWxzZSxcbiAgICAgICAgdHJ1bmNhdGVkOiBmYWxzZSxcbiAgICAgICAgZHJvcFJlYXNvbjogJ2JvZHktdW5hdmFpbGFibGUnXG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBib3VuZGVkVGV4dCA9IHRydW5jYXRlVXRmOCh0ZXh0LCBieXRlTGltaXQpO1xuICAgIGZpbmlzaFJlc3BvbnNlT2JzZXJ2YXRpb24oe1xuICAgICAgYnl0ZUFsbG93YW5jZTogYnl0ZUxpbWl0LFxuICAgICAgY2FwdHVyZWRCeXRlczogYm91bmRlZFRleHQuYnl0ZXMsXG4gICAgICBvYnNlcnZlZDogdHJ1ZSxcbiAgICAgIHRydW5jYXRlZDogc291cmNlVHJ1bmNhdGVkIHx8IGJvdW5kZWRUZXh0LnRydW5jYXRlZFxuICAgIH0pO1xuICAgIGNvbnN0IGNhbmRpZGF0ZXMgPSBleHRyYWN0RmVhdHVyZUNhbmRpZGF0ZXMoYm91bmRlZFRleHQudGV4dCk7XG4gICAgaWYgKGNhbmRpZGF0ZXMubGVuZ3RoID09PSAwKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC5jYW5kaWRhdGVFdmVudENvdW50ICs9IDE7XG4gICAgcHVzaEV2ZW50KCdmZWF0dXJlLWNhbmRpZGF0ZXMtb2JzZXJ2ZWQnLCByZXNwb25zZVVybCwge1xuICAgICAgdHJhbnNwb3J0OiAneGhyJyxcbiAgICAgIHJlc3BvbnNlVXJsLFxuICAgICAgc3RhdHVzOiByZXF1ZXN0LnN0YXR1cyxcbiAgICAgIGNvbnRlbnRUeXBlLFxuICAgICAgY2FwdHVyZWRCeXRlczogYm91bmRlZFRleHQuYnl0ZXMsXG4gICAgICB0cnVuY2F0ZWQ6IHNvdXJjZVRydW5jYXRlZCB8fCBib3VuZGVkVGV4dC50cnVuY2F0ZWQsXG4gICAgICBjYW5kaWRhdGVzXG4gICAgfSk7XG4gIH07XG5cbiAgY29uc3QgZGVzY3JpYmVOb2RlID0gKFxuICAgIG5vZGU6IEVsZW1lbnRcbiAgKTogQXJyYXk8e1xuICAgIHR5cGU6IEluc3RydW1lbnRhdGlvbkV2ZW50Wyd0eXBlJ107XG4gICAgdXJsPzogc3RyaW5nO1xuICAgIGF0dHJpYnV0ZXM6IFJlY29yZDxzdHJpbmcsIHVua25vd24+O1xuICB9PiA9PiB7XG4gICAgY29uc3QgdGFnTmFtZSA9IG5vZGUudGFnTmFtZS50b0xvd2VyQ2FzZSgpO1xuICAgIGlmICh0YWdOYW1lID09PSAnc2NyaXB0Jykge1xuICAgICAgcmV0dXJuIFtcbiAgICAgICAge1xuICAgICAgICAgIHR5cGU6ICdzY3JpcHQtYWRkZWQnLFxuICAgICAgICAgIHVybDogKG5vZGUgYXMgSFRNTFNjcmlwdEVsZW1lbnQpLnNyYyB8fCB1bmRlZmluZWQsXG4gICAgICAgICAgYXR0cmlidXRlczoge1xuICAgICAgICAgICAgdGFnTmFtZSxcbiAgICAgICAgICAgIGlubGluZTogIShub2RlIGFzIEhUTUxTY3JpcHRFbGVtZW50KS5zcmMsXG4gICAgICAgICAgICBhc3luYzogbm9kZS5oYXNBdHRyaWJ1dGUoJ2FzeW5jJyksXG4gICAgICAgICAgICBkZWZlcjogbm9kZS5oYXNBdHRyaWJ1dGUoJ2RlZmVyJyksXG4gICAgICAgICAgICB0eXBlQXR0cmlidXRlOiBub2RlLmdldEF0dHJpYnV0ZSgndHlwZScpXG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICBdO1xuICAgIH1cblxuICAgIGlmICh0YWdOYW1lID09PSAnbGluaycgJiYgbm9kZS5nZXRBdHRyaWJ1dGUoJ3JlbCcpPy5pbmNsdWRlcygnc3R5bGVzaGVldCcpKSB7XG4gICAgICByZXR1cm4gW1xuICAgICAgICB7XG4gICAgICAgICAgdHlwZTogJ3N0eWxlc2hlZXQtYWRkZWQnLFxuICAgICAgICAgIHVybDogKG5vZGUgYXMgSFRNTExpbmtFbGVtZW50KS5ocmVmIHx8IHVuZGVmaW5lZCxcbiAgICAgICAgICBhdHRyaWJ1dGVzOiB7XG4gICAgICAgICAgICB0YWdOYW1lLFxuICAgICAgICAgICAgcmVsOiBub2RlLmdldEF0dHJpYnV0ZSgncmVsJyksXG4gICAgICAgICAgICBtZWRpYTogbm9kZS5nZXRBdHRyaWJ1dGUoJ21lZGlhJylcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIF07XG4gICAgfVxuXG4gICAgaWYgKHRhZ05hbWUgPT09ICdpbWcnKSB7XG4gICAgICByZXR1cm4gW1xuICAgICAgICB7XG4gICAgICAgICAgdHlwZTogJ2ltYWdlLWFkZGVkJyxcbiAgICAgICAgICB1cmw6IChub2RlIGFzIEhUTUxJbWFnZUVsZW1lbnQpLmN1cnJlbnRTcmMgfHwgKG5vZGUgYXMgSFRNTEltYWdlRWxlbWVudCkuc3JjIHx8IHVuZGVmaW5lZCxcbiAgICAgICAgICBhdHRyaWJ1dGVzOiB7XG4gICAgICAgICAgICB0YWdOYW1lLFxuICAgICAgICAgICAgbG9hZGluZzogbm9kZS5nZXRBdHRyaWJ1dGUoJ2xvYWRpbmcnKVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgXTtcbiAgICB9XG5cbiAgICBpZiAodGFnTmFtZSA9PT0gJ2lmcmFtZScgfHwgdGFnTmFtZSA9PT0gJ2ZyYW1lJykge1xuICAgICAgcmV0dXJuIFtcbiAgICAgICAge1xuICAgICAgICAgIHR5cGU6ICdpZnJhbWUtYWRkZWQnLFxuICAgICAgICAgIHVybDogKG5vZGUgYXMgSFRNTElGcmFtZUVsZW1lbnQpLnNyYyB8fCB1bmRlZmluZWQsXG4gICAgICAgICAgYXR0cmlidXRlczoge1xuICAgICAgICAgICAgdGFnTmFtZSxcbiAgICAgICAgICAgIHNhbmRib3g6IG5vZGUuZ2V0QXR0cmlidXRlKCdzYW5kYm94JylcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIF07XG4gICAgfVxuXG4gICAgcmV0dXJuIFtdO1xuICB9O1xuXG4gIGNvbnN0IHJlY29yZEVsZW1lbnRUcmVlID0gKG5vZGU6IE5vZGUpID0+IHtcbiAgICBpZiAoIShub2RlIGluc3RhbmNlb2YgRWxlbWVudCkpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBtYXhWaXNpdGVkRWxlbWVudHMgPSAyMDA7XG4gICAgY29uc3Qgd2Fsa2VyID0gbm9kZS5vd25lckRvY3VtZW50LmNyZWF0ZVRyZWVXYWxrZXIobm9kZSwgTm9kZUZpbHRlci5TSE9XX0VMRU1FTlQpO1xuICAgIGxldCBjdXJyZW50OiBOb2RlIHwgbnVsbCA9IHdhbGtlci5jdXJyZW50Tm9kZTtcbiAgICBsZXQgdmlzaXRlZEVsZW1lbnRzID0gMDtcbiAgICB3aGlsZSAoY3VycmVudCAmJiB2aXNpdGVkRWxlbWVudHMgPCBtYXhWaXNpdGVkRWxlbWVudHMpIHtcbiAgICAgIGlmIChjdXJyZW50IGluc3RhbmNlb2YgRWxlbWVudCkge1xuICAgICAgICBmb3IgKGNvbnN0IGRlc2NyaXB0aW9uIG9mIGRlc2NyaWJlTm9kZShjdXJyZW50KSkge1xuICAgICAgICAgIHB1c2hFdmVudChkZXNjcmlwdGlvbi50eXBlLCBkZXNjcmlwdGlvbi51cmwsIGRlc2NyaXB0aW9uLmF0dHJpYnV0ZXMpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICB2aXNpdGVkRWxlbWVudHMgKz0gMTtcbiAgICAgIGN1cnJlbnQgPSB3YWxrZXIubmV4dE5vZGUoKTtcbiAgICB9XG4gICAgaWYgKGN1cnJlbnQpIHtcbiAgICAgIHN0YXRlLmRyb3BwZWRFdmVudENvdW50ICs9IDE7XG4gICAgICBzdGF0ZS5kcm9wcGVkRXZlbnRzQnlSZWFzb25bJ211dGF0aW9uLXN1YnRyZWUtbm9kZS1saW1pdCddID1cbiAgICAgICAgKHN0YXRlLmRyb3BwZWRFdmVudHNCeVJlYXNvblsnbXV0YXRpb24tc3VidHJlZS1ub2RlLWxpbWl0J10gPz8gMCkgKyAxO1xuICAgICAgaWYgKCFzdGF0ZS53YXJuaW5ncy5pbmNsdWRlcygnQSBtdXRhdGVkIERPTSBzdWJ0cmVlIGV4Y2VlZGVkIHRoZSAyMDAtZWxlbWVudCBpbnNwZWN0aW9uIGNhcC4nKSkge1xuICAgICAgICBzdGF0ZS53YXJuaW5ncy5wdXNoKCdBIG11dGF0ZWQgRE9NIHN1YnRyZWUgZXhjZWVkZWQgdGhlIDIwMC1lbGVtZW50IGluc3BlY3Rpb24gY2FwLicpO1xuICAgICAgfVxuICAgIH1cbiAgfTtcblxuICB0cnkge1xuICAgIGNvbnN0IG9yaWdpbmFsQ3JlYXRlT2JqZWN0VXJsID0gVVJMLmNyZWF0ZU9iamVjdFVSTC5iaW5kKFVSTCk7XG4gICAgVVJMLmNyZWF0ZU9iamVjdFVSTCA9IChvYmplY3Q6IEJsb2IgfCBNZWRpYVNvdXJjZSkgPT4ge1xuICAgICAgY29uc3QgY3JlYXRlZFVybCA9IG9yaWdpbmFsQ3JlYXRlT2JqZWN0VXJsKG9iamVjdCk7XG4gICAgICBwdXNoRXZlbnQoJ2Jsb2ItY3JlYXRlZCcsIGNyZWF0ZWRVcmwsIHtcbiAgICAgICAgb2JqZWN0VHlwZTogb2JqZWN0LmNvbnN0cnVjdG9yLm5hbWUsXG4gICAgICAgIHR5cGU6ICd0eXBlJyBpbiBvYmplY3QgPyAob2JqZWN0IGFzIEJsb2IpLnR5cGUgOiBudWxsLFxuICAgICAgICBzaXplOiAnc2l6ZScgaW4gb2JqZWN0ID8gKG9iamVjdCBhcyBCbG9iKS5zaXplIDogbnVsbFxuICAgICAgfSk7XG4gICAgICByZXR1cm4gY3JlYXRlZFVybDtcbiAgICB9O1xuXG4gICAgY29uc3Qgb3JpZ2luYWxSZXZva2VPYmplY3RVcmwgPSBVUkwucmV2b2tlT2JqZWN0VVJMLmJpbmQoVVJMKTtcbiAgICBVUkwucmV2b2tlT2JqZWN0VVJMID0gKHVybDogc3RyaW5nKSA9PiB7XG4gICAgICBwdXNoRXZlbnQoJ2Jsb2ItcmV2b2tlZCcsIHVybCwge30pO1xuICAgICAgb3JpZ2luYWxSZXZva2VPYmplY3RVcmwodXJsKTtcbiAgICB9O1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIHN0YXRlLndhcm5pbmdzLnB1c2goXG4gICAgICBzYW5pdGl6ZVNlbnNpdGl2ZVRleHQoYFVuYWJsZSB0byBwYXRjaCBVUkwgYmxvYiBBUElzOiAke1N0cmluZyhlcnJvcil9YCwgNTAwKVxuICAgICk7XG4gIH1cblxuICB0cnkge1xuICAgIGNvbnN0IG9yaWdpbmFsRmV0Y2ggPSB3aW5kb3cuZmV0Y2guYmluZCh3aW5kb3cpO1xuICAgIHdpbmRvdy5mZXRjaCA9IChhc3luYyAoLi4uYXJnczogUGFyYW1ldGVyczx0eXBlb2YgZmV0Y2g+KSA9PiB7XG4gICAgICBjb25zdCByZXF1ZXN0VXJsID1cbiAgICAgICAgdHlwZW9mIGFyZ3NbMF0gPT09ICdzdHJpbmcnXG4gICAgICAgICAgPyBhcmdzWzBdXG4gICAgICAgICAgOiBhcmdzWzBdIGluc3RhbmNlb2YgVVJMXG4gICAgICAgICAgICA/IGFyZ3NbMF0uaHJlZlxuICAgICAgICAgICAgOiBhcmdzWzBdPy51cmw7XG4gICAgICBjb25zdCBtZXRob2QgPVxuICAgICAgICBhcmdzWzFdPy5tZXRob2QgPz9cbiAgICAgICAgKHR5cGVvZiBSZXF1ZXN0ICE9PSAndW5kZWZpbmVkJyAmJiBhcmdzWzBdIGluc3RhbmNlb2YgUmVxdWVzdCA/IGFyZ3NbMF0ubWV0aG9kIDogJ0dFVCcpO1xuICAgICAgcHVzaEV2ZW50KCduZXR3b3JrLXJlcXVlc3QnLCByZXF1ZXN0VXJsLCB7XG4gICAgICAgIHRyYW5zcG9ydDogJ2ZldGNoJyxcbiAgICAgICAgbWV0aG9kOiBTdHJpbmcobWV0aG9kIHx8ICdHRVQnKS50b1VwcGVyQ2FzZSgpLnNsaWNlKDAsIDE2KSxcbiAgICAgICAgaW5pdGlhdG9yOiBjYXB0dXJlSW5pdGlhdG9yKCkgPz8gbnVsbFxuICAgICAgfSk7XG4gICAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IG9yaWdpbmFsRmV0Y2goLi4uYXJncyk7XG4gICAgICB0cnkge1xuICAgICAgICB2b2lkIGluc3BlY3RSZXNwb25zZShyZXNwb25zZS5jbG9uZSgpLCAnZmV0Y2gnLCByZXF1ZXN0VXJsKTtcbiAgICAgIH0gY2F0Y2gge1xuICAgICAgICAvLyBPcGFxdWUgYW5kIGFscmVhZHktY29uc3VtZWQgcmVzcG9uc2VzIGNhbiBiZSB1bmNsb25lYWJsZTsgdGhlIHBhZ2Ugc3RpbGwgcmVjZWl2ZXMgaXRzIG9yaWdpbmFsLlxuICAgICAgfVxuICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgIH0pIGFzIHR5cGVvZiB3aW5kb3cuZmV0Y2g7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgc3RhdGUud2FybmluZ3MucHVzaChcbiAgICAgIHNhbml0aXplU2Vuc2l0aXZlVGV4dChgVW5hYmxlIHRvIG9ic2VydmUgZmV0Y2ggcmVzcG9uc2VzOiAke1N0cmluZyhlcnJvcil9YCwgNTAwKVxuICAgICk7XG4gIH1cblxuICB0cnkge1xuICAgIGNvbnN0IHJlcXVlc3RNZXRhZGF0YSA9IG5ldyBXZWFrTWFwPFhNTEh0dHBSZXF1ZXN0LCB7IG1ldGhvZDogc3RyaW5nOyB1cmw6IHN0cmluZyB9PigpO1xuICAgIGNvbnN0IG9yaWdpbmFsT3BlbiA9IFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuO1xuICAgIFhNTEh0dHBSZXF1ZXN0LnByb3RvdHlwZS5vcGVuID0gZnVuY3Rpb24gKFxuICAgICAgdGhpczogWE1MSHR0cFJlcXVlc3QsXG4gICAgICBtZXRob2Q6IHN0cmluZyxcbiAgICAgIHVybDogc3RyaW5nIHwgVVJMLFxuICAgICAgYXN5bmMgPSB0cnVlLFxuICAgICAgdXNlcm5hbWU/OiBzdHJpbmcgfCBudWxsLFxuICAgICAgcGFzc3dvcmQ/OiBzdHJpbmcgfCBudWxsXG4gICAgKSB7XG4gICAgICByZXF1ZXN0TWV0YWRhdGEuc2V0KHRoaXMsIHtcbiAgICAgICAgbWV0aG9kOiBTdHJpbmcobWV0aG9kIHx8ICdHRVQnKS50b1VwcGVyQ2FzZSgpLnNsaWNlKDAsIDE2KSxcbiAgICAgICAgdXJsOiBTdHJpbmcodXJsKVxuICAgICAgfSk7XG4gICAgICBSZWZsZWN0LmFwcGx5KG9yaWdpbmFsT3BlbiwgdGhpcywgW21ldGhvZCwgdXJsLCBhc3luYywgdXNlcm5hbWUsIHBhc3N3b3JkXSk7XG4gICAgfSBhcyB0eXBlb2YgWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLm9wZW47XG4gICAgY29uc3Qgb3JpZ2luYWxTZW5kID0gWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLnNlbmQ7XG4gICAgWE1MSHR0cFJlcXVlc3QucHJvdG90eXBlLnNlbmQgPSBmdW5jdGlvbiAoXG4gICAgICB0aGlzOiBYTUxIdHRwUmVxdWVzdCxcbiAgICAgIGJvZHk/OiBEb2N1bWVudCB8IFhNTEh0dHBSZXF1ZXN0Qm9keUluaXQgfCBudWxsXG4gICAgKSB7XG4gICAgICBjb25zdCBtZXRhZGF0YSA9IHJlcXVlc3RNZXRhZGF0YS5nZXQodGhpcyk7XG4gICAgICBwdXNoRXZlbnQoJ25ldHdvcmstcmVxdWVzdCcsIG1ldGFkYXRhPy51cmwsIHtcbiAgICAgICAgdHJhbnNwb3J0OiAneGhyJyxcbiAgICAgICAgbWV0aG9kOiBtZXRhZGF0YT8ubWV0aG9kID8/ICdHRVQnLFxuICAgICAgICBpbml0aWF0b3I6IGNhcHR1cmVJbml0aWF0b3IoKSA/PyBudWxsXG4gICAgICB9KTtcbiAgICAgIHRoaXMuYWRkRXZlbnRMaXN0ZW5lcihcbiAgICAgICAgJ2xvYWRlbmQnLFxuICAgICAgICAoKSA9PiB7XG4gICAgICAgICAgaW5zcGVjdFhocih0aGlzKTtcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIG9uY2U6IHRydWVcbiAgICAgICAgfVxuICAgICAgKTtcbiAgICAgIHJldHVybiBvcmlnaW5hbFNlbmQuY2FsbCh0aGlzLCBib2R5KTtcbiAgICB9O1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIHN0YXRlLndhcm5pbmdzLnB1c2goXG4gICAgICBzYW5pdGl6ZVNlbnNpdGl2ZVRleHQoYFVuYWJsZSB0byBvYnNlcnZlIFhNTEh0dHBSZXF1ZXN0IHJlc3BvbnNlczogJHtTdHJpbmcoZXJyb3IpfWAsIDUwMClcbiAgICApO1xuICB9XG5cbiAgaWYgKCdXb3JrZXInIGluIHdpbmRvdykge1xuICAgIGNvbnN0IE9yaWdpbmFsV29ya2VyID0gV29ya2VyO1xuICAgICh3aW5kb3cgYXMgV2luZG93ICYgeyBXb3JrZXI6IHR5cGVvZiBXb3JrZXIgfSkuV29ya2VyID0gY2xhc3MgZXh0ZW5kcyBPcmlnaW5hbFdvcmtlciB7XG4gICAgICBjb25zdHJ1Y3RvcihzY3JpcHRVcmw6IHN0cmluZyB8IFVSTCwgb3B0aW9ucz86IFdvcmtlck9wdGlvbnMpIHtcbiAgICAgICAgcHVzaEV2ZW50KCd3b3JrZXItY29uc3RydWN0ZWQnLCBTdHJpbmcoc2NyaXB0VXJsKSwge1xuICAgICAgICAgIHR5cGU6IG9wdGlvbnM/LnR5cGUgPz8gJ2NsYXNzaWMnLFxuICAgICAgICAgIGNyZWRlbnRpYWxzOiBvcHRpb25zPy5jcmVkZW50aWFscyA/PyBudWxsLFxuICAgICAgICAgIG5hbWU6IG9wdGlvbnM/Lm5hbWUgPz8gbnVsbCxcbiAgICAgICAgICBpbml0aWF0b3I6IGNhcHR1cmVJbml0aWF0b3IoKSA/PyBudWxsXG4gICAgICAgIH0pO1xuICAgICAgICBzdXBlcihzY3JpcHRVcmwsIG9wdGlvbnMpO1xuICAgICAgfVxuICAgIH07XG4gIH1cblxuICBpZiAoJ1NoYXJlZFdvcmtlcicgaW4gd2luZG93KSB7XG4gICAgY29uc3QgT3JpZ2luYWxTaGFyZWRXb3JrZXIgPSBTaGFyZWRXb3JrZXI7XG4gICAgKFxuICAgICAgd2luZG93IGFzIFdpbmRvdyAmIHtcbiAgICAgIFNoYXJlZFdvcmtlcjogdHlwZW9mIFNoYXJlZFdvcmtlcjtcbiAgICAgIH1cbiAgICApLlNoYXJlZFdvcmtlciA9IGNsYXNzIGV4dGVuZHMgT3JpZ2luYWxTaGFyZWRXb3JrZXIge1xuICAgICAgY29uc3RydWN0b3Ioc2NyaXB0VXJsOiBzdHJpbmcgfCBVUkwsIG9wdGlvbnM/OiBzdHJpbmcgfCBXb3JrZXJPcHRpb25zKSB7XG4gICAgICAgIHB1c2hFdmVudCgnc2hhcmVkLXdvcmtlci1jb25zdHJ1Y3RlZCcsIFN0cmluZyhzY3JpcHRVcmwpLCB7XG4gICAgICAgICAgbmFtZTogdHlwZW9mIG9wdGlvbnMgPT09ICdzdHJpbmcnID8gb3B0aW9ucyA6IG9wdGlvbnM/Lm5hbWUgPz8gbnVsbCxcbiAgICAgICAgICBpbml0aWF0b3I6IGNhcHR1cmVJbml0aWF0b3IoKSA/PyBudWxsXG4gICAgICAgIH0pO1xuICAgICAgICBzdXBlcihzY3JpcHRVcmwsIG9wdGlvbnMpO1xuICAgICAgfVxuICAgIH07XG4gIH1cblxuICBpZiAoJ1dlYlNvY2tldCcgaW4gd2luZG93KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IE9yaWdpbmFsV2ViU29ja2V0ID0gV2ViU29ja2V0O1xuICAgICAgKHdpbmRvdyBhcyBXaW5kb3cgJiB7IFdlYlNvY2tldDogdHlwZW9mIFdlYlNvY2tldCB9KS5XZWJTb2NrZXQgPSBjbGFzcyBleHRlbmRzIE9yaWdpbmFsV2ViU29ja2V0IHtcbiAgICAgICAgY29uc3RydWN0b3IodXJsOiBzdHJpbmcgfCBVUkwsIHByb3RvY29scz86IHN0cmluZyB8IHN0cmluZ1tdKSB7XG4gICAgICAgICAgcHVzaEV2ZW50KCd3ZWJzb2NrZXQtY29uc3RydWN0ZWQnLCBTdHJpbmcodXJsKSwge1xuICAgICAgICAgICAgcHJvdG9jb2xDb3VudDogQXJyYXkuaXNBcnJheShwcm90b2NvbHMpID8gcHJvdG9jb2xzLmxlbmd0aCA6IHByb3RvY29scyA/IDEgOiAwLFxuICAgICAgICAgICAgaW5pdGlhdG9yOiBjYXB0dXJlSW5pdGlhdG9yKCkgPz8gbnVsbFxuICAgICAgICAgIH0pO1xuICAgICAgICAgIHN1cGVyKHVybCwgcHJvdG9jb2xzID8/IFtdKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgc3RhdGUud2FybmluZ3MucHVzaChcbiAgICAgICAgc2FuaXRpemVTZW5zaXRpdmVUZXh0KGBVbmFibGUgdG8gb2JzZXJ2ZSBXZWJTb2NrZXQgY29uc3RydWN0aW9uOiAke1N0cmluZyhlcnJvcil9YCwgNTAwKVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBpZiAoJ0V2ZW50U291cmNlJyBpbiB3aW5kb3cpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgT3JpZ2luYWxFdmVudFNvdXJjZSA9IEV2ZW50U291cmNlO1xuICAgICAgKHdpbmRvdyBhcyBXaW5kb3cgJiB7IEV2ZW50U291cmNlOiB0eXBlb2YgRXZlbnRTb3VyY2UgfSkuRXZlbnRTb3VyY2UgPSBjbGFzcyBleHRlbmRzIE9yaWdpbmFsRXZlbnRTb3VyY2Uge1xuICAgICAgICBjb25zdHJ1Y3Rvcih1cmw6IHN0cmluZyB8IFVSTCwgZXZlbnRTb3VyY2VJbml0RGljdD86IEV2ZW50U291cmNlSW5pdCkge1xuICAgICAgICAgIHB1c2hFdmVudCgnZXZlbnRzb3VyY2UtY29uc3RydWN0ZWQnLCBTdHJpbmcodXJsKSwge1xuICAgICAgICAgICAgd2l0aENyZWRlbnRpYWxzOiBldmVudFNvdXJjZUluaXREaWN0Py53aXRoQ3JlZGVudGlhbHMgPT09IHRydWUsXG4gICAgICAgICAgICBpbml0aWF0b3I6IGNhcHR1cmVJbml0aWF0b3IoKSA/PyBudWxsXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgc3VwZXIodXJsLCBldmVudFNvdXJjZUluaXREaWN0KTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgc3RhdGUud2FybmluZ3MucHVzaChcbiAgICAgICAgc2FuaXRpemVTZW5zaXRpdmVUZXh0KGBVbmFibGUgdG8gb2JzZXJ2ZSBFdmVudFNvdXJjZSBjb25zdHJ1Y3Rpb246ICR7U3RyaW5nKGVycm9yKX1gLCA1MDApXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIGlmICh0eXBlb2YgbmF2aWdhdG9yLnNlbmRCZWFjb24gPT09ICdmdW5jdGlvbicpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3Qgb3JpZ2luYWxTZW5kQmVhY29uID0gbmF2aWdhdG9yLnNlbmRCZWFjb24uYmluZChuYXZpZ2F0b3IpO1xuICAgICAgbmF2aWdhdG9yLnNlbmRCZWFjb24gPSAodXJsOiBzdHJpbmcgfCBVUkwsIGRhdGE/OiBCb2R5SW5pdCB8IG51bGwpOiBib29sZWFuID0+IHtcbiAgICAgICAgY29uc3QgYXBwcm94aW1hdGVCeXRlcyA9XG4gICAgICAgICAgdHlwZW9mIGRhdGEgPT09ICdzdHJpbmcnXG4gICAgICAgICAgICA/IGRhdGEubGVuZ3RoXG4gICAgICAgICAgICA6IGRhdGEgaW5zdGFuY2VvZiBCbG9iXG4gICAgICAgICAgICAgID8gZGF0YS5zaXplXG4gICAgICAgICAgICAgIDogZGF0YSBpbnN0YW5jZW9mIEFycmF5QnVmZmVyXG4gICAgICAgICAgICAgICAgPyBkYXRhLmJ5dGVMZW5ndGhcbiAgICAgICAgICAgICAgICA6IEFycmF5QnVmZmVyLmlzVmlldyhkYXRhKVxuICAgICAgICAgICAgICAgICAgPyBkYXRhLmJ5dGVMZW5ndGhcbiAgICAgICAgICAgICAgICAgIDogdW5kZWZpbmVkO1xuICAgICAgICBwdXNoRXZlbnQoJ2JlYWNvbi1zZW50JywgU3RyaW5nKHVybCksIHtcbiAgICAgICAgICBhcHByb3hpbWF0ZUJ5dGVzOiBhcHByb3hpbWF0ZUJ5dGVzID8/IG51bGwsXG4gICAgICAgICAgYXBwcm94aW1hdGVCeXRlc0Jhc2lzOiB0eXBlb2YgZGF0YSA9PT0gJ3N0cmluZycgPyAndXRmMTYtY29kZS11bml0cycgOiAnYmluYXJ5LXNpemUnLFxuICAgICAgICAgIGluaXRpYXRvcjogY2FwdHVyZUluaXRpYXRvcigpID8/IG51bGxcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiBvcmlnaW5hbFNlbmRCZWFjb24odXJsLCBkYXRhKTtcbiAgICAgIH07XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHN0YXRlLndhcm5pbmdzLnB1c2goXG4gICAgICAgIHNhbml0aXplU2Vuc2l0aXZlVGV4dChgVW5hYmxlIHRvIG9ic2VydmUgYmVhY29uIHNlbmRzOiAke1N0cmluZyhlcnJvcil9YCwgNTAwKVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICB0cnkge1xuICAgIGNvbnN0IG9yaWdpbmFsU2V0SXRlbSA9IFN0b3JhZ2UucHJvdG90eXBlLnNldEl0ZW07XG4gICAgY29uc3Qgb3JpZ2luYWxSZW1vdmVJdGVtID0gU3RvcmFnZS5wcm90b3R5cGUucmVtb3ZlSXRlbTtcbiAgICBjb25zdCBvcmlnaW5hbENsZWFyID0gU3RvcmFnZS5wcm90b3R5cGUuY2xlYXI7XG4gICAgY29uc3Qgc3RvcmFnZUFyZWEgPSAodGFyZ2V0OiBTdG9yYWdlKTogc3RyaW5nID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGlmICh0YXJnZXQgPT09IHdpbmRvdy5sb2NhbFN0b3JhZ2UpIHJldHVybiAnbG9jYWxTdG9yYWdlJztcbiAgICAgICAgaWYgKHRhcmdldCA9PT0gd2luZG93LnNlc3Npb25TdG9yYWdlKSByZXR1cm4gJ3Nlc3Npb25TdG9yYWdlJztcbiAgICAgIH0gY2F0Y2gge1xuICAgICAgICAvLyBTdG9yYWdlIGFjY2VzcyBjYW4gYmUgZGVuaWVkIGJ5IHBhZ2UgcG9saWN5LlxuICAgICAgfVxuICAgICAgcmV0dXJuICdzdG9yYWdlJztcbiAgICB9O1xuICAgIFN0b3JhZ2UucHJvdG90eXBlLnNldEl0ZW0gPSBmdW5jdGlvbiAodGhpczogU3RvcmFnZSwga2V5OiBzdHJpbmcsIHZhbHVlOiBzdHJpbmcpOiB2b2lkIHtcbiAgICAgIHB1c2hFdmVudCgnc3RvcmFnZS13cml0ZScsIHVuZGVmaW5lZCwge1xuICAgICAgICBhcmVhOiBzdG9yYWdlQXJlYSh0aGlzKSxcbiAgICAgICAgb3BlcmF0aW9uOiAnc2V0SXRlbScsXG4gICAgICAgIGtleTogU3RyaW5nKGtleSkuc2xpY2UoMCwgMTgwKSxcbiAgICAgICAgdmFsdWVMZW5ndGg6IFN0cmluZyh2YWx1ZSkubGVuZ3RoLFxuICAgICAgICBpbml0aWF0b3I6IGNhcHR1cmVJbml0aWF0b3IoKSA/PyBudWxsXG4gICAgICB9KTtcbiAgICAgIG9yaWdpbmFsU2V0SXRlbS5jYWxsKHRoaXMsIGtleSwgdmFsdWUpO1xuICAgIH07XG4gICAgU3RvcmFnZS5wcm90b3R5cGUucmVtb3ZlSXRlbSA9IGZ1bmN0aW9uICh0aGlzOiBTdG9yYWdlLCBrZXk6IHN0cmluZyk6IHZvaWQge1xuICAgICAgcHVzaEV2ZW50KCdzdG9yYWdlLXdyaXRlJywgdW5kZWZpbmVkLCB7XG4gICAgICAgIGFyZWE6IHN0b3JhZ2VBcmVhKHRoaXMpLFxuICAgICAgICBvcGVyYXRpb246ICdyZW1vdmVJdGVtJyxcbiAgICAgICAga2V5OiBTdHJpbmcoa2V5KS5zbGljZSgwLCAxODApLFxuICAgICAgICBpbml0aWF0b3I6IGNhcHR1cmVJbml0aWF0b3IoKSA/PyBudWxsXG4gICAgICB9KTtcbiAgICAgIG9yaWdpbmFsUmVtb3ZlSXRlbS5jYWxsKHRoaXMsIGtleSk7XG4gICAgfTtcbiAgICBTdG9yYWdlLnByb3RvdHlwZS5jbGVhciA9IGZ1bmN0aW9uICh0aGlzOiBTdG9yYWdlKTogdm9pZCB7XG4gICAgICBwdXNoRXZlbnQoJ3N0b3JhZ2Utd3JpdGUnLCB1bmRlZmluZWQsIHtcbiAgICAgICAgYXJlYTogc3RvcmFnZUFyZWEodGhpcyksXG4gICAgICAgIG9wZXJhdGlvbjogJ2NsZWFyJyxcbiAgICAgICAgaW5pdGlhdG9yOiBjYXB0dXJlSW5pdGlhdG9yKCkgPz8gbnVsbFxuICAgICAgfSk7XG4gICAgICBvcmlnaW5hbENsZWFyLmNhbGwodGhpcyk7XG4gICAgfTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBzdGF0ZS53YXJuaW5ncy5wdXNoKFxuICAgICAgc2FuaXRpemVTZW5zaXRpdmVUZXh0KGBVbmFibGUgdG8gb2JzZXJ2ZSBicm93c2VyIHN0b3JhZ2Ugd3JpdGVzOiAke1N0cmluZyhlcnJvcil9YCwgNTAwKVxuICAgICk7XG4gIH1cblxuICB0cnkge1xuICAgIGZvciAoY29uc3QgbWV0aG9kTmFtZSBvZiBbJ3B1c2hTdGF0ZScsICdyZXBsYWNlU3RhdGUnXSBhcyBjb25zdCkge1xuICAgICAgY29uc3Qgb3JpZ2luYWwgPSBoaXN0b3J5W21ldGhvZE5hbWVdLmJpbmQoaGlzdG9yeSk7XG4gICAgICBoaXN0b3J5W21ldGhvZE5hbWVdID0gKChkYXRhOiB1bmtub3duLCB1bnVzZWQ6IHN0cmluZywgdXJsPzogc3RyaW5nIHwgVVJMIHwgbnVsbCkgPT4ge1xuICAgICAgICBwdXNoRXZlbnQoJ3JvdXRlLWNoYW5nZScsIFN0cmluZyh1cmwgPz8gbG9jYXRpb24uaHJlZiksIHtcbiAgICAgICAgICBvcGVyYXRpb246IG1ldGhvZE5hbWUsXG4gICAgICAgICAgaW5pdGlhdG9yOiBjYXB0dXJlSW5pdGlhdG9yKCkgPz8gbnVsbFxuICAgICAgICB9KTtcbiAgICAgICAgb3JpZ2luYWwoZGF0YSwgdW51c2VkLCB1cmwpO1xuICAgICAgfSkgYXMgSGlzdG9yeVt0eXBlb2YgbWV0aG9kTmFtZV07XG4gICAgfVxuICB9IGNhdGNoIChlcnJvcikge1xuICAgIHN0YXRlLndhcm5pbmdzLnB1c2goXG4gICAgICBzYW5pdGl6ZVNlbnNpdGl2ZVRleHQoYFVuYWJsZSB0byBvYnNlcnZlIGhpc3Rvcnkgcm91dGUgY2hhbmdlczogJHtTdHJpbmcoZXJyb3IpfWAsIDUwMClcbiAgICApO1xuICB9XG5cbiAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ2Vycm9yJywgKGV2ZW50KSA9PiB7XG4gICAgcHVzaEV2ZW50KCdydW50aW1lLWVycm9yJywgZXZlbnQuZmlsZW5hbWUgfHwgdW5kZWZpbmVkLCB7XG4gICAgICAuLi5zYWZlRXJyb3JTdW1tYXJ5KGV2ZW50LmVycm9yID8/IGV2ZW50Lm1lc3NhZ2UpLFxuICAgICAgbGluZTogZXZlbnQubGluZW5vIHx8IG51bGwsXG4gICAgICBjb2x1bW46IGV2ZW50LmNvbG5vIHx8IG51bGxcbiAgICB9KTtcbiAgfSk7XG4gIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCd1bmhhbmRsZWRyZWplY3Rpb24nLCAoZXZlbnQpID0+IHtcbiAgICBwdXNoRXZlbnQoJ3VuaGFuZGxlZC1yZWplY3Rpb24nLCB1bmRlZmluZWQsIHNhZmVFcnJvclN1bW1hcnkoZXZlbnQucmVhc29uKSk7XG4gIH0pO1xuXG4gIGxldCBkb21NdXRhdGlvbkV2ZW50Q291bnQgPSAwO1xuICBjb25zdCBvYnNlcnZlciA9IG5ldyBNdXRhdGlvbk9ic2VydmVyKChtdXRhdGlvbnMpID0+IHtcbiAgICBsZXQgYWRkZWROb2RlcyA9IDA7XG4gICAgbGV0IHJlbW92ZWROb2RlcyA9IDA7XG4gICAgbGV0IGF0dHJpYnV0ZUNoYW5nZXMgPSAwO1xuICAgIGZvciAoY29uc3QgbXV0YXRpb24gb2YgbXV0YXRpb25zKSB7XG4gICAgICBhZGRlZE5vZGVzICs9IG11dGF0aW9uLmFkZGVkTm9kZXMubGVuZ3RoO1xuICAgICAgcmVtb3ZlZE5vZGVzICs9IG11dGF0aW9uLnJlbW92ZWROb2Rlcy5sZW5ndGg7XG4gICAgICBhdHRyaWJ1dGVDaGFuZ2VzICs9IG11dGF0aW9uLnR5cGUgPT09ICdhdHRyaWJ1dGVzJyA/IDEgOiAwO1xuICAgICAgZm9yIChjb25zdCBhZGRlZE5vZGUgb2YgQXJyYXkuZnJvbShtdXRhdGlvbi5hZGRlZE5vZGVzKSkge1xuICAgICAgICByZWNvcmRFbGVtZW50VHJlZShhZGRlZE5vZGUpO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAoZG9tTXV0YXRpb25FdmVudENvdW50IDwgNTApIHtcbiAgICAgIGRvbU11dGF0aW9uRXZlbnRDb3VudCArPSAxO1xuICAgICAgcHVzaEV2ZW50KCdkb20tbXV0YXRpb24nLCB1bmRlZmluZWQsIHtcbiAgICAgICAgbXV0YXRpb25Db3VudDogbXV0YXRpb25zLmxlbmd0aCxcbiAgICAgICAgYWRkZWROb2RlcyxcbiAgICAgICAgcmVtb3ZlZE5vZGVzLFxuICAgICAgICBhdHRyaWJ1dGVDaGFuZ2VzXG4gICAgICB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgc3RhdGUuZHJvcHBlZEV2ZW50Q291bnQgKz0gMTtcbiAgICAgIHN0YXRlLmRyb3BwZWRFdmVudHNCeVJlYXNvblsnZG9tLW11dGF0aW9uLWV2ZW50LWxpbWl0J10gPVxuICAgICAgICAoc3RhdGUuZHJvcHBlZEV2ZW50c0J5UmVhc29uWydkb20tbXV0YXRpb24tZXZlbnQtbGltaXQnXSA/PyAwKSArIDE7XG4gICAgfVxuICB9KTtcblxuICBpZiAoZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50KSB7XG4gICAgb2JzZXJ2ZXIub2JzZXJ2ZShkb2N1bWVudC5kb2N1bWVudEVsZW1lbnQsIHtcbiAgICAgIGNoaWxkTGlzdDogdHJ1ZSxcbiAgICAgIHN1YnRyZWU6IHRydWUsXG4gICAgICBhdHRyaWJ1dGVzOiB0cnVlXG4gICAgfSk7XG4gIH0gZWxzZSB7XG4gICAgc3RhdGUud2FybmluZ3MucHVzaCgnRG9jdW1lbnQgcm9vdCB3YXMgdW5hdmFpbGFibGUgd2hlbiBNdXRhdGlvbk9ic2VydmVyIHN0YXJ0ZWQuJyk7XG4gIH1cblxuICBkb2N1bWVudC5hZGRFdmVudExpc3RlbmVyKFxuICAgICdET01Db250ZW50TG9hZGVkJyxcbiAgICAoKSA9PiB7XG4gICAgICBwdXNoRXZlbnQoJ2xpZmVjeWNsZScsIHVuZGVmaW5lZCwge1xuICAgICAgICBzdGFnZTogJ2RvbWNvbnRlbnRsb2FkZWQnXG4gICAgICB9KTtcbiAgICB9LFxuICAgIHsgb25jZTogdHJ1ZSB9XG4gICk7XG5cbiAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoXG4gICAgJ2xvYWQnLFxuICAgICgpID0+IHtcbiAgICAgIHB1c2hFdmVudCgnbGlmZWN5Y2xlJywgdW5kZWZpbmVkLCB7XG4gICAgICAgIHN0YWdlOiAnbG9hZCdcbiAgICAgIH0pO1xuICAgIH0sXG4gICAgeyBvbmNlOiB0cnVlIH1cbiAgKTtcblxuICBjb25zdCBidWlsZENvdmVyYWdlID0gKCk6IEluc3RydW1lbnRhdGlvbkNvdmVyYWdlID0+ICh7XG4gICAgZXZlbnRCdWZmZXI6IHtcbiAgICAgIGxpbWl0OiBtYXhJbnN0cnVtZW50YXRpb25FdmVudHMsXG4gICAgICByZXRhaW5lZEV2ZW50Q291bnQ6IHN0YXRlLmV2ZW50cy5sZW5ndGgsXG4gICAgICBkcm9wcGVkRXZlbnRDb3VudDogc3RhdGUuZHJvcHBlZEV2ZW50Q291bnQsXG4gICAgICBkcm9wcGVkQnlSZWFzb246IHsgLi4uc3RhdGUuZHJvcHBlZEV2ZW50c0J5UmVhc29uIH1cbiAgICB9LFxuICAgIHJlc3BvbnNlT2JzZXJ2YXRpb246IHtcbiAgICAgIHJlc3BvbnNlTGltaXQ6IG1heE9ic2VydmVkUmVzcG9uc2VzLFxuICAgICAgcGVyUmVzcG9uc2VCeXRlTGltaXQ6IG1heE9ic2VydmVkUmVzcG9uc2VCeXRlcyxcbiAgICAgIHRvdGFsQnl0ZUxpbWl0OiBtYXhPYnNlcnZlZFRvdGFsQnl0ZXMsXG4gICAgICBlbGlnaWJsZVJlc3BvbnNlQ291bnQ6IGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC5lbGlnaWJsZVJlc3BvbnNlQ291bnQsXG4gICAgICBzdGFydGVkUmVzcG9uc2VDb3VudDogZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LnN0YXJ0ZWRSZXNwb25zZUNvdW50LFxuICAgICAgb2JzZXJ2ZWRSZXNwb25zZUNvdW50OiBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQub2JzZXJ2ZWRSZXNwb25zZUNvdW50LFxuICAgICAgY2FuZGlkYXRlRXZlbnRDb3VudDogZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmNhbmRpZGF0ZUV2ZW50Q291bnQsXG4gICAgICBjYXB0dXJlZEJ5dGVzOiBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQuY2FwdHVyZWRCeXRlcyxcbiAgICAgIGRyb3BwZWRSZXNwb25zZUNvdW50OiBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQuZHJvcHBlZFJlc3BvbnNlQ291bnQsXG4gICAgICB0cnVuY2F0ZWRSZXNwb25zZUNvdW50OiBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQudHJ1bmNhdGVkUmVzcG9uc2VDb3VudCxcbiAgICAgIGRyb3BwZWRCeVJlYXNvbjogeyAuLi5mZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQuZHJvcHBlZEJ5UmVhc29uIH0sXG4gICAgICB0cnVuY2F0ZWRCeVJlYXNvbjogeyAuLi5mZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQudHJ1bmNhdGVkQnlSZWFzb24gfVxuICAgIH1cbiAgfSk7XG5cbiAgY29uc3QgZm9ybWF0UmVhc29uQ291bnRzID0gKHJlYXNvbnM6IFJlY29yZDxzdHJpbmcsIG51bWJlcj4pOiBzdHJpbmcgPT5cbiAgICBPYmplY3QuZW50cmllcyhyZWFzb25zKVxuICAgICAgLnNvcnQoKFtsZWZ0XSwgW3JpZ2h0XSkgPT4gbGVmdC5sb2NhbGVDb21wYXJlKHJpZ2h0KSlcbiAgICAgIC5tYXAoKFtyZWFzb24sIGNvdW50XSkgPT4gYCR7cmVhc29ufT0ke2NvdW50fWApXG4gICAgICAuam9pbignLCAnKTtcblxuICBjb25zdCBidWlsZENvdmVyYWdlV2FybmluZ3MgPSAoKTogc3RyaW5nW10gPT4ge1xuICAgIGNvbnN0IHdhcm5pbmdzOiBzdHJpbmdbXSA9IFtdO1xuICAgIGlmIChzdGF0ZS5kcm9wcGVkRXZlbnRDb3VudCA+IDApIHtcbiAgICAgIHdhcm5pbmdzLnB1c2goXG4gICAgICAgIGBJbnN0cnVtZW50YXRpb24gY292ZXJhZ2UgZHJvcHBlZCAke3N0YXRlLmRyb3BwZWRFdmVudENvdW50fSBldmVudCBvYnNlcnZhdGlvbiR7XG4gICAgICAgICAgc3RhdGUuZHJvcHBlZEV2ZW50Q291bnQgPT09IDEgPyAnJyA6ICdzJ1xuICAgICAgICB9OiAke2Zvcm1hdFJlYXNvbkNvdW50cyhzdGF0ZS5kcm9wcGVkRXZlbnRzQnlSZWFzb24pfS5gXG4gICAgICApO1xuICAgIH1cbiAgICBpZiAoZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmRyb3BwZWRSZXNwb25zZUNvdW50ID4gMCkge1xuICAgICAgd2FybmluZ3MucHVzaChcbiAgICAgICAgYFJ1bnRpbWUgcmVzcG9uc2UgY292ZXJhZ2UgZHJvcHBlZCAke2ZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC5kcm9wcGVkUmVzcG9uc2VDb3VudH0gZWxpZ2libGUgYm9keSBvYnNlcnZhdGlvbiR7XG4gICAgICAgICAgZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmRyb3BwZWRSZXNwb25zZUNvdW50ID09PSAxID8gJycgOiAncydcbiAgICAgICAgfTogJHtmb3JtYXRSZWFzb25Db3VudHMoZmVhdHVyZU9ic2VydmF0aW9uQnVkZ2V0LmRyb3BwZWRCeVJlYXNvbil9LmBcbiAgICAgICk7XG4gICAgfVxuICAgIGlmIChmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQudHJ1bmNhdGVkUmVzcG9uc2VDb3VudCA+IDApIHtcbiAgICAgIHdhcm5pbmdzLnB1c2goXG4gICAgICAgIGBSdW50aW1lIHJlc3BvbnNlIGNvdmVyYWdlIHRydW5jYXRlZCAke2ZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC50cnVuY2F0ZWRSZXNwb25zZUNvdW50fSBib2R5IG9ic2VydmF0aW9uJHtcbiAgICAgICAgICBmZWF0dXJlT2JzZXJ2YXRpb25CdWRnZXQudHJ1bmNhdGVkUmVzcG9uc2VDb3VudCA9PT0gMSA/ICcnIDogJ3MnXG4gICAgICAgIH06ICR7Zm9ybWF0UmVhc29uQ291bnRzKGZlYXR1cmVPYnNlcnZhdGlvbkJ1ZGdldC50cnVuY2F0ZWRCeVJlYXNvbil9LmBcbiAgICAgICk7XG4gICAgfVxuICAgIHJldHVybiB3YXJuaW5ncztcbiAgfTtcblxuICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIChldmVudCkgPT4ge1xuICAgIGlmIChldmVudC5zb3VyY2UgIT09IHdpbmRvdyB8fCAhZXZlbnQuZGF0YSB8fCBldmVudC5kYXRhLl9fYmxhbmNoZSAhPT0gJ2J1cnAtYnJpZGdlJykge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmIChldmVudC5kYXRhLnR5cGUgIT09ICdpbnN0cnVtZW50YXRpb24tc25hcHNob3QtcmVxdWVzdCcpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBwb3N0QnJpZGdlTWVzc2FnZSgnaW5zdHJ1bWVudGF0aW9uLXNuYXBzaG90LXJlc3BvbnNlJywge1xuICAgICAgcmVxdWVzdElkOiBldmVudC5kYXRhLnBheWxvYWQucmVxdWVzdElkLFxuICAgICAgc25hcHNob3Q6IHtcbiAgICAgICAgdmVyc2lvbjogc3RhdGUudmVyc2lvbixcbiAgICAgICAgc3RhcnRlZEF0OiBzdGF0ZS5zdGFydGVkQXQsXG4gICAgICAgIHBhZ2VVcmw6IHNhbml0aXplT2JzZXJ2ZWRVcmwobG9jYXRpb24uaHJlZiksXG4gICAgICAgIGV2ZW50czogWy4uLnN0YXRlLmV2ZW50c10sXG4gICAgICAgIHdhcm5pbmdzOiBbXG4gICAgICAgICAgLi4uc3RhdGUud2FybmluZ3MubWFwKCh3YXJuaW5nKSA9PiBzYW5pdGl6ZVNlbnNpdGl2ZVRleHQod2FybmluZywgNTAwKSksXG4gICAgICAgICAgLi4uYnVpbGRDb3ZlcmFnZVdhcm5pbmdzKClcbiAgICAgICAgXS5zbGljZSgwLCAxMDApLFxuICAgICAgICBjb3ZlcmFnZTogYnVpbGRDb3ZlcmFnZSgpXG4gICAgICB9XG4gICAgfSk7XG4gIH0pO1xuXG4gIHBvc3RCcmlkZ2VNZXNzYWdlKCdpbnN0cnVtZW50YXRpb24tcmVhZHknLCB7XG4gICAgc3RhcnRlZEF0OiBzdGF0ZS5zdGFydGVkQXRcbiAgfSk7XG59KSgpO1xuIl0sCiAgIm1hcHBpbmdzIjogIjs7O0FBQUEsR0FBQyxNQUFNO0FBQ0wsVUFBTSxZQUFZO0FBQ2xCLFFBQUssT0FBOEMsU0FBUyxHQUFHO0FBQzdEO0FBQUEsSUFDRjtBQUVBLElBQUMsT0FBOEMsU0FBUyxJ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
