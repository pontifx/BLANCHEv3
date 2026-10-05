"use strict";
(() => {
  // chromium-extension/src/content/bridgeContent.ts
  var state = {
    instrumented: false,
    warnings: [],
    liveEvents: [],
    startedAt: void 0,
    droppedLiveEventCount: 0
  };
  var PAGE_WORLD_INTEGRITY_WARNING = "Page-world instrumentation is unverified: same-window postMessage evidence can be fabricated or suppressed by the inspected page.";
  function sanitizeBridgeUrl(rawUrl) {
    try {
      const parsed = new URL(rawUrl, location.href);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return `${parsed.protocol}${parsed.protocol === "blob:" ? "[redacted]" : ""}`;
      }
      parsed.username = "";
      parsed.password = "";
      parsed.hash = "";
      const names = [.../* @__PURE__ */ new Set([...parsed.searchParams.keys()])].sort();
      parsed.search = names.length > 0 ? `?${names.map((name) => `${encodeURIComponent(name)}=`).join("&")}` : "";
      return parsed.toString();
    } catch {
      return "[unparseable-url]";
    }
  }
  function sanitizeBridgeText(value, maxLength = 500) {
    return value.replace(/https?:\/\/[^\s"'<>]+/gi, (url) => sanitizeBridgeUrl(url)).replace(/(\/\/)[^/\s:@]+:[^@\s/]+@/g, "$1[redacted-credentials]@").replace(/([?&][A-Za-z0-9_.~%-]{1,100})=([^&#\s]*)/g, "$1=[redacted]").replace(/#[^\s"'<>]*/g, "#[redacted]").replace(/\b(bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]").replace(
      /\b(password|passwd|secret|access[-_]?token|refresh[-_]?token|authorization|api[-_]?key|session[-_]?id|cookie)\s*[:=]\s*[^\s,;]+/gi,
      "$1=[redacted]"
    ).slice(0, maxLength);
  }
  function isBridgeUrlAttribute(key) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
    return normalized.endsWith("url") || normalized.endsWith("uri") || normalized.endsWith("href") || normalized.endsWith("src") || normalized === "endpoint" || normalized === "location" || normalized === "referrer" || normalized === "initiator";
  }
  function sanitizeBridgeAttributes(attributes, redactStrings) {
    const visit = (key, value, depth) => {
      if (value === void 0 || value === null) return value;
      if (isBridgeUrlAttribute(key) && typeof value === "string") {
        return sanitizeBridgeUrl(value);
      }
      if (depth >= 5) return "[depth-limit]";
      if (Array.isArray(value)) {
        return value.slice(0, 100).map((entry) => visit(key, entry, depth + 1));
      }
      if (typeof value === "object") {
        return Object.fromEntries(
          Object.entries(value).slice(0, 100).map(([childKey, entry]) => [childKey, visit(childKey, entry, depth + 1)])
        );
      }
      if (redactStrings && typeof value === "string") {
        return sanitizeBridgeText(value);
      }
      return value;
    };
    return Object.fromEntries(
      Object.entries(attributes).slice(0, 100).map(([key, value]) => [key, visit(key, value, 0)])
    );
  }
  function sanitizeBridgeEvent(event) {
    return {
      ...event,
      pageUrl: event.pageUrl ? sanitizeBridgeUrl(event.pageUrl) : void 0,
      frameHref: event.frameHref ? sanitizeBridgeUrl(event.frameHref) : void 0,
      url: event.url ? sanitizeBridgeUrl(event.url) : void 0,
      attributes: sanitizeBridgeAttributes(
        event.attributes,
        event.type === "runtime-error" || event.type === "unhandled-rejection"
      )
    };
  }
  function sanitizeBridgeSnapshot(snapshot) {
    return {
      ...snapshot,
      pageUrl: snapshot.pageUrl ? sanitizeBridgeUrl(snapshot.pageUrl) : void 0,
      events: snapshot.events.slice(0, 400).map(sanitizeBridgeEvent),
      warnings: snapshot.warnings.slice(0, 100).map((warning) => sanitizeBridgeText(warning))
    };
  }
  var pendingRequests = /* @__PURE__ */ new Map();
  window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data || event.data.__blanche !== "burp-bridge") {
      return;
    }
    switch (event.data.type) {
      case "instrumentation-event":
        state.liveEvents.unshift(sanitizeBridgeEvent(event.data.payload));
        if (state.liveEvents.length > 300) {
          state.droppedLiveEventCount += state.liveEvents.length - 300;
          state.liveEvents.length = 300;
        }
        break;
      case "instrumentation-ready":
        state.instrumented = true;
        state.startedAt = event.data.payload.startedAt;
        break;
      case "instrumentation-snapshot-response": {
        const pending = pendingRequests.get(event.data.payload.requestId);
        if (!pending) {
          break;
        }
        window.clearTimeout(pending.timeout);
        pendingRequests.delete(event.data.payload.requestId);
        pending.resolve({
          instrumented: true,
          integrity: "page-world-unverified",
          frameUrl: sanitizeBridgeUrl(location.href),
          topFrame: window.top === window,
          snapshot: sanitizeBridgeSnapshot(event.data.payload.snapshot),
          warnings: [...state.warnings, PAGE_WORLD_INTEGRITY_WARNING]
        });
        break;
      }
      default:
        break;
    }
  });
  ensureInstrumentorInjected();
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || typeof message !== "object" || message.channel !== "blanche-burp-bridge" || message.type !== "content/getInstrumentationSnapshot") {
      return false;
    }
    void requestInstrumentationSnapshot().then(sendResponse);
    return true;
  });
  function ensureInstrumentorInjected() {
    if (document.documentElement?.hasAttribute("data-blanche-burp-bridge")) {
      return;
    }
    const inject = () => {
      if (document.documentElement?.hasAttribute("data-blanche-burp-bridge")) {
        return;
      }
      const host = document.head ?? document.documentElement;
      if (!host) {
        state.warnings.push("Unable to inject page instrumentor before document root was available.");
        return;
      }
      const instrumentorPath = resolveInstrumentorPath();
      if (!instrumentorPath) {
        state.warnings.push("Page instrumentor is not exposed in web_accessible_resources.");
        return;
      }
      const script = document.createElement("script");
      script.src = chrome.runtime.getURL(instrumentorPath);
      script.async = false;
      script.dataset.blanche = "burp-bridge";
      host.prepend(script);
      document.documentElement?.setAttribute("data-blanche-burp-bridge", "true");
      script.addEventListener("load", () => script.remove(), { once: true });
      script.addEventListener(
        "error",
        () => {
          state.warnings.push("Failed to load page instrumentor script.");
        },
        { once: true }
      );
    };
    if (document.documentElement) {
      inject();
      return;
    }
    document.addEventListener("readystatechange", inject, { once: true });
  }
  function resolveInstrumentorPath() {
    const manifest = chrome.runtime.getManifest();
    for (const entry of manifest.web_accessible_resources ?? []) {
      if (typeof entry === "string") {
        if (entry.endsWith("pageInstrumentor.js")) {
          return entry;
        }
        continue;
      }
      for (const resource of entry.resources ?? []) {
        if (resource.endsWith("pageInstrumentor.js")) {
          return resource;
        }
      }
    }
    return void 0;
  }
  async function requestInstrumentationSnapshot() {
    const requestId = crypto.randomUUID();
    return new Promise((resolve) => {
      const timeout = window.setTimeout(() => {
        pendingRequests.delete(requestId);
        resolve({
          instrumented: state.instrumented,
          integrity: "page-world-unverified",
          frameUrl: sanitizeBridgeUrl(location.href),
          topFrame: window.top === window,
          snapshot: state.startedAt ? {
            version: "0.3.0",
            startedAt: state.startedAt,
            pageUrl: sanitizeBridgeUrl(location.href),
            events: [...state.liveEvents],
            warnings: [
              ...state.warnings,
              ...state.droppedLiveEventCount > 0 ? [`Fallback instrumentation buffer dropped ${state.droppedLiveEventCount} event observation${state.droppedLiveEventCount === 1 ? "" : "s"} at its 300-event limit.`] : [],
              "Fallback instrumentation snapshot could not recover page-world response-observation coverage counters."
            ],
            coverage: {
              eventBuffer: {
                limit: 300,
                retainedEventCount: state.liveEvents.length,
                droppedEventCount: state.droppedLiveEventCount,
                droppedByReason: state.droppedLiveEventCount > 0 ? { "fallback-event-buffer-limit": state.droppedLiveEventCount } : {}
              }
            }
          } : void 0,
          warnings: [
            ...state.warnings,
            PAGE_WORLD_INTEGRITY_WARNING,
            "Timed out waiting for instrumented snapshot response."
          ]
        });
      }, 700);
      pendingRequests.set(requestId, {
        resolve,
        timeout
      });
      window.postMessage(
        {
          __blanche: "burp-bridge",
          type: "instrumentation-snapshot-request",
          payload: {
            requestId
          }
        },
        "*"
      );
    });
  }
})();
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vLi4vc3JjL2NvbnRlbnQvYnJpZGdlQ29udGVudC50cyJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiaW1wb3J0IHR5cGUgeyBDb250ZW50SW5zdHJ1bWVudGF0aW9uUmVzcG9uc2UsIEluc3RydW1lbnRhdGlvblNuYXBzaG90IH0gZnJvbSAnLi4vbW9kdWxlcy9idXJwQnJpZGdlL3R5cGVzJztcblxudHlwZSBQYWdlQnJpZGdlTWVzc2FnZSA9XG4gIHwge1xuICAgICAgX19ibGFuY2hlOiAnYnVycC1icmlkZ2UnO1xuICAgICAgdHlwZTogJ2luc3RydW1lbnRhdGlvbi1ldmVudCc7XG4gICAgICBwYXlsb2FkOiBJbnN0cnVtZW50YXRpb25TbmFwc2hvdFsnZXZlbnRzJ11bbnVtYmVyXTtcbiAgICB9XG4gIHwge1xuICAgICAgX19ibGFuY2hlOiAnYnVycC1icmlkZ2UnO1xuICAgICAgdHlwZTogJ2luc3RydW1lbnRhdGlvbi1yZWFkeSc7XG4gICAgICBwYXlsb2FkOiB7XG4gICAgICAgIHN0YXJ0ZWRBdDogc3RyaW5nO1xuICAgICAgfTtcbiAgICB9XG4gIHwge1xuICAgICAgX19ibGFuY2hlOiAnYnVycC1icmlkZ2UnO1xuICAgICAgdHlwZTogJ2luc3RydW1lbnRhdGlvbi1zbmFwc2hvdC1yZXNwb25zZSc7XG4gICAgICBwYXlsb2FkOiB7XG4gICAgICAgIHJlcXVlc3RJZDogc3RyaW5nO1xuICAgICAgICBzbmFwc2hvdDogSW5zdHJ1bWVudGF0aW9uU25hcHNob3Q7XG4gICAgICB9O1xuICAgIH07XG5cbmNvbnN0IHN0YXRlID0ge1xuICBpbnN0cnVtZW50ZWQ6IGZhbHNlLFxuICB3YXJuaW5nczogW10gYXMgc3RyaW5nW10sXG4gIGxpdmVFdmVudHM6IFtdIGFzIEluc3RydW1lbnRhdGlvblNuYXBzaG90WydldmVudHMnXSxcbiAgc3RhcnRlZEF0OiB1bmRlZmluZWQgYXMgc3RyaW5nIHwgdW5kZWZpbmVkLFxuICBkcm9wcGVkTGl2ZUV2ZW50Q291bnQ6IDBcbn07XG5cbmNvbnN0IFBBR0VfV09STERfSU5URUdSSVRZX1dBUk5JTkcgPVxuICAnUGFnZS13b3JsZCBpbnN0cnVtZW50YXRpb24gaXMgdW52ZXJpZmllZDogc2FtZS13aW5kb3cgcG9zdE1lc3NhZ2UgZXZpZGVuY2UgY2FuIGJlIGZhYnJpY2F0ZWQgb3Igc3VwcHJlc3NlZCBieSB0aGUgaW5zcGVjdGVkIHBhZ2UuJztcblxuZnVuY3Rpb24gc2FuaXRpemVCcmlkZ2VVcmwocmF3VXJsOiBzdHJpbmcpOiBzdHJpbmcge1xuICB0cnkge1xuICAgIGNvbnN0IHBhcnNlZCA9IG5ldyBVUkwocmF3VXJsLCBsb2NhdGlvbi5ocmVmKTtcbiAgICBpZiAocGFyc2VkLnByb3RvY29sICE9PSAnaHR0cDonICYmIHBhcnNlZC5wcm90b2NvbCAhPT0gJ2h0dHBzOicpIHtcbiAgICAgIHJldHVybiBgJHtwYXJzZWQucHJvdG9jb2x9JHtwYXJzZWQucHJvdG9jb2wgPT09ICdibG9iOicgPyAnW3JlZGFjdGVkXScgOiAnJ31gO1xuICAgIH1cbiAgICBwYXJzZWQudXNlcm5hbWUgPSAnJztcbiAgICBwYXJzZWQucGFzc3dvcmQgPSAnJztcbiAgICBwYXJzZWQuaGFzaCA9ICcnO1xuICAgIGNvbnN0IG5hbWVzID0gWy4uLm5ldyBTZXQoWy4uLnBhcnNlZC5zZWFyY2hQYXJhbXMua2V5cygpXSldLnNvcnQoKTtcbiAgICBwYXJzZWQuc2VhcmNoID0gbmFtZXMubGVuZ3RoID4gMFxuICAgICAgPyBgPyR7bmFtZXMubWFwKChuYW1lKSA9PiBgJHtlbmNvZGVVUklDb21wb25lbnQobmFtZSl9PWApLmpvaW4oJyYnKX1gXG4gICAgICA6ICcnO1xuICAgIHJldHVybiBwYXJzZWQudG9TdHJpbmcoKTtcbiAgfSBjYXRjaCB7XG4gICAgcmV0dXJuICdbdW5wYXJzZWFibGUtdXJsXSc7XG4gIH1cbn1cblxuZnVuY3Rpb24gc2FuaXRpemVCcmlkZ2VUZXh0KHZhbHVlOiBzdHJpbmcsIG1heExlbmd0aCA9IDUwMCk6IHN0cmluZyB7XG4gIHJldHVybiB2YWx1ZVxuICAgIC5yZXBsYWNlKC9odHRwcz86XFwvXFwvW15cXHNcIic8Pl0rL2dpLCAodXJsKSA9PiBzYW5pdGl6ZUJyaWRnZVVybCh1cmwpKVxuICAgIC5yZXBsYWNlKC8oXFwvXFwvKVteL1xcczpAXSs6W15AXFxzL10rQC9nLCAnJDFbcmVkYWN0ZWQtY3JlZGVudGlhbHNdQCcpXG4gICAgLnJlcGxhY2UoLyhbPyZdW0EtWmEtejAtOV8ufiUtXXsxLDEwMH0pPShbXiYjXFxzXSopL2csICckMT1bcmVkYWN0ZWRdJylcbiAgICAucmVwbGFjZSgvI1teXFxzXCInPD5dKi9nLCAnI1tyZWRhY3RlZF0nKVxuICAgIC5yZXBsYWNlKC9cXGIoYmVhcmVyKVxccytbQS1aYS16MC05Ll9+Ky89LV0rL2dpLCAnJDEgW3JlZGFjdGVkXScpXG4gICAgLnJlcGxhY2UoXG4gICAgICAvXFxiKHBhc3N3b3JkfHBhc3N3ZHxzZWNyZXR8YWNjZXNzWy1fXT90b2tlbnxyZWZyZXNoWy1fXT90b2tlbnxhdXRob3JpemF0aW9ufGFwaVstX10/a2V5fHNlc3Npb25bLV9dP2lkfGNvb2tpZSlcXHMqWzo9XVxccypbXlxccyw7XSsvZ2ksXG4gICAgICAnJDE9W3JlZGFjdGVkXSdcbiAgICApXG4gICAgLnNsaWNlKDAsIG1heExlbmd0aCk7XG59XG5cbmZ1bmN0aW9uIGlzQnJpZGdlVXJsQXR0cmlidXRlKGtleTogc3RyaW5nKTogYm9vbGVhbiB7XG4gIGNvbnN0IG5vcm1hbGl6ZWQgPSBrZXkudG9Mb3dlckNhc2UoKS5yZXBsYWNlKC9bXmEtejAtOV0vZywgJycpO1xuICByZXR1cm4gKFxuICAgIG5vcm1hbGl6ZWQuZW5kc1dpdGgoJ3VybCcpIHx8XG4gICAgbm9ybWFsaXplZC5lbmRzV2l0aCgndXJpJykgfHxcbiAgICBub3JtYWxpemVkLmVuZHNXaXRoKCdocmVmJykgfHxcbiAgICBub3JtYWxpemVkLmVuZHNXaXRoKCdzcmMnKSB8fFxuICAgIG5vcm1hbGl6ZWQgPT09ICdlbmRwb2ludCcgfHxcbiAgICBub3JtYWxpemVkID09PSAnbG9jYXRpb24nIHx8XG4gICAgbm9ybWFsaXplZCA9PT0gJ3JlZmVycmVyJyB8fFxuICAgIG5vcm1hbGl6ZWQgPT09ICdpbml0aWF0b3InXG4gICk7XG59XG5cbmZ1bmN0aW9uIHNhbml0aXplQnJpZGdlQXR0cmlidXRlcyhcbiAgYXR0cmlidXRlczogSW5zdHJ1bWVudGF0aW9uU25hcHNob3RbJ2V2ZW50cyddW251bWJlcl1bJ2F0dHJpYnV0ZXMnXSxcbiAgcmVkYWN0U3RyaW5nczogYm9vbGVhblxuKTogSW5zdHJ1bWVudGF0aW9uU25hcHNob3RbJ2V2ZW50cyddW251bWJlcl1bJ2F0dHJpYnV0ZXMnXSB7XG4gIGNvbnN0IHZpc2l0ID0gKGtleTogc3RyaW5nLCB2YWx1ZTogdW5rbm93biwgZGVwdGg6IG51bWJlcik6IHVua25vd24gPT4ge1xuICAgIGlmICh2YWx1ZSA9PT0gdW5kZWZpbmVkIHx8IHZhbHVlID09PSBudWxsKSByZXR1cm4gdmFsdWU7XG4gICAgaWYgKGlzQnJpZGdlVXJsQXR0cmlidXRlKGtleSkgJiYgdHlwZW9mIHZhbHVlID09PSAnc3RyaW5nJykge1xuICAgICAgcmV0dXJuIHNhbml0aXplQnJpZGdlVXJsKHZhbHVlKTtcbiAgICB9XG4gICAgaWYgKGRlcHRoID49IDUpIHJldHVybiAnW2RlcHRoLWxpbWl0XSc7XG4gICAgaWYgKEFycmF5LmlzQXJyYXkodmFsdWUpKSB7XG4gICAgICByZXR1cm4gdmFsdWUuc2xpY2UoMCwgMTAwKS5tYXAoKGVudHJ5KSA9PiB2aXNpdChrZXksIGVudHJ5LCBkZXB0aCArIDEpKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ29iamVjdCcpIHtcbiAgICAgIHJldHVybiBPYmplY3QuZnJvbUVudHJpZXMoXG4gICAgICAgIE9iamVjdC5lbnRyaWVzKHZhbHVlIGFzIFJlY29yZDxzdHJpbmcsIHVua25vd24+KVxuICAgICAgICAgIC5zbGljZSgwLCAxMDApXG4gICAgICAgICAgLm1hcCgoW2NoaWxkS2V5LCBlbnRyeV0pID0+IFtjaGlsZEtleSwgdmlzaXQoY2hpbGRLZXksIGVudHJ5LCBkZXB0aCArIDEpXSlcbiAgICAgICk7XG4gICAgfVxuICAgIGlmIChyZWRhY3RTdHJpbmdzICYmIHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIHJldHVybiBzYW5pdGl6ZUJyaWRnZVRleHQodmFsdWUpO1xuICAgIH1cbiAgICByZXR1cm4gdmFsdWU7XG4gIH07XG5cbiAgcmV0dXJuIE9iamVjdC5mcm9tRW50cmllcyhcbiAgICBPYmplY3QuZW50cmllcyhhdHRyaWJ1dGVzKVxuICAgICAgLnNsaWNlKDAsIDEwMClcbiAgICAgIC5tYXAoKFtrZXksIHZhbHVlXSkgPT4gW2tleSwgdmlzaXQoa2V5LCB2YWx1ZSwgMCldKVxuICApIGFzIEluc3RydW1lbnRhdGlvblNuYXBzaG90WydldmVudHMnXVtudW1iZXJdWydhdHRyaWJ1dGVzJ107XG59XG5cbmZ1bmN0aW9uIHNhbml0aXplQnJpZGdlRXZlbnQoXG4gIGV2ZW50OiBJbnN0cnVtZW50YXRpb25TbmFwc2hvdFsnZXZlbnRzJ11bbnVtYmVyXVxuKTogSW5zdHJ1bWVudGF0aW9uU25hcHNob3RbJ2V2ZW50cyddW251bWJlcl0ge1xuICByZXR1cm4ge1xuICAgIC4uLmV2ZW50LFxuICAgIHBhZ2VVcmw6IGV2ZW50LnBhZ2VVcmwgPyBzYW5pdGl6ZUJyaWRnZVVybChldmVudC5wYWdlVXJsKSA6IHVuZGVmaW5lZCxcbiAgICBmcmFtZUhyZWY6IGV2ZW50LmZyYW1lSHJlZiA/IHNhbml0aXplQnJpZGdlVXJsKGV2ZW50LmZyYW1lSHJlZikgOiB1bmRlZmluZWQsXG4gICAgdXJsOiBldmVudC51cmwgPyBzYW5pdGl6ZUJyaWRnZVVybChldmVudC51cmwpIDogdW5kZWZpbmVkLFxuICAgIGF0dHJpYnV0ZXM6IHNhbml0aXplQnJpZGdlQXR0cmlidXRlcyhcbiAgICAgIGV2ZW50LmF0dHJpYnV0ZXMsXG4gICAgICBldmVudC50eXBlID09PSAncnVudGltZS1lcnJvcicgfHwgZXZlbnQudHlwZSA9PT0gJ3VuaGFuZGxlZC1yZWplY3Rpb24nXG4gICAgKVxuICB9O1xufVxuXG5mdW5jdGlvbiBzYW5pdGl6ZUJyaWRnZVNuYXBzaG90KHNuYXBzaG90OiBJbnN0cnVtZW50YXRpb25TbmFwc2hvdCk6IEluc3RydW1lbnRhdGlvblNuYXBzaG90IHtcbiAgcmV0dXJuIHtcbiAgICAuLi5zbmFwc2hvdCxcbiAgICBwYWdlVXJsOiBzbmFwc2hvdC5wYWdlVXJsID8gc2FuaXRpemVCcmlkZ2VVcmwoc25hcHNob3QucGFnZVVybCkgOiB1bmRlZmluZWQsXG4gICAgZXZlbnRzOiBzbmFwc2hvdC5ldmVudHMuc2xpY2UoMCwgNDAwKS5tYXAoc2FuaXRpemVCcmlkZ2VFdmVudCksXG4gICAgd2FybmluZ3M6IHNuYXBzaG90Lndhcm5pbmdzLnNsaWNlKDAsIDEwMCkubWFwKCh3YXJuaW5nKSA9PiBzYW5pdGl6ZUJyaWRnZVRleHQod2FybmluZykpXG4gIH07XG59XG5cbmNvbnN0IHBlbmRpbmdSZXF1ZXN0cyA9IG5ldyBNYXA8XG4gIHN0cmluZyxcbiAge1xuICAgIHJlc29sdmU6IChyZXNwb25zZTogQ29udGVudEluc3RydW1lbnRhdGlvblJlc3BvbnNlKSA9PiB2b2lkO1xuICAgIHRpbWVvdXQ6IG51bWJlcjtcbiAgfVxuPigpO1xuXG53aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIChldmVudDogTWVzc2FnZUV2ZW50PFBhZ2VCcmlkZ2VNZXNzYWdlPikgPT4ge1xuICBpZiAoZXZlbnQuc291cmNlICE9PSB3aW5kb3cgfHwgIWV2ZW50LmRhdGEgfHwgZXZlbnQuZGF0YS5fX2JsYW5jaGUgIT09ICdidXJwLWJyaWRnZScpIHtcbiAgICByZXR1cm47XG4gIH1cblxuICBzd2l0Y2ggKGV2ZW50LmRhdGEudHlwZSkge1xuICAgIGNhc2UgJ2luc3RydW1lbnRhdGlvbi1ldmVudCc6XG4gICAgICBzdGF0ZS5saXZlRXZlbnRzLnVuc2hpZnQoc2FuaXRpemVCcmlkZ2VFdmVudChldmVudC5kYXRhLnBheWxvYWQpKTtcbiAgICAgIGlmIChzdGF0ZS5saXZlRXZlbnRzLmxlbmd0aCA+IDMwMCkge1xuICAgICAgICBzdGF0ZS5kcm9wcGVkTGl2ZUV2ZW50Q291bnQgKz0gc3RhdGUubGl2ZUV2ZW50cy5sZW5ndGggLSAzMDA7XG4gICAgICAgIHN0YXRlLmxpdmVFdmVudHMubGVuZ3RoID0gMzAwO1xuICAgICAgfVxuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnaW5zdHJ1bWVudGF0aW9uLXJlYWR5JzpcbiAgICAgIHN0YXRlLmluc3RydW1lbnRlZCA9IHRydWU7XG4gICAgICBzdGF0ZS5zdGFydGVkQXQgPSBldmVudC5kYXRhLnBheWxvYWQuc3RhcnRlZEF0O1xuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnaW5zdHJ1bWVudGF0aW9uLXNuYXBzaG90LXJlc3BvbnNlJzoge1xuICAgICAgY29uc3QgcGVuZGluZyA9IHBlbmRpbmdSZXF1ZXN0cy5nZXQoZXZlbnQuZGF0YS5wYXlsb2FkLnJlcXVlc3RJZCk7XG4gICAgICBpZiAoIXBlbmRpbmcpIHtcbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG5cbiAgICAgIHdpbmRvdy5jbGVhclRpbWVvdXQocGVuZGluZy50aW1lb3V0KTtcbiAgICAgIHBlbmRpbmdSZXF1ZXN0cy5kZWxldGUoZXZlbnQuZGF0YS5wYXlsb2FkLnJlcXVlc3RJZCk7XG4gICAgICBwZW5kaW5nLnJlc29sdmUoe1xuICAgICAgICBpbnN0cnVtZW50ZWQ6IHRydWUsXG4gICAgICAgIGludGVncml0eTogJ3BhZ2Utd29ybGQtdW52ZXJpZmllZCcsXG4gICAgICAgIGZyYW1lVXJsOiBzYW5pdGl6ZUJyaWRnZVVybChsb2NhdGlvbi5ocmVmKSxcbiAgICAgICAgdG9wRnJhbWU6IHdpbmRvdy50b3AgPT09IHdpbmRvdyxcbiAgICAgICAgc25hcHNob3Q6IHNhbml0aXplQnJpZGdlU25hcHNob3QoZXZlbnQuZGF0YS5wYXlsb2FkLnNuYXBzaG90KSxcbiAgICAgICAgd2FybmluZ3M6IFsuLi5zdGF0ZS53YXJuaW5ncywgUEFHRV9XT1JMRF9JTlRFR1JJVFlfV0FSTklOR11cbiAgICAgIH0pO1xuICAgICAgYnJlYWs7XG4gICAgfVxuICAgIGRlZmF1bHQ6XG4gICAgICBicmVhaztcbiAgfVxufSk7XG5cbmVuc3VyZUluc3RydW1lbnRvckluamVjdGVkKCk7XG5cbmNocm9tZS5ydW50aW1lLm9uTWVzc2FnZS5hZGRMaXN0ZW5lcigobWVzc2FnZSwgX3NlbmRlciwgc2VuZFJlc3BvbnNlKSA9PiB7XG4gIGlmIChcbiAgICAhbWVzc2FnZSB8fFxuICAgIHR5cGVvZiBtZXNzYWdlICE9PSAnb2JqZWN0JyB8fFxuICAgIG1lc3NhZ2UuY2hhbm5lbCAhPT0gJ2JsYW5jaGUtYnVycC1icmlkZ2UnIHx8XG4gICAgbWVzc2FnZS50eXBlICE9PSAnY29udGVudC9nZXRJbnN0cnVtZW50YXRpb25TbmFwc2hvdCdcbiAgKSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgdm9pZCByZXF1ZXN0SW5zdHJ1bWVudGF0aW9uU25hcHNob3QoKS50aGVuKHNlbmRSZXNwb25zZSk7XG4gIHJldHVybiB0cnVlO1xufSk7XG5cbmZ1bmN0aW9uIGVuc3VyZUluc3RydW1lbnRvckluamVjdGVkKCk6IHZvaWQge1xuICBpZiAoZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50Py5oYXNBdHRyaWJ1dGUoJ2RhdGEtYmxhbmNoZS1idXJwLWJyaWRnZScpKSB7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgY29uc3QgaW5qZWN0ID0gKCkgPT4ge1xuICAgIGlmIChkb2N1bWVudC5kb2N1bWVudEVsZW1lbnQ/Lmhhc0F0dHJpYnV0ZSgnZGF0YS1ibGFuY2hlLWJ1cnAtYnJpZGdlJykpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBob3N0ID0gZG9jdW1lbnQuaGVhZCA/PyBkb2N1bWVudC5kb2N1bWVudEVsZW1lbnQ7XG4gICAgaWYgKCFob3N0KSB7XG4gICAgICBzdGF0ZS53YXJuaW5ncy5wdXNoKCdVbmFibGUgdG8gaW5qZWN0IHBhZ2UgaW5zdHJ1bWVudG9yIGJlZm9yZSBkb2N1bWVudCByb290IHdhcyBhdmFpbGFibGUuJyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3QgaW5zdHJ1bWVudG9yUGF0aCA9IHJlc29sdmVJbnN0cnVtZW50b3JQYXRoKCk7XG4gICAgaWYgKCFpbnN0cnVtZW50b3JQYXRoKSB7XG4gICAgICBzdGF0ZS53YXJuaW5ncy5wdXNoKCdQYWdlIGluc3RydW1lbnRvciBpcyBub3QgZXhwb3NlZCBpbiB3ZWJfYWNjZXNzaWJsZV9yZXNvdXJjZXMuJyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgY29uc3Qgc2NyaXB0ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7XG4gICAgc2NyaXB0LnNyYyA9IGNocm9tZS5ydW50aW1lLmdldFVSTChpbnN0cnVtZW50b3JQYXRoKTtcbiAgICBzY3JpcHQuYXN5bmMgPSBmYWxzZTtcbiAgICBzY3JpcHQuZGF0YXNldC5ibGFuY2hlID0gJ2J1cnAtYnJpZGdlJztcbiAgICBob3N0LnByZXBlbmQoc2NyaXB0KTtcbiAgICBkb2N1bWVudC5kb2N1bWVudEVsZW1lbnQ/LnNldEF0dHJpYnV0ZSgnZGF0YS1ibGFuY2hlLWJ1cnAtYnJpZGdlJywgJ3RydWUnKTtcbiAgICBzY3JpcHQuYWRkRXZlbnRMaXN0ZW5lcignbG9hZCcsICgpID0+IHNjcmlwdC5yZW1vdmUoKSwgeyBvbmNlOiB0cnVlIH0pO1xuICAgIHNjcmlwdC5hZGRFdmVudExpc3RlbmVyKFxuICAgICAgJ2Vycm9yJyxcbiAgICAgICgpID0+IHtcbiAgICAgICAgc3RhdGUud2FybmluZ3MucHVzaCgnRmFpbGVkIHRvIGxvYWQgcGFnZSBpbnN0cnVtZW50b3Igc2NyaXB0LicpO1xuICAgICAgfSxcbiAgICAgIHsgb25jZTogdHJ1ZSB9XG4gICAgKTtcbiAgfTtcblxuICBpZiAoZG9jdW1lbnQuZG9jdW1lbnRFbGVtZW50KSB7XG4gICAgaW5qZWN0KCk7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgZG9jdW1lbnQuYWRkRXZlbnRMaXN0ZW5lcigncmVhZHlzdGF0ZWNoYW5nZScsIGluamVjdCwgeyBvbmNlOiB0cnVlIH0pO1xufVxuXG5mdW5jdGlvbiByZXNvbHZlSW5zdHJ1bWVudG9yUGF0aCgpOiBzdHJpbmcgfCB1bmRlZmluZWQge1xuICBjb25zdCBtYW5pZmVzdCA9IGNocm9tZS5ydW50aW1lLmdldE1hbmlmZXN0KCk7XG4gIGZvciAoY29uc3QgZW50cnkgb2YgbWFuaWZlc3Qud2ViX2FjY2Vzc2libGVfcmVzb3VyY2VzID8/IFtdKSB7XG4gICAgaWYgKHR5cGVvZiBlbnRyeSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGlmIChlbnRyeS5lbmRzV2l0aCgncGFnZUluc3RydW1lbnRvci5qcycpKSB7XG4gICAgICAgIHJldHVybiBlbnRyeTtcbiAgICAgIH1cbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgcmVzb3VyY2Ugb2YgZW50cnkucmVzb3VyY2VzID8/IFtdKSB7XG4gICAgICBpZiAocmVzb3VyY2UuZW5kc1dpdGgoJ3BhZ2VJbnN0cnVtZW50b3IuanMnKSkge1xuICAgICAgICByZXR1cm4gcmVzb3VyY2U7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHVuZGVmaW5lZDtcbn1cblxuYXN5bmMgZnVuY3Rpb24gcmVxdWVzdEluc3RydW1lbnRhdGlvblNuYXBzaG90KCk6IFByb21pc2U8Q29udGVudEluc3RydW1lbnRhdGlvblJlc3BvbnNlPiB7XG4gIGNvbnN0IHJlcXVlc3RJZCA9IGNyeXB0by5yYW5kb21VVUlEKCk7XG4gIHJldHVybiBuZXcgUHJvbWlzZTxDb250ZW50SW5zdHJ1bWVudGF0aW9uUmVzcG9uc2U+KChyZXNvbHZlKSA9PiB7XG4gICAgY29uc3QgdGltZW91dCA9IHdpbmRvdy5zZXRUaW1lb3V0KCgpID0+IHtcbiAgICAgIHBlbmRpbmdSZXF1ZXN0cy5kZWxldGUocmVxdWVzdElkKTtcbiAgICAgIHJlc29sdmUoe1xuICAgICAgICBpbnN0cnVtZW50ZWQ6IHN0YXRlLmluc3RydW1lbnRlZCxcbiAgICAgICAgaW50ZWdyaXR5OiAncGFnZS13b3JsZC11bnZlcmlmaWVkJyxcbiAgICAgICAgZnJhbWVVcmw6IHNhbml0aXplQnJpZGdlVXJsKGxvY2F0aW9uLmhyZWYpLFxuICAgICAgICB0b3BGcmFtZTogd2luZG93LnRvcCA9PT0gd2luZG93LFxuICAgICAgICBzbmFwc2hvdDogc3RhdGUuc3RhcnRlZEF0XG4gICAgICAgICAgPyB7XG4gICAgICAgICAgICAgIHZlcnNpb246ICcwLjMuMCcsXG4gICAgICAgICAgICAgIHN0YXJ0ZWRBdDogc3RhdGUuc3RhcnRlZEF0LFxuICAgICAgICAgICAgICBwYWdlVXJsOiBzYW5pdGl6ZUJyaWRnZVVybChsb2NhdGlvbi5ocmVmKSxcbiAgICAgICAgICAgICAgZXZlbnRzOiBbLi4uc3RhdGUubGl2ZUV2ZW50c10sXG4gICAgICAgICAgICAgIHdhcm5pbmdzOiBbXG4gICAgICAgICAgICAgICAgLi4uc3RhdGUud2FybmluZ3MsXG4gICAgICAgICAgICAgICAgLi4uKHN0YXRlLmRyb3BwZWRMaXZlRXZlbnRDb3VudCA+IDBcbiAgICAgICAgICAgICAgICAgID8gW2BGYWxsYmFjayBpbnN0cnVtZW50YXRpb24gYnVmZmVyIGRyb3BwZWQgJHtzdGF0ZS5kcm9wcGVkTGl2ZUV2ZW50Q291bnR9IGV2ZW50IG9ic2VydmF0aW9uJHtzdGF0ZS5kcm9wcGVkTGl2ZUV2ZW50Q291bnQgPT09IDEgPyAnJyA6ICdzJ30gYXQgaXRzIDMwMC1ldmVudCBsaW1pdC5gXVxuICAgICAgICAgICAgICAgICAgOiBbXSksXG4gICAgICAgICAgICAgICAgJ0ZhbGxiYWNrIGluc3RydW1lbnRhdGlvbiBzbmFwc2hvdCBjb3VsZCBub3QgcmVjb3ZlciBwYWdlLXdvcmxkIHJlc3BvbnNlLW9ic2VydmF0aW9uIGNvdmVyYWdlIGNvdW50ZXJzLidcbiAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgICAgY292ZXJhZ2U6IHtcbiAgICAgICAgICAgICAgICBldmVudEJ1ZmZlcjoge1xuICAgICAgICAgICAgICAgICAgbGltaXQ6IDMwMCxcbiAgICAgICAgICAgICAgICAgIHJldGFpbmVkRXZlbnRDb3VudDogc3RhdGUubGl2ZUV2ZW50cy5sZW5ndGgsXG4gICAgICAgICAgICAgICAgICBkcm9wcGVkRXZlbnRDb3VudDogc3RhdGUuZHJvcHBlZExpdmVFdmVudENvdW50LFxuICAgICAgICAgICAgICAgICAgZHJvcHBlZEJ5UmVhc29uOlxuICAgICAgICAgICAgICAgICAgICBzdGF0ZS5kcm9wcGVkTGl2ZUV2ZW50Q291bnQgPiAwXG4gICAgICAgICAgICAgICAgICAgICAgPyB7ICdmYWxsYmFjay1ldmVudC1idWZmZXItbGltaXQnOiBzdGF0ZS5kcm9wcGVkTGl2ZUV2ZW50Q291bnQgfVxuICAgICAgICAgICAgICAgICAgICAgIDoge31cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICA6IHVuZGVmaW5lZCxcbiAgICAgICAgd2FybmluZ3M6IFtcbiAgICAgICAgICAuLi5zdGF0ZS53YXJuaW5ncyxcbiAgICAgICAgICBQQUdFX1dPUkxEX0lOVEVHUklUWV9XQVJOSU5HLFxuICAgICAgICAgICdUaW1lZCBvdXQgd2FpdGluZyBmb3IgaW5zdHJ1bWVudGVkIHNuYXBzaG90IHJlc3BvbnNlLidcbiAgICAgICAgXVxuICAgICAgfSk7XG4gICAgfSwgNzAwKTtcblxuICAgIHBlbmRpbmdSZXF1ZXN0cy5zZXQocmVxdWVzdElkLCB7XG4gICAgICByZXNvbHZlLFxuICAgICAgdGltZW91dFxuICAgIH0pO1xuICAgIHdpbmRvdy5wb3N0TWVzc2FnZShcbiAgICAgIHtcbiAgICAgICAgX19ibGFuY2hlOiAnYnVycC1icmlkZ2UnLFxuICAgICAgICB0eXBlOiAnaW5zdHJ1bWVudGF0aW9uLXNuYXBzaG90LXJlcXVlc3QnLFxuICAgICAgICBwYXlsb2FkOiB7XG4gICAgICAgICAgcmVxdWVzdElkXG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICAnKidcbiAgICApO1xuICB9KTtcbn1cbiJdLAogICJtYXBwaW5ncyI6ICI7OztBQXdCQSxNQUFNLFFBQVE7QUFBQSxJQUNaLGNBQWM7QUFBQSxJQUNkLFVBQVUsQ0FBQztBQUFBLElBQ1gsWUFBWSxDQUFDO0FBQUEsSUFDYixXQUFXO0FBQUEsSUFDWCx1QkFBdUI7QUFBQSxFQUN6QjtBQUVBLE1BQU0sK0JBQ0o7QUFFRixXQUFTLGtCQUFrQixRQUF3QjtBQUNqRCxRQUFJO0FBQ0YsWUFBTSxTQUFTLElBQUksSUFBSSxRQUFRLFNBQVMsSUFBSTtBQUM1QyxVQUFJLE9BQU8sYUFBYSxXQUFXLE9BQU8sYUFBYSxVQUFVO0FBQy9ELGVBQU8sR0FBRyxPQUFPLFFBQVEsR0FBRyxPQUFPLGFBQWEsVUFBVSxlQUFlLEVBQUU7QUFBQSxNQUM3RTtBQUNBLGFBQU8sV0FBVztBQUNsQixhQUFPLFdBQVc7QUFDbEIsYUFBTyxPQUFPO0FBQ2QsWUFBTSxRQUFRLENBQUMsR0FBRyxvQkFBSSxJQUFJLENBQUMsR0FBRyxPQUFPLGFBQWEsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLEtBQUs7QUFDakUsYUFBTyxTQUFTLE1BQU0sU0FBUyxJQUMzQixJQUFJLE1BQU0sSUFBSSxDQUFDLFNBQVMsR0FBRyxtQkFBbUIsSUFBSSxDQUFDLEdBQUcsRUFBRSxLQUFLLEdBQUcsQ0FBQyxLQUNqRTtBQUNKLGFBQU8sT0FBTyxTQUFTO0FBQUEsSUFDekIsUUFBUTtBQUNOLGFBQU87QUFBQSxJQUNUO0FBQUEsRUFDRjtBQUVBLFdBQVMsbUJBQW1CLE9BQWUsWUFBWSxLQUFhO0FBQ2xFLFdBQU8sTUFDSixRQUFRLDJCQUEyQixDQUFDLFFBQVEsa0JBQWtCLEdBQUcsQ0FBQyxFQUNsRSxRQUFRLDhCQUE4QiwyQkFBMkIsRUFDakUsUUFBUSw2Q0FBNkMsZUFBZSxFQUNwRSxRQUFRLGdCQUFn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
