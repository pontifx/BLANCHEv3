(() => {
  const globalKey = '__blancheBurpBridgeInstrumented';
  if ((window as Window & { [globalKey]?: boolean })[globalKey]) {
    return;
  }

  (window as Window & { [globalKey]?: boolean })[globalKey] = true;
  document.documentElement?.setAttribute('data-blanche-burp-bridge', 'true');

  type InstrumentationEvent = {
    id: string;
    type:
      | 'blob-created'
      | 'blob-revoked'
      | 'script-added'
      | 'stylesheet-added'
      | 'image-added'
      | 'iframe-added'
      | 'worker-constructed'
      | 'shared-worker-constructed'
      | 'websocket-constructed'
      | 'eventsource-constructed'
      | 'network-request'
      | 'beacon-sent'
      | 'storage-write'
      | 'route-change'
      | 'runtime-error'
      | 'unhandled-rejection'
      | 'dom-mutation'
      | 'feature-candidates-observed'
      | 'lifecycle';
    observedAt: string;
    pageUrl: string;
    frameHref: string;
    url?: string;
    attributes: Record<string, unknown>;
  };

  type InstrumentationCoverage = {
    eventBuffer: {
      limit: number;
      retainedEventCount: number;
      droppedEventCount: number;
      droppedByReason: Record<string, number>;
    };
    responseObservation: {
      responseLimit: number;
      perResponseByteLimit: number;
      totalByteLimit: number;
      eligibleResponseCount: number;
      startedResponseCount: number;
      observedResponseCount: number;
      candidateEventCount: number;
      capturedBytes: number;
      droppedResponseCount: number;
      truncatedResponseCount: number;
      droppedByReason: Record<string, number>;
      truncatedByReason: Record<string, number>;
    };
  };

  const maxInstrumentationEvents = 400;

  const state = {
    version: '0.3.0',
    startedAt: new Date().toISOString(),
    events: [] as InstrumentationEvent[],
    warnings: [] as string[],
    droppedEventCount: 0,
    droppedEventsByReason: {} as Record<string, number>
  };

  const sanitizeObservedUrl = (rawUrl: string | URL | undefined): string | undefined => {
    if (rawUrl === undefined) {
      return undefined;
    }
    try {
      const parsed = new URL(String(rawUrl), location.href);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return `${parsed.protocol}${parsed.protocol === 'blob:' ? '[redacted]' : ''}`;
      }
      parsed.username = '';
      parsed.password = '';
      parsed.hash = '';
      const names = [...new Set([...parsed.searchParams.keys()])].sort();
      parsed.search = names.length > 0
        ? `?${names.map((name) => `${encodeURIComponent(name)}=`).join('&')}`
        : '';
      parsed.pathname = parsed.pathname
        .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, '{uuid}')
        .replace(/\b[0-9a-f]{24,}\b/gi, '{hex}')
        .replace(/\b\d{4,}\b/g, '{id}');
      return parsed.toString();
    } catch {
      return '[unparseable-url]';
    }
  };

  const sanitizeSensitiveText = (value: unknown, maxLength = 300): string => {
    const text = String(value ?? '');
    return text
      .replace(/https?:\/\/[^\s"'<>]+/gi, (url) => sanitizeObservedUrl(url) ?? '[redacted-url]')
      .replace(/(\/\/)[^/\s:@]+:[^@\s/]+@/g, '$1[redacted-credentials]@')
      .replace(/([?&][A-Za-z0-9_.~%-]{1,100})=([^&#\s]*)/g, '$1=[redacted]')
      .replace(/#[^\s"'<>]*/g, '#[redacted]')
      .replace(/\b(bearer)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [redacted]')
      .replace(
        /\b(password|passwd|secret|access[-_]?token|refresh[-_]?token|authorization|api[-_]?key|session[-_]?id|cookie)\s*[:=]\s*[^\s,;]+/gi,
        '$1=[redacted]'
      )
      .slice(0, maxLength);
  };

  const isUrlLikeAttribute = (key: string): boolean => {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    return (
      normalized.endsWith('url') ||
      normalized.endsWith('uri') ||
      normalized.endsWith('href') ||
      normalized.endsWith('src') ||
      normalized === 'endpoint' ||
      normalized === 'location' ||
      normalized === 'referrer' ||
      normalized === 'initiator'
    );
  };

  const sanitizeEventAttributes = (
    attributes: Record<string, unknown>
  ): Record<string, unknown> => {
    const visit = (key: string, value: unknown, depth: number): unknown => {
      if (value === undefined || value === null) {
        return value;
      }
      if (isUrlLikeAttribute(key)) {
        if (Array.isArray(value)) {
          return value
            .slice(0, 100)
            .map((entry) =>
              typeof entry === 'string' || entry instanceof URL
                ? sanitizeObservedUrl(entry) ?? '[redacted-url]'
                : visit(key, entry, depth + 1)
            );
        }
        if (typeof value === 'string' || value instanceof URL) {
          return sanitizeObservedUrl(value) ?? '[redacted-url]';
        }
      }
      if (depth >= 5) {
        return '[depth-limit]';
      }
      if (Array.isArray(value)) {
        return value.slice(0, 100).map((entry) => visit(key, entry, depth + 1));
      }
      if (typeof value === 'object') {
        return Object.fromEntries(
          Object.entries(value as Record<string, unknown>)
            .slice(0, 100)
            .map(([childKey, entry]) => [childKey, visit(childKey, entry, depth + 1)])
        );
      }
      return value;
    };

    return Object.fromEntries(
      Object.entries(attributes)
        .slice(0, 100)
        .map(([key, value]) => [key, visit(key, value, 0)])
    );
  };

  const captureInitiator = (): string | undefined => {
    const stack = new Error().stack ?? '';
    for (const line of stack.split('\n').slice(2, 10)) {
      const match = line.match(/(https?:\/\/[^\s)]+?)(?::\d+){1,2}(?:\)?$|\s)/i);
      if (!match?.[1]) {
        continue;
      }
      return match[1];
    }
    return undefined;
  };

  const safeErrorSummary = (
    value: unknown
  ): { name: string; message?: string; messageLength?: number } => {
    if (value instanceof Error) {
      const message = String(value.message ?? '');
      return {
        name: sanitizeSensitiveText(value.name || 'Error', 80),
        message: message ? sanitizeSensitiveText(message) : undefined,
        messageLength: message.length
      };
    }
    const message =
      typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
        ? String(value)
        : '';
    return {
      name: typeof value,
      message: message ? sanitizeSensitiveText(message) : undefined,
      messageLength: message.length || undefined
    };
  };

  type ObservedFeatureCandidate = {
    key: string;
    currentValue?: boolean | number | string | null;
    suggestedValue?: boolean | number | string | null;
    confidence: 'high' | 'medium' | 'low';
    detail: string;
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
    droppedByReason: {} as Record<string, number>,
    truncatedByReason: {} as Record<string, number>
  };
  const maxObservedResponses = 40;
  const maxObservedResponseBytes = 32768;
  const maxObservedTotalBytes = 524288;

  const postBridgeMessage = (type: string, payload: unknown) => {
    window.postMessage(
      {
        __blanche: 'burp-bridge',
        type,
        payload
      },
      '*'
    );
  };

  const pushEvent = (
    type: InstrumentationEvent['type'],
    url: string | undefined,
    attributes: Record<string, unknown>
  ) => {
    const event: InstrumentationEvent = {
      id: crypto.randomUUID(),
      type,
      observedAt: new Date().toISOString(),
      pageUrl: sanitizeObservedUrl(location.href) ?? '[redacted-url]',
      frameHref: sanitizeObservedUrl(location.href) ?? '[redacted-url]',
      url: sanitizeObservedUrl(url),
      attributes: sanitizeEventAttributes(attributes)
    };

    state.events.unshift(event);
    if (state.events.length > maxInstrumentationEvents) {
      const dropped = state.events.length - maxInstrumentationEvents;
      state.events.length = maxInstrumentationEvents;
      state.droppedEventCount += dropped;
      state.droppedEventsByReason['event-buffer-limit'] =
        (state.droppedEventsByReason['event-buffer-limit'] ?? 0) + dropped;
    }
    postBridgeMessage('instrumentation-event', event);
  };

  const looksLikeFlagName = (value: string): boolean => {
    return (
      /(?:^|[-_.:/])(?:feature|features|flag|flags|experiment|experiments|variant|variation|rollout|beta|preview|labs?|gate|gates|toggle|toggles|enabled?|disabled?)(?:$|[-_.:/])/i.test(
        value
      ) ||
      /(?:feature|flag|experiment|variant|variation|rollout|preview|beta|labs?|gate|toggle|enabled|disabled|new[A-Z]|legacy[A-Z])/.test(
        value
      )
    );
  };

  const looksSensitive = (value: string): boolean => {
    return /(?:^|[-_.:/])(?:auth|authorization|access[-_]?token|refresh[-_]?token|jwt|csrf|password|passwd|secret|credential|session[-_]?id|license|subscription|permission|role)(?:$|[-_.:/])/i.test(
      value
    );
  };

  const toggleValues = (
    value: unknown
  ):
    | {
        currentValue: boolean | number | string;
        suggestedValue: boolean | number | string;
      }
    | undefined => {
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
    if (typeof value !== 'string') {
      return undefined;
    }
    const normalized = value.trim().toLowerCase();
    const pairs: Record<string, string> = {
      false: 'true',
      true: 'false',
      '0': '1',
      '1': '0',
      off: 'on',
      on: 'off',
      disabled: 'enabled',
      enabled: 'disabled',
      no: 'yes',
      yes: 'no',
      control: 'treatment',
      treatment: 'control'
    };
    const suggestedValue = pairs[normalized];
    return suggestedValue
      ? {
          currentValue: value,
          suggestedValue
        }
      : undefined;
  };

  const extractFeatureCandidates = (text: string): ObservedFeatureCandidate[] => {
    const candidates = new Map<string, ObservedFeatureCandidate>();
    const observe = (candidate: ObservedFeatureCandidate) => {
      const key = candidate.key.trim().slice(0, 180);
      if (key.length < 2 || looksSensitive(key)) {
        return;
      }
      const signature = key.toLowerCase().replace(/[^a-z0-9]+/g, '-');
      const existing = candidates.get(signature);
      if (!existing || (existing.confidence !== 'high' && candidate.confidence === 'high')) {
        candidates.set(signature, {
          ...candidate,
          key
        });
      }
    };

    try {
      const parsed = JSON.parse(text) as unknown;
      let visited = 0;
      const visit = (value: unknown, inheritedFlagContext: boolean) => {
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
        if (!value || typeof value !== 'object') {
          return;
        }
        const record = value as Record<string, unknown>;
        const identity = ['featureKey', 'flagKey', 'key', 'feature', 'name', 'id']
          .map((key) => record[key])
          .find((entry): entry is string => typeof entry === 'string' && entry.length >= 2);
        const stateEntry = ['enabled', 'isEnabled', 'value', 'variation', 'variant', 'state']
          .map((key) => [key, record[key]] as const)
          .find((entry) => toggleValues(entry[1]) !== undefined);
        if (identity && stateEntry && !looksSensitive(identity)) {
          const toggle = toggleValues(stateEntry[1]);
          if (toggle) {
            observe({
              key: identity,
              ...toggle,
              confidence: 'high',
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
              confidence: looksLikeFlagName(key) ? 'high' : 'medium',
              detail: 'Flag-shaped value in a response already delivered to the page.'
            });
          }
          if (entry && typeof entry === 'object') {
            visit(entry, flagContext);
          }
        }
      };
      visit(parsed, false);
    } catch {
      // JavaScript and non-JSON configuration are handled by the compact-source patterns below.
    }

    const providerPattern =
      /(?:isEnabled|isFeatureEnabled|featureEnabled|hasFeature|useFeature|variation|getFeatureFlag|getBooleanValue|checkGate|isGateEnabled)\s*\(\s*["'`]([^"'`]{2,160})["'`]/g;
    for (const match of text.matchAll(providerPattern)) {
      if (match[1]) {
        observe({
          key: match[1],
          suggestedValue: true,
          confidence: 'high',
          detail: 'Flag-client callsite in an already-delivered response.'
        });
      }
      if (candidates.size >= 80) {
        break;
      }
    }

    const pairPattern =
      /(?:["'`]([^"'`]{2,160})["'`]|([A-Za-z_$][\w$.-]{1,159}))\s*:\s*(true|false|!0|!1|0|1|["'`](?:enabled|disabled|on|off|control|treatment|yes|no)["'`])/g;
    for (const match of text.matchAll(pairPattern)) {
      const key = match[1] ?? match[2];
      const raw = (match[3] ?? '').replace(/^["'`]|["'`]$/g, '');
      const toggle = toggleValues(raw === '!0' ? true : raw === '!1' ? false : raw);
      const index = match.index ?? 0;
      const nearby = text.slice(Math.max(0, index - 100), index + 220);
      if (key && toggle && (looksLikeFlagName(key) || /feature|flag|experiment|gate/i.test(nearby))) {
        observe({
          key,
          ...toggle,
          confidence: looksLikeFlagName(key) ? 'high' : 'medium',
          detail: 'Toggle-shaped key/value pair in an already-delivered response.'
        });
      }
      if (candidates.size >= 80) {
        break;
      }
    }

    return [...candidates.values()].slice(0, 80);
  };

  const shouldInspectResponse = (contentType: string, responseUrl: string): boolean => {
    return (
      /json|javascript|ecmascript|text\/plain/i.test(contentType) ||
      /(?:feature|flag|experiment|variant|rollout|bootstrap|config|settings|\.m?js|\.json)(?:$|[?#/])/i.test(
        responseUrl
      )
    );
  };

  const incrementReason = (reasons: Record<string, number>, reason: string): void => {
    reasons[reason] = (reasons[reason] ?? 0) + 1;
  };

  const beginResponseObservation = (): number | undefined => {
    featureObservationBudget.eligibleResponseCount += 1;
    if (featureObservationBudget.startedResponseCount >= maxObservedResponses) {
      featureObservationBudget.droppedResponseCount += 1;
      incrementReason(featureObservationBudget.droppedByReason, 'response-count-limit');
      return undefined;
    }

    const remainingTotal =
      maxObservedTotalBytes -
      featureObservationBudget.capturedBytes -
      featureObservationBudget.reservedBytes;
    if (remainingTotal <= 0) {
      featureObservationBudget.droppedResponseCount += 1;
      incrementReason(featureObservationBudget.droppedByReason, 'total-byte-limit');
      return undefined;
    }

    const byteAllowance = Math.min(maxObservedResponseBytes, remainingTotal);
    featureObservationBudget.startedResponseCount += 1;
    featureObservationBudget.reservedBytes += byteAllowance;
    return byteAllowance;
  };

  const finishResponseObservation = (input: {
    byteAllowance: number;
    capturedBytes: number;
    observed: boolean;
    truncated: boolean;
    dropReason?: string;
  }): void => {
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
        input.dropReason ?? 'body-unavailable'
      );
    }
    if (input.truncated) {
      featureObservationBudget.truncatedResponseCount += 1;
      incrementReason(
        featureObservationBudget.truncatedByReason,
        input.byteAllowance < maxObservedResponseBytes
          ? 'total-byte-limit'
          : 'per-response-byte-limit'
      );
    }
  };

  const truncateUtf8 = (
    value: string,
    byteLimit: number
  ): { text: string; bytes: number; truncated: boolean } => {
    const encoded = new TextEncoder().encode(value);
    if (encoded.byteLength <= byteLimit) {
      return {
        text: value,
        bytes: encoded.byteLength,
        truncated: false
      };
    }

    let end = Math.max(0, Math.min(byteLimit, encoded.byteLength));
    while (end > 0 && end < encoded.byteLength && (encoded[end]! & 0xc0) === 0x80) {
      end -= 1;
    }
    return {
      text: new TextDecoder().decode(encoded.slice(0, end)),
      bytes: end,
      truncated: true
    };
  };

  const stringifyBoundedJson = (
    value: unknown,
    characterLimit: number
  ): { text: string; truncated: boolean } => {
    const chunks: string[] = [];
    const seen = new WeakSet<object>();
    let retainedCharacters = 0;
    let visitedNodes = 0;
    let truncated = false;
    const maxNodes = 1_000;
    const maxEntriesPerContainer = 100;
    const maxDepth = 6;
    const append = (text: string): boolean => {
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
    const visit = (entry: unknown, depth: number): boolean => {
      visitedNodes += 1;
      if (visitedNodes > maxNodes || depth > maxDepth) {
        truncated = true;
        return append('null');
      }
      if (entry === null || typeof entry === 'boolean' || typeof entry === 'number') {
        return append(JSON.stringify(entry));
      }
      if (typeof entry === 'string') {
        const remaining = Math.max(0, characterLimit - retainedCharacters - 2);
        const bounded = entry.slice(0, remaining);
        if (bounded.length < entry.length) truncated = true;
        return append(JSON.stringify(bounded));
      }
      if (typeof entry !== 'object') {
        return append('null');
      }
      if (seen.has(entry)) {
        truncated = true;
        return append('null');
      }
      seen.add(entry);
      if (Array.isArray(entry)) {
        if (!append('[')) return false;
        const limit = Math.min(entry.length, maxEntriesPerContainer);
        for (let index = 0; index < limit; index += 1) {
          if (index > 0 && !append(',')) return false;
          if (!visit(entry[index], depth + 1)) return false;
        }
        if (entry.length > limit) truncated = true;
        return append(']');
      }
      if (!append('{')) return false;
      let retainedEntries = 0;
      for (const key in entry as Record<string, unknown>) {
        if (!Object.prototype.hasOwnProperty.call(entry, key)) continue;
        if (retainedEntries >= maxEntriesPerContainer) {
          truncated = true;
          break;
        }
        if (retainedEntries > 0 && !append(',')) return false;
        const remaining = Math.max(0, characterLimit - retainedCharacters - 2);
        const boundedKey = key.slice(0, Math.min(200, remaining));
        if (boundedKey.length < key.length) truncated = true;
        if (!append(JSON.stringify(boundedKey)) || !append(':')) return false;
        let child: unknown;
        try {
          child = (entry as Record<string, unknown>)[key];
        } catch {
          truncated = true;
          child = null;
        }
        if (!visit(child, depth + 1)) return false;
        retainedEntries += 1;
      }
      return append('}');
    };
    visit(value, 0);
    return { text: chunks.join(''), truncated };
  };

  const inspectResponse = async (
    response: Response,
    transport: 'fetch' | 'xhr',
    fallbackUrl?: string
  ) => {
    const responseUrl = response.url || fallbackUrl || location.href;
    const contentType = response.headers.get('content-type') ?? '';
    if (!shouldInspectResponse(contentType, responseUrl)) {
      return;
    }

    const byteLimit = beginResponseObservation();
    if (byteLimit === undefined) {
      return;
    }
    const reader = response.body?.getReader();
    if (!reader) {
      finishResponseObservation({
        byteAllowance: byteLimit,
        capturedBytes: 0,
        observed: false,
        truncated: false,
        dropReason: 'body-unavailable'
      });
      return;
    }

    const decoder = new TextDecoder();
    let text = '';
    let capturedBytes = 0;
    let truncated = false;
    try {
      while (capturedBytes < byteLimit) {
        const next = await reader.read();
        if (next.done) {
          break;
        }
        const remaining = byteLimit - capturedBytes;
        const accepted =
          next.value.byteLength > remaining ? next.value.slice(0, remaining) : next.value;
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
        await reader.cancel().catch(() => {});
      }
    } catch {
      finishResponseObservation({
        byteAllowance: byteLimit,
        capturedBytes: 0,
        observed: false,
        truncated: false,
        dropReason: 'body-read-error'
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
    pushEvent('feature-candidates-observed', responseUrl, {
      transport,
      responseUrl,
      status: response.status,
      contentType,
      capturedBytes,
      truncated,
      candidates
    });
  };

  const inspectXhr = (request: XMLHttpRequest) => {
    const responseUrl = request.responseURL || location.href;
    const contentType = request.getResponseHeader('content-type') ?? '';
    if (!shouldInspectResponse(contentType, responseUrl)) {
      return;
    }

    const byteLimit = beginResponseObservation();
    if (byteLimit === undefined) {
      return;
    }

    let text = '';
    let sourceTruncated = false;
    try {
      if (request.responseType === '' || request.responseType === 'text') {
        const responseText = request.responseText;
        sourceTruncated = responseText.length > byteLimit;
        text = responseText.slice(0, byteLimit);
      } else if (request.responseType === 'json') {
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
        dropReason: 'body-read-error'
      });
      return;
    }
    if (!text) {
      finishResponseObservation({
        byteAllowance: byteLimit,
        capturedBytes: 0,
        observed: false,
        truncated: false,
        dropReason: 'body-unavailable'
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
    pushEvent('feature-candidates-observed', responseUrl, {
      transport: 'xhr',
      responseUrl,
      status: request.status,
      contentType,
      capturedBytes: boundedText.bytes,
      truncated: sourceTruncated || boundedText.truncated,
      candidates
    });
  };

  const describeNode = (
    node: Element
  ): Array<{
    type: InstrumentationEvent['type'];
    url?: string;
    attributes: Record<string, unknown>;
  }> => {
    const tagName = node.tagName.toLowerCase();
    if (tagName === 'script') {
      return [
        {
          type: 'script-added',
          url: (node as HTMLScriptElement).src || undefined,
          attributes: {
            tagName,
            inline: !(node as HTMLScriptElement).src,
            async: node.hasAttribute('async'),
            defer: node.hasAttribute('defer'),
            typeAttribute: node.getAttribute('type')
          }
        }
      ];
    }

    if (tagName === 'link' && node.getAttribute('rel')?.includes('stylesheet')) {
      return [
        {
          type: 'stylesheet-added',
          url: (node as HTMLLinkElement).href || undefined,
          attributes: {
            tagName,
            rel: node.getAttribute('rel'),
            media: node.getAttribute('media')
          }
        }
      ];
    }

    if (tagName === 'img') {
      return [
        {
          type: 'image-added',
          url: (node as HTMLImageElement).currentSrc || (node as HTMLImageElement).src || undefined,
          attributes: {
            tagName,
            loading: node.getAttribute('loading')
          }
        }
      ];
    }

    if (tagName === 'iframe' || tagName === 'frame') {
      return [
        {
          type: 'iframe-added',
          url: (node as HTMLIFrameElement).src || undefined,
          attributes: {
            tagName,
            sandbox: node.getAttribute('sandbox')
          }
        }
      ];
    }

    return [];
  };

  const recordElementTree = (node: Node) => {
    if (!(node instanceof Element)) {
      return;
    }

    const maxVisitedElements = 200;
    const walker = node.ownerDocument.createTreeWalker(node, NodeFilter.SHOW_ELEMENT);
    let current: Node | null = walker.currentNode;
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
      state.droppedEventsByReason['mutation-subtree-node-limit'] =
        (state.droppedEventsByReason['mutation-subtree-node-limit'] ?? 0) + 1;
      if (!state.warnings.includes('A mutated DOM subtree exceeded the 200-element inspection cap.')) {
        state.warnings.push('A mutated DOM subtree exceeded the 200-element inspection cap.');
      }
    }
  };

  try {
    const originalCreateObjectUrl = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (object: Blob | MediaSource) => {
      const createdUrl = originalCreateObjectUrl(object);
      pushEvent('blob-created', createdUrl, {
        objectType: object.constructor.name,
        type: 'type' in object ? (object as Blob).type : null,
        size: 'size' in object ? (object as Blob).size : null
      });
      return createdUrl;
    };

    const originalRevokeObjectUrl = URL.revokeObjectURL.bind(URL);
    URL.revokeObjectURL = (url: string) => {
      pushEvent('blob-revoked', url, {});
      originalRevokeObjectUrl(url);
    };
  } catch (error) {
    state.warnings.push(
      sanitizeSensitiveText(`Unable to patch URL blob APIs: ${String(error)}`, 500)
    );
  }

  try {
    const originalFetch = window.fetch.bind(window);
    window.fetch = (async (...args: Parameters<typeof fetch>) => {
      const requestUrl =
        typeof args[0] === 'string'
          ? args[0]
          : args[0] instanceof URL
            ? args[0].href
            : args[0]?.url;
      const method =
        args[1]?.method ??
        (typeof Request !== 'undefined' && args[0] instanceof Request ? args[0].method : 'GET');
      pushEvent('network-request', requestUrl, {
        transport: 'fetch',
        method: String(method || 'GET').toUpperCase().slice(0, 16),
        initiator: captureInitiator() ?? null
      });
      const response = await originalFetch(...args);
      try {
        void inspectResponse(response.clone(), 'fetch', requestUrl);
      } catch {
        // Opaque and already-consumed responses can be uncloneable; the page still receives its original.
      }
      return response;
    }) as typeof window.fetch;
  } catch (error) {
    state.warnings.push(
      sanitizeSensitiveText(`Unable to observe fetch responses: ${String(error)}`, 500)
    );
  }

  try {
    const requestMetadata = new WeakMap<XMLHttpRequest, { method: string; url: string }>();
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (
      this: XMLHttpRequest,
      method: string,
      url: string | URL,
      async = true,
      username?: string | null,
      password?: string | null
    ) {
      requestMetadata.set(this, {
        method: String(method || 'GET').toUpperCase().slice(0, 16),
        url: String(url)
      });
      Reflect.apply(originalOpen, this, [method, url, async, username, password]);
    } as typeof XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function (
      this: XMLHttpRequest,
      body?: Document | XMLHttpRequestBodyInit | null
    ) {
      const metadata = requestMetadata.get(this);
      pushEvent('network-request', metadata?.url, {
        transport: 'xhr',
        method: metadata?.method ?? 'GET',
        initiator: captureInitiator() ?? null
      });
      this.addEventListener(
        'loadend',
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

  if ('Worker' in window) {
    const OriginalWorker = Worker;
    (window as Window & { Worker: typeof Worker }).Worker = class extends OriginalWorker {
      constructor(scriptUrl: string | URL, options?: WorkerOptions) {
        pushEvent('worker-constructed', String(scriptUrl), {
          type: options?.type ?? 'classic',
          credentials: options?.credentials ?? null,
          name: options?.name ?? null,
          initiator: captureInitiator() ?? null
        });
        super(scriptUrl, options);
      }
    };
  }

  if ('SharedWorker' in window) {
    const OriginalSharedWorker = SharedWorker;
    (
      window as Window & {
      SharedWorker: typeof SharedWorker;
      }
    ).SharedWorker = class extends OriginalSharedWorker {
      constructor(scriptUrl: string | URL, options?: string | WorkerOptions) {
        pushEvent('shared-worker-constructed', String(scriptUrl), {
          name: typeof options === 'string' ? options : options?.name ?? null,
          initiator: captureInitiator() ?? null
        });
        super(scriptUrl, options);
      }
    };
  }

  if ('WebSocket' in window) {
    try {
      const OriginalWebSocket = WebSocket;
      (window as Window & { WebSocket: typeof WebSocket }).WebSocket = class extends OriginalWebSocket {
        constructor(url: string | URL, protocols?: string | string[]) {
          pushEvent('websocket-constructed', String(url), {
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

  if ('EventSource' in window) {
    try {
      const OriginalEventSource = EventSource;
      (window as Window & { EventSource: typeof EventSource }).EventSource = class extends OriginalEventSource {
        constructor(url: string | URL, eventSourceInitDict?: EventSourceInit) {
          pushEvent('eventsource-constructed', String(url), {
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

  if (typeof navigator.sendBeacon === 'function') {
    try {
      const originalSendBeacon = navigator.sendBeacon.bind(navigator);
      navigator.sendBeacon = (url: string | URL, data?: BodyInit | null): boolean => {
        const approximateBytes =
          typeof data === 'string'
            ? data.length
            : data instanceof Blob
              ? data.size
              : data instanceof ArrayBuffer
                ? data.byteLength
                : ArrayBuffer.isView(data)
                  ? data.byteLength
                  : undefined;
        pushEvent('beacon-sent', String(url), {
          approximateBytes: approximateBytes ?? null,
          approximateBytesBasis: typeof data === 'string' ? 'utf16-code-units' : 'binary-size',
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
    const storageArea = (target: Storage): string => {
      try {
        if (target === window.localStorage) return 'localStorage';
        if (target === window.sessionStorage) return 'sessionStorage';
      } catch {
        // Storage access can be denied by page policy.
      }
      return 'storage';
    };
    Storage.prototype.setItem = function (this: Storage, key: string, value: string): void {
      pushEvent('storage-write', undefined, {
        area: storageArea(this),
        operation: 'setItem',
        key: String(key).slice(0, 180),
        valueLength: String(value).length,
        initiator: captureInitiator() ?? null
      });
      originalSetItem.call(this, key, value);
    };
    Storage.prototype.removeItem = function (this: Storage, key: string): void {
      pushEvent('storage-write', undefined, {
        area: storageArea(this),
        operation: 'removeItem',
        key: String(key).slice(0, 180),
        initiator: captureInitiator() ?? null
      });
      originalRemoveItem.call(this, key);
    };
    Storage.prototype.clear = function (this: Storage): void {
      pushEvent('storage-write', undefined, {
        area: storageArea(this),
        operation: 'clear',
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
    for (const methodName of ['pushState', 'replaceState'] as const) {
      const original = history[methodName].bind(history);
      history[methodName] = ((data: unknown, unused: string, url?: string | URL | null) => {
        pushEvent('route-change', String(url ?? location.href), {
          operation: methodName,
          initiator: captureInitiator() ?? null
        });
        original(data, unused, url);
      }) as History[typeof methodName];
    }
  } catch (error) {
    state.warnings.push(
      sanitizeSensitiveText(`Unable to observe history route changes: ${String(error)}`, 500)
    );
  }

  window.addEventListener('error', (event) => {
    pushEvent('runtime-error', event.filename || undefined, {
      ...safeErrorSummary(event.error ?? event.message),
      line: event.lineno || null,
      column: event.colno || null
    });
  });
  window.addEventListener('unhandledrejection', (event) => {
    pushEvent('unhandled-rejection', undefined, safeErrorSummary(event.reason));
  });

  let domMutationEventCount = 0;
  const observer = new MutationObserver((mutations) => {
    let addedNodes = 0;
    let removedNodes = 0;
    let attributeChanges = 0;
    for (const mutation of mutations) {
      addedNodes += mutation.addedNodes.length;
      removedNodes += mutation.removedNodes.length;
      attributeChanges += mutation.type === 'attributes' ? 1 : 0;
      for (const addedNode of Array.from(mutation.addedNodes)) {
        recordElementTree(addedNode);
      }
    }
    if (domMutationEventCount < 50) {
      domMutationEventCount += 1;
      pushEvent('dom-mutation', undefined, {
        mutationCount: mutations.length,
        addedNodes,
        removedNodes,
        attributeChanges
      });
    } else {
      state.droppedEventCount += 1;
      state.droppedEventsByReason['dom-mutation-event-limit'] =
        (state.droppedEventsByReason['dom-mutation-event-limit'] ?? 0) + 1;
    }
  });

  if (document.documentElement) {
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true
    });
  } else {
    state.warnings.push('Document root was unavailable when MutationObserver started.');
  }

  document.addEventListener(
    'DOMContentLoaded',
    () => {
      pushEvent('lifecycle', undefined, {
        stage: 'domcontentloaded'
      });
    },
    { once: true }
  );

  window.addEventListener(
    'load',
    () => {
      pushEvent('lifecycle', undefined, {
        stage: 'load'
      });
    },
    { once: true }
  );

  const buildCoverage = (): InstrumentationCoverage => ({
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

  const formatReasonCounts = (reasons: Record<string, number>): string =>
    Object.entries(reasons)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([reason, count]) => `${reason}=${count}`)
      .join(', ');

  const buildCoverageWarnings = (): string[] => {
    const warnings: string[] = [];
    if (state.droppedEventCount > 0) {
      warnings.push(
        `Instrumentation coverage dropped ${state.droppedEventCount} event observation${
          state.droppedEventCount === 1 ? '' : 's'
        }: ${formatReasonCounts(state.droppedEventsByReason)}.`
      );
    }
    if (featureObservationBudget.droppedResponseCount > 0) {
      warnings.push(
        `Runtime response coverage dropped ${featureObservationBudget.droppedResponseCount} eligible body observation${
          featureObservationBudget.droppedResponseCount === 1 ? '' : 's'
        }: ${formatReasonCounts(featureObservationBudget.droppedByReason)}.`
      );
    }
    if (featureObservationBudget.truncatedResponseCount > 0) {
      warnings.push(
        `Runtime response coverage truncated ${featureObservationBudget.truncatedResponseCount} body observation${
          featureObservationBudget.truncatedResponseCount === 1 ? '' : 's'
        }: ${formatReasonCounts(featureObservationBudget.truncatedByReason)}.`
      );
    }
    return warnings;
  };

  window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data || event.data.__blanche !== 'burp-bridge') {
      return;
    }

    if (event.data.type !== 'instrumentation-snapshot-request') {
      return;
    }

    postBridgeMessage('instrumentation-snapshot-response', {
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

  postBridgeMessage('instrumentation-ready', {
    startedAt: state.startedAt
  });
})();
