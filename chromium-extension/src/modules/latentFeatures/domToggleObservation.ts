export interface LatentFeatureDomSignature {
  selector: string;
  parentSelector?: string;
  tagName: string;
  fingerprint: string;
}

export interface LatentFeatureDomSnapshot {
  origin: string;
  signatures: LatentFeatureDomSignature[];
  truncated: boolean;
  limitations: string[];
}

export interface LatentFeatureDomDiffEntry {
  selector: string;
  parentSelector?: string;
  tagName: string;
}

export interface LatentFeatureDomDiff {
  added: LatentFeatureDomDiffEntry[];
  changed: LatentFeatureDomDiffEntry[];
  removed: LatentFeatureDomDiffEntry[];
  truncated: boolean;
  limitations: string[];
}

/**
 * Runs in the target's MAIN world. Keep this function self-contained: Chrome serializes the
 * function body rather than its module closure.
 */
export function captureLatentFeatureDomSignatures(input: {
  expectedOrigin: string;
  maxElements: number;
}): LatentFeatureDomSnapshot {
  if (location.origin !== input.expectedOrigin) {
    throw new Error(`The page origin changed before DOM observation (${location.origin}).`);
  }

  const markerAttribute = 'data-blanche-latent-highlight';
  const styleId = 'blanche-latent-highlight-style';
  document.getElementById(styleId)?.remove();
  document.querySelectorAll(`[${markerAttribute}]`).forEach((element) => {
    element.removeAttribute(markerAttribute);
  });

  const maximum = Math.max(1, Math.min(1_500, Math.floor(input.maxElements)));
  const allElements = Array.from(document.body?.querySelectorAll('*') ?? []);
  const candidates = allElements.filter((element) => {
    const tag = element.localName.toLowerCase();
    return !['script', 'style', 'link', 'meta', 'noscript', 'template'].includes(tag);
  });

  const selectorFor = (element: Element | null): string | undefined => {
    if (!element || element === document.documentElement) return undefined;
    if (element === document.body) return 'body';
    const segments: string[] = [];
    let cursor: Element | null = element;
    for (let depth = 0; cursor && cursor !== document.body && depth < 12; depth += 1) {
      const rawTag = cursor.localName.toLowerCase();
      const tag = /^[a-z][a-z0-9-]*$/.test(rawTag) ? rawTag : '*';
      const parentElement: Element | null = cursor.parentElement;
      if (!parentElement) return undefined;
      const sameTagSiblings: Element[] = Array.from(parentElement.children).filter(
        (sibling: Element) => sibling.localName.toLowerCase() === rawTag
      );
      const position = sameTagSiblings.indexOf(cursor) + 1;
      if (position <= 0) return undefined;
      segments.unshift(`${tag}:nth-of-type(${position})`);
      cursor = parentElement;
    }
    if (cursor !== document.body) return undefined;
    return ['body', ...segments].join(' > ').slice(0, 1_000);
  };

  const hashText = (value: string): string => {
    let hash = 0x811c9dc5;
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193);
    }
    return (hash >>> 0).toString(16).padStart(8, '0');
  };

  const signatures: LatentFeatureDomSignature[] = [];
  for (const element of candidates.slice(0, maximum)) {
    const selector = selectorFor(element);
    if (!selector) continue;
    const directText = Array.from(element.childNodes)
      .filter((node) => node.nodeType === Node.TEXT_NODE)
      .map((node) => node.textContent ?? '')
      .join(' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 200);
    const stateParts = [
      element.localName.toLowerCase(),
      `children:${element.childElementCount}`,
      `text:${directText}`,
      `class:${element.getAttribute('class') ?? ''}`,
      `role:${element.getAttribute('role') ?? ''}`,
      `aria-expanded:${element.getAttribute('aria-expanded') ?? ''}`,
      `aria-hidden:${element.getAttribute('aria-hidden') ?? ''}`,
      `hidden:${element.hasAttribute('hidden')}`,
      `open:${element.hasAttribute('open')}`,
      `disabled:${element.hasAttribute('disabled')}`,
      `checked:${element.hasAttribute('checked')}`,
      `selected:${element.hasAttribute('selected')}`
    ];
    signatures.push({
      selector,
      parentSelector: selectorFor(element.parentElement),
      tagName: element.localName.toLowerCase().slice(0, 80),
      fingerprint: hashText(stateParts.join('\n'))
    });
  }

  return {
    origin: location.origin,
    signatures,
    truncated: candidates.length > maximum,
    limitations: [
      'Top-frame, open-DOM structure only; closed shadow roots and cross-origin frames are not observed.',
      'Element text and attribute values are hashed into fingerprints and are not retained.'
    ]
  };
}

export function diffLatentFeatureDomSignatures(
  before: LatentFeatureDomSnapshot,
  after: LatentFeatureDomSnapshot,
  maximumPerKind = 30
): LatentFeatureDomDiff {
  const maximum = Math.max(1, Math.min(100, Math.floor(maximumPerKind)));
  const beforeBySelector = new Map(before.signatures.map((entry) => [entry.selector, entry]));
  const afterBySelector = new Map(after.signatures.map((entry) => [entry.selector, entry]));
  const addedAll: LatentFeatureDomDiffEntry[] = [];
  const changedAll: LatentFeatureDomDiffEntry[] = [];
  const removedAll: LatentFeatureDomDiffEntry[] = [];

  for (const entry of after.signatures) {
    const previous = beforeBySelector.get(entry.selector);
    if (!previous) {
      addedAll.push(toDiffEntry(entry));
    } else if (previous.fingerprint !== entry.fingerprint) {
      changedAll.push(toDiffEntry(entry));
    }
  }
  for (const entry of before.signatures) {
    if (!afterBySelector.has(entry.selector)) {
      removedAll.push(toDiffEntry(entry));
    }
  }

  const limitations = [
    ...before.limitations,
    ...after.limitations,
    'Changes were observed after the toggle; temporal association does not prove the toggle caused them.'
  ];
  if (before.truncated || after.truncated) {
    limitations.push('The DOM signature element cap was reached, so the observed diff is incomplete.');
  }

  return {
    added: addedAll.slice(0, maximum),
    changed: changedAll.slice(0, maximum),
    removed: removedAll.slice(0, maximum),
    truncated:
      before.truncated ||
      after.truncated ||
      addedAll.length > maximum ||
      changedAll.length > maximum ||
      removedAll.length > maximum,
    limitations: [...new Set(limitations)].slice(0, 20)
  };
}

function toDiffEntry(entry: LatentFeatureDomSignature): LatentFeatureDomDiffEntry {
  return {
    selector: entry.selector,
    parentSelector: entry.parentSelector,
    tagName: entry.tagName
  };
}

/** Runs in the target's MAIN world; keep this function self-contained. */
export function highlightLatentFeatureDomChanges(input: {
  expectedOrigin: string;
  added: LatentFeatureDomDiffEntry[];
  changed: LatentFeatureDomDiffEntry[];
  removed: LatentFeatureDomDiffEntry[];
  durationMs: number;
}): { highlightedCount: number; missedCount: number } {
  if (location.origin !== input.expectedOrigin) {
    throw new Error(`The page origin changed before highlighting (${location.origin}).`);
  }
  const markerAttribute = 'data-blanche-latent-highlight';
  const styleId = 'blanche-latent-highlight-style';
  document.getElementById(styleId)?.remove();
  document.querySelectorAll(`[${markerAttribute}]`).forEach((element) => {
    element.removeAttribute(markerAttribute);
  });

  const highlightToken = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const style = document.createElement('style');
  style.id = styleId;
  style.dataset.blancheLatentHighlightToken = highlightToken;
  style.textContent = `
    [${markerAttribute}="added"] { outline: 4px solid #20c997 !important; outline-offset: 2px !important; animation: blanche-latent-pulse .8s ease-in-out 3 !important; }
    [${markerAttribute}="changed"] { outline: 4px solid #ffc107 !important; outline-offset: 2px !important; animation: blanche-latent-pulse .8s ease-in-out 3 !important; }
    [${markerAttribute}="removed"] { outline: 4px dashed #ff6b6b !important; outline-offset: 2px !important; animation: blanche-latent-pulse .8s ease-in-out 3 !important; }
    @keyframes blanche-latent-pulse { 0%,100% { filter: none; } 50% { filter: brightness(1.25); } }
    @media (prefers-reduced-motion: reduce) { [${markerAttribute}] { animation: none !important; } }
  `;
  (document.head ?? document.documentElement).appendChild(style);

  const duration = Math.max(1_000, Math.min(15_000, Math.floor(input.durationMs)));
  const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches === true;
  const highlightedElements = new Set<Element>();
  let highlightedCount = 0;
  let missedCount = 0;
  const mark = (selector: string | undefined, kind: 'added' | 'changed' | 'removed') => {
    if (!selector) {
      missedCount += 1;
      return;
    }
    try {
      const element = document.querySelector(selector);
      if (!element) {
        missedCount += 1;
        return;
      }
      element.setAttribute(markerAttribute, kind);
      if (!highlightedElements.has(element)) {
        highlightedElements.add(element);
        highlightedCount += 1;
      }
      const color = kind === 'added' ? '#20c997' : kind === 'changed' ? '#ffc107' : '#ff6b6b';
      try {
        element.animate(
          reducedMotion
            ? [
                { outline: `4px solid ${color}`, outlineOffset: '2px' },
                { outline: `4px solid ${color}`, outlineOffset: '2px' }
              ]
            : [
                { outline: `4px solid ${color}`, outlineOffset: '2px' },
                { outline: '4px solid transparent', outlineOffset: '6px' },
                { outline: `4px solid ${color}`, outlineOffset: '2px' }
              ],
          {
            duration: reducedMotion ? duration : 800,
            iterations: reducedMotion ? 1 : Math.max(1, Math.floor(duration / 800))
          }
        );
      } catch {
        // The injected stylesheet remains the visual fallback when Web Animations is unavailable.
      }
    } catch {
      missedCount += 1;
    }
  };

  input.added.slice(0, 100).forEach((entry) => mark(entry.selector, 'added'));
  input.changed.slice(0, 100).forEach((entry) => mark(entry.selector, 'changed'));
  input.removed.slice(0, 100).forEach((entry) => mark(entry.parentSelector, 'removed'));

  window.setTimeout(() => {
    const currentStyle = document.getElementById(styleId);
    if (currentStyle?.dataset.blancheLatentHighlightToken !== highlightToken) return;
    currentStyle.remove();
    document.querySelectorAll(`[${markerAttribute}]`).forEach((element) => {
      element.removeAttribute(markerAttribute);
    });
  }, duration);

  return { highlightedCount, missedCount };
}
