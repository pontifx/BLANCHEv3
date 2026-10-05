import {
  buildInterestAnalysis,
  normalizeInterestWorkbenchSettings,
  type InterestAnalysis,
  type InterestBookmarkInput,
  type InterestContentInput,
  type InterestWorkbenchSettings
} from '../shared/interestWorkbench';

interface BookmarkFolderBinding {
  id: string;
  title: string;
}

export interface InterestAnalysisResult {
  settings: InterestWorkbenchSettings;
  analysis: InterestAnalysis;
}

export async function analyzeInterestModel(
  settings: InterestWorkbenchSettings,
  tabId?: number
): Promise<InterestAnalysisResult> {
  const normalizedSettings = normalizeInterestWorkbenchSettings(settings);
  const folder = await resolveBookmarkFolder(normalizedSettings);
  const bookmarks = folder ? await listFolderBookmarks(folder.id) : [];
  const currentTab = tabId ? await getTabInterestInput(tabId) : undefined;
  const boundSettings = folder
    ? {
        ...normalizedSettings,
        folderId: folder.id,
        folderName: folder.title
      }
    : normalizedSettings;

  return {
    settings: boundSettings,
    analysis: buildInterestAnalysis({
      settings: boundSettings,
      folderId: folder?.id,
      folderFound: Boolean(folder),
      bookmarks,
      currentTab
    })
  };
}

export async function createInterestFolder(
  settings: InterestWorkbenchSettings
): Promise<InterestWorkbenchSettings> {
  const normalizedSettings = normalizeInterestWorkbenchSettings(settings);
  const existingFolder = await resolveBookmarkFolder(normalizedSettings);
  if (existingFolder) {
    return {
      ...normalizedSettings,
      folderId: existingFolder.id,
      folderName: existingFolder.title
    };
  }

  const parentId = await getDefaultBookmarkParentId();
  const createdFolder = await chrome.bookmarks.create({
    parentId,
    title: normalizedSettings.folderName
  });
  if (!createdFolder.id) {
    throw new Error('Chrome did not return a bookmark folder identifier.');
  }

  return {
    ...normalizedSettings,
    folderId: createdFolder.id,
    folderName: createdFolder.title
  };
}

export async function bookmarkTabAsInterestSample(
  settings: InterestWorkbenchSettings,
  tabId?: number
): Promise<InterestAnalysisResult> {
  if (!tabId) {
    throw new Error('An active tab is required before adding an interest bookmark.');
  }

  const currentTab = await getTabInterestInput(tabId);
  const normalizedSettings = await createInterestFolder(settings);
  const existingFolder = await resolveBookmarkFolder(normalizedSettings);
  if (!existingFolder) {
    throw new Error('Unable to resolve the configured bookmark folder.');
  }

  const existingBookmarks = await listFolderBookmarks(existingFolder.id);
  const existingBookmark = existingBookmarks.find((bookmark) => bookmark.url === currentTab.url);
  if (existingBookmark) {
    await chrome.bookmarks.update(existingBookmark.id, {
      title: currentTab.title
    });
  } else {
    await chrome.bookmarks.create({
      parentId: existingFolder.id,
      title: currentTab.title,
      url: currentTab.url
    });
  }

  return analyzeInterestModel(normalizedSettings, tabId);
}

async function resolveBookmarkFolder(
  settings: InterestWorkbenchSettings
): Promise<BookmarkFolderBinding | undefined> {
  if (settings.folderId) {
    try {
      const nodes = await chrome.bookmarks.get(settings.folderId);
      const folder = nodes.find((node) => !node.url && node.id);
      if (folder?.id) {
        return {
          id: folder.id,
          title: folder.title
        };
      }
    } catch {
      // Fall through to title lookup.
    }
  }

  const matches = await chrome.bookmarks.search({
    title: settings.folderName
  });
  const folder = matches.find((node) => !node.url && node.id);
  if (!folder?.id) {
    return undefined;
  }

  return {
    id: folder.id,
    title: folder.title
  };
}

async function listFolderBookmarks(folderId: string): Promise<InterestBookmarkInput[]> {
  const subtree = await chrome.bookmarks.getSubTree(folderId);
  const rootNode = subtree[0];
  if (!rootNode) {
    return [];
  }

  const bookmarks: InterestBookmarkInput[] = [];
  const queue = [...(rootNode.children ?? [])];

  while (queue.length > 0) {
    const node = queue.shift();
    if (!node) {
      continue;
    }

    if (node.url && node.id) {
      bookmarks.push({
        id: node.id,
        title: node.title,
        url: node.url,
        dateAdded: node.dateAdded
      });
    }

    if (node.children?.length) {
      queue.push(...node.children);
    }
  }

  return bookmarks.sort((left, right) => (left.dateAdded ?? 0) - (right.dateAdded ?? 0));
}

async function getTabInterestInput(tabId: number): Promise<InterestContentInput> {
  const tab = await chrome.tabs.get(tabId);
  const url = tab.url?.trim();
  if (!url) {
    throw new Error('The selected tab does not have a bookmarkable URL.');
  }

  const parsedUrl = tryParseUrl(url);
  if (!parsedUrl || (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:')) {
    throw new Error('Only http and https pages can be used as interest samples.');
  }

  return {
    title: tab.title?.trim() || url,
    url
  };
}

async function getDefaultBookmarkParentId(): Promise<string> {
  const tree = await chrome.bookmarks.getTree();
  const root = tree[0];
  const rootChildren = root?.children ?? [];
  const parentNode =
    rootChildren.find((node) => node.id === '2') ??
    rootChildren.find((node) => !node.url && node.id) ??
    root;

  if (!parentNode?.id) {
    throw new Error('Unable to find a bookmark parent folder.');
  }

  return parentNode.id;
}

function tryParseUrl(rawValue: string): URL | undefined {
  try {
    return new URL(rawValue);
  } catch {
    return undefined;
  }
}
