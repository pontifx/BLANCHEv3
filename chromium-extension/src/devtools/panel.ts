import { mountOperatorConsole } from '../shared/operatorConsole';

const container = document.getElementById('app');
if (!container) {
  throw new Error('Unable to find DevTools panel root container.');
}

mountOperatorConsole({
  container,
  surfaceLabel: 'DevTools',
  async resolveTargetTab() {
    const tabId = chrome.devtools.inspectedWindow.tabId;
    const tab = await chrome.tabs.get(tabId);

    return {
      tabId,
      title: tab.title,
      url: tab.url,
      windowId: tab.windowId,
      index: tab.index
    };
  }
});
