import { mountOperatorConsole } from '../shared/operatorConsole';

const container = document.getElementById('app');
if (!container) {
  throw new Error('Unable to find side panel root container.');
}

mountOperatorConsole({
  container,
  surfaceLabel: 'Side Panel',
  async resolveTargetTab() {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    if (!tab?.id) {
      return undefined;
    }

    return {
      tabId: tab.id,
      title: tab.title,
      url: tab.url,
      windowId: tab.windowId,
      index: tab.index
    };
  }
});
