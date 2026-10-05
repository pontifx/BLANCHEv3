const panelPath = new URL('./devtools-panel.html', window.location.href).pathname.replace(/^\/+/, '');

chrome.devtools.panels.create('BLANCHE', '', panelPath);
