"use strict";
(() => {
  // chromium-extension/src/devtools/index.ts
  var panelPath = new URL("./devtools-panel.html", window.location.href).pathname.replace(/^\/+/, "");
  chrome.devtools.panels.create("BLANCHE", "", panelPath);
})();
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2RldnRvb2xzL2luZGV4LnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJjb25zdCBwYW5lbFBhdGggPSBuZXcgVVJMKCcuL2RldnRvb2xzLXBhbmVsLmh0bWwnLCB3aW5kb3cubG9jYXRpb24uaHJlZikucGF0aG5hbWUucmVwbGFjZSgvXlxcLysvLCAnJyk7XG5cbmNocm9tZS5kZXZ0b29scy5wYW5lbHMuY3JlYXRlKCdCTEFOQ0hFJywgJycsIHBhbmVsUGF0aCk7XG4iXSwKICAibWFwcGluZ3MiOiAiOzs7QUFBQSxNQUFNLFlBQVksSUFBSSxJQUFJLHlCQUF5QixPQUFPLFNBQVMsSUFBSSxFQUFFLFNBQVMsUUFBUSxRQUFRLEVBQUU7QUFFcEcsU0FBTyxTQUFTLE9BQU8sT0FBTyxXQUFXLElBQUksU0FBUzsiLAogICJuYW1lcyI6IFtdCn0K
