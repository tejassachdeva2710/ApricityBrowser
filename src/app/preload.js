// preload.js — CommonJS (required for Electron preload context)
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('apricityAPI', {
  // Tab management
  openTab:  (url)   => ipcRenderer.invoke('ztr:open-tab', url),
  closeTab: (tabId) => ipcRenderer.invoke('ztr:close-tab', tabId),

  // Window controls (frameless window)
  windowControls: {
    minimize: () => ipcRenderer.send('window:minimize'),
    maximize: () => ipcRenderer.send('window:maximize'),
    close:    () => ipcRenderer.send('window:close'),
  },

  // Pull-based: renderer calls this at startup to get current Tor state
  getTorStatus: () => ipcRenderer.invoke('tor:get-status'),

  // Push-based: main notifies renderer when Tor connects
  onTorStatus: (callback) => {
    ipcRenderer.on('tor:status', (_event, data) => callback(data));
  }
});
