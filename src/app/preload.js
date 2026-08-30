// preload.js — CommonJS (required for Electron preload context)
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('apricityAPI', {
  // Tab management
  openTab:  (url)   => ipcRenderer.invoke('ztr:open-tab', url),
  closeTab: (tabId) => ipcRenderer.invoke('ztr:close-tab', tabId),
  
  // Navigation & View control
  navigate: (tabId, url) => ipcRenderer.send('ztr:navigate', tabId, url),
  goBack: (tabId) => ipcRenderer.send('ztr:go-back', tabId),
  goForward: (tabId) => ipcRenderer.send('ztr:go-forward', tabId),
  reload: (tabId) => ipcRenderer.send('ztr:reload', tabId),
  switchTab: (tabId) => ipcRenderer.send('ztr:switch-tab', tabId),
  updateBounds: (bounds) => ipcRenderer.send('ztr:update-bounds', bounds),

  // WebContents events
  onTabDidNavigate: (callback) => {
    ipcRenderer.on('tab:did-navigate', (_event, data) => callback(data));
  },

  // Window controls (frameless window)
  windowControls: {
    minimize: () => ipcRenderer.send('window:minimize'),
    maximize: () => ipcRenderer.send('window:maximize'),
    close:    () => ipcRenderer.send('window:close'),
  },

  // Tor
  getTorStatus: () => ipcRenderer.invoke('tor:get-status'),
  onTorStatus: (callback) => {
    ipcRenderer.on('tor:status', (_event, data) => callback(data));
  }
});

