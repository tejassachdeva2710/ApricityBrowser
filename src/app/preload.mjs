import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('apricityAPI', {
  openTab: (url) => ipcRenderer.invoke('ztr:open-tab', url),
  closeTab: (tabId) => ipcRenderer.invoke('ztr:close-tab', tabId),
  navigateTab: (tabId, url) => ipcRenderer.invoke('ztr:navigate-tab', { tabId, url }),
  onTabStatusUpdate: (callback) => {
    ipcRenderer.on('ztr:status-update', (_event, data) => callback(data));
  }
});
