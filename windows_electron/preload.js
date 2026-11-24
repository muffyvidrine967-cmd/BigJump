'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cfApi', {
  getState: () => ipcRenderer.invoke('state:get'),
  setState: (key, value) => ipcRenderer.invoke('state:set', key, value),
  setLocale: (value) => ipcRenderer.invoke('locale:set', value),
  probe: (host) => ipcRenderer.invoke('probe', host),
  refreshIps: () => ipcRenderer.invoke('refresh-ips'),
  onStateChanged: (callback) => {
    ipcRenderer.on('state-changed', (_event, state) => callback(state));
  },
});
