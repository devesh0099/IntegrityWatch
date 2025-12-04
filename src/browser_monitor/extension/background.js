const NATIVE_HOST_NAME = 'com.integritywatch.host';
const HEARTBEAT_INTERVAL = 5000

let TARGET_WEBSITE = 'leetcode.com';
let extensionScanDone = false;

let SUSPICIOUS_DOMAINS = [
    'meet.google.com',
    'teams.microsoft.com',
    'zoom.us',
    'discord.com',
    'whereby.com',
    'jitsi.org',
    '8x8.vc',
    'webex.com'
];

const HIGH_RISK_PERMISSIONS = [
  'desktopCapture',      
  'nativeMessaging',     
  'debugger',            
  'proxy',               
  'webRequest'           
];

// State tracking
let nativePort = null;
let monitoringActive = false;
let heartbeatTimer = null;

function connectNativeHost() {
    try{
        nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);

        nativePort.onMessage.addListener((message) => {
            console.log('[IntegrityWatch] Received from native:', message);
            handleNativeMessage(message);
        });
        nativePort.onDisconnect.addListener(() => {
            console.error('[IntegrityWatch] Native host disconnected:',
                chrome.runtime.lastError
            );
            nativePort = null;
            setTimeout(connectNativeHost, 5000);
        });

        console.log('[IntegrityWatch] Connected to native host');
        sendToNative({type: 'EXTENSION_READY', timestamp: Date.now()});
    } catch (error) {
        console.error('[IntegrityWatch] Failed to connect to native host:', error);
        nativePort = null;
    }
}

function sendToNative(message) {
    if (nativePort) {
        try {
            nativePort.postMessage(message);
        } catch (error) {
            console.error('[IntegrityWatch] Failed to send message:', error);
        }
    } else {
        console.warn('[IntegrityWatch] Native port not connected, message dropped:', message);
    }
}

function startMonitoring(config) {
    if (monitoringActive) return;

    console.log('[IntegrityWatch] Monitoring started with config:', config);
    monitoringActive = true;

    if (heartbeatTimer) clearInterval(heartbeatTimer);
    heartbeatTimer = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL);
    checkAlreadyOpenTabs();
    sendHeartbeat();
}

function stopMonitoring() {
    console.log('[IntegrityWatch] Monitoring stopped');
    monitoringActive = false;

    if (heartbeatTimer) {
        clearInterval(heartbeatTimer);
        heartbeatTimer = null;
    }
}

async function sendHeartbeat() {
    if (!monitoringActive) return;

    try {
        const tabs = await chrome.tabs.query({});
        const suspiciousTabs = tabs.filter(tab => isSuspiciousURL(tab.url));

        sendToNative({
            type: 'HEARTBEAT',
            timestamp: Date.now(),
            data: {
                totalTabs: tabs.length,
                suspiciousTabCount: suspiciousTabs.length,
                suspiciousTabs: suspiciousTabs.map(tab => ({
                    id: tab.id,
                    url: tab.url,
                    title: tab.title,
                    active: tab.active
                }))
            }
        });
    } catch (error) {
        console.error('[IntegrityWatch] Heartbeat error:', error);
    }
}

async function checkAlreadyOpenTabs() {
  console.log('[IntegrityWatch] Checking already open tabs...');
  
  try {
    const tabs = await chrome.tabs.query({});
    console.log(`[IntegrityWatch] Found ${tabs.length} open tabs`);
    
    const suspiciousPatterns = SUSPICIOUS_DOMAINS
    
    let suspiciousCount = 0;
    
    for (const tab of tabs) {
      if (!tab.url) continue;
      
      const isSuspicious = suspiciousPatterns.some(pattern => 
        tab.url.includes(pattern)
      );
      
      if (isSuspicious) {
        suspiciousCount++;
        console.warn(`[IntegrityWatch] Found already-open suspicious tab: ${tab.url}`);
        
        sendViolation('SUSPICIOUS_TAB_ALREADY_OPEN', {
          tabId: tab.id,
          url: tab.url,
          title: tab.title,
          detectedAt: 'extension_startup'
        });
      }
    }
    
    if (suspiciousCount > 0) {
      console.warn(`[IntegrityWatch] Found ${suspiciousCount} suspicious tabs already open`);
    } else {
      console.log('[IntegrityWatch] No suspicious tabs found at startup');
    }
    
  } catch (error) {
    console.error('[IntegrityWatch] Error checking already open tabs:', error);
  }
}


function isSuspiciousURL(url) {
    if (!url) return false;

    try {
        const urlObj = new URL(url);
        return SUSPICIOUS_DOMAINS.some(domain => 
            urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain)
        );
    } catch {
        return false;
    }
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith('http')) return;
  
  console.log('[IntegrityWatch] Injecting override into:', details.url);
  
  chrome.scripting.executeScript({
    target: { tabId: details.tabId },
    world: 'MAIN',
    injectImmediately: true,
    func: function() {
      console.log('[IntegrityWatch Override] Installing...');
      
      if (!navigator.mediaDevices?.getDisplayMedia) {
        console.warn('[IntegrityWatch Override] API not available');
        return;
      }
      
      const original = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);
      
      navigator.mediaDevices.getDisplayMedia = function(constraints) {
        
        const eventData = {
          timestamp: Date.now(),
          url: window.location.href,
          title: document.title,
          constraints: constraints ? JSON.parse(JSON.stringify(constraints)) : null
        };
        
        console.log('[IntegrityWatch Override] Event data:', eventData);
        
        window.dispatchEvent(new CustomEvent('integritywatch-screenshare-start', {
          detail: eventData
        }));
        
        const promise = original(constraints);
        
        promise.then(stream => {
          console.log('[IntegrityWatch Override] Monitoring stream...');
          stream.getVideoTracks().forEach(track => {
            track.addEventListener('ended', () => {
              console.log('[IntegrityWatch Override] Stream ended');
              window.dispatchEvent(new CustomEvent('integritywatch-screenshare-stop', {
                detail: {
                  timestamp: Date.now(),
                  url: window.location.href
                }
              }));
            });
          });
        }).catch(err => {
          console.log('[IntegrityWatch Override] Cancelled:', err.name);
        });
        
        return promise;
      };
      
      console.log('[IntegrityWatch Override] Installed successfully');
    }
  }).catch(err => {
    console.error('[IntegrityWatch] Injection failed:', err);
  });
}, { url: [{ schemes: ['http', 'https'] }] });

chrome.tabs.onCreated.addListener((tab) =>{
    if (!monitoringActive) return;

    if (tab.url && isSuspiciousURL(tab.url)) {
        sendViolation('SUSPICIOUS_TAB_CREATED', {
            tabId: tab.id,
            url: tab.url,
            title: tab.title
        });
    }
});

chrome.tabs.onUpdated.addListener((tabId, changeinfo, tab) => {
    if (!monitoringActive) return;

    if (changeinfo.url && isSuspiciousURL(changeinfo.url)) {
        sendViolation('SUSPICIOUS_TAB_NAVIGATION', {
            tabId: tabId,
            url: changeinfo.url,
            title: tab.title,
            previousUrl: changeinfo.url !== tab.url ? tab.url : null
        });
    }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
    if (!monitoringActive) return;

    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (isSuspiciousURL(tab.url)) {
            sendViolation('SUSPICIOUS_TAB_ACTIVATED', {
                tabId: tab.id,
                url: tab.url,
                title: tab.title
            });
        }
    }  catch (error) {
        console.error('[IntegrityWatch] Error checking activated tab:', error);
    }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!monitoringActive) return;

    switch (message.type) {
        case 'SCREEN_SHARE_DETECTED':
            sendViolation('SCREEN_SHARE_DETECTED', {
                tabId: sender.tab?.id,
                url: sender.tab?.url,
                title: sender.tab?.title,
                constraints: message.constraints,
                timestamp: message.timestamp
            });
            break;

        case 'SCREEN_SHARE_STOPPED':
            sendToNative({
                type: 'SCREEN_SHARE_STOPPED',
                timestamp: Date.now(),
                data: {
                    tabId: sender.tab?.id,
                    url: sender.tab?.url
                }
            });
            break;

        case 'DOM_MANIPULATION_DETECTED':
            sendViolation(message.violationType, {
                tabId: sender.tab?.id,
                url: message.url,
                timestamp: message.timestamp,
                details: message.details
            });
            break;
    }
});

function sendViolation(violationType, details) {
    const violation = {
        type: 'VIOLATION',
        timestamp: Date.now(),
        violationType: violationType,
        details: details
    };

    console.warn('[IntegrityWatch] VIOLATION:', violation);
    sendToNative(violation);
}

chrome.runtime.onInstalled.addListener(()=> {
    console.log('[IntegrityWatch] Extension installed');
    connectNativeHost();
});

chrome.runtime.onStartup.addListener(() => {
    console.log('[IntegrityWatch] Extension started');
    connectNativeHost();
});

connectNativeHost();

chrome.alarms.create('keepalive', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'keepalive') {
        console.log('[IntegrityWatch] Keepalive ping');
    }
});

function canAccessTargetWebsite(extension) {
  const hostPermissions = extension.hostPermissions || [];
  
  for (const pattern of hostPermissions) {
    if (pattern === '<all_urls>') {
      return true;
    }
    
    if (pattern.includes(TARGET_WEBSITE)) {
      return true;
    }
  }
  
  return false;
}

function hasHighRiskPermissions(extension) {
  const permissions = extension.permissions || [];
  const riskyPerms = permissions.filter(perm => 
    HIGH_RISK_PERMISSIONS.includes(perm)
  );
  return riskyPerms;
}

async function scanInstalledExtensions() {
  if (extensionScanDone) return;
  
  try {
    const extensions = await chrome.management.getAll();
    console.log(`[IntegrityWatch] Scanning ${extensions.length} extensions for ${TARGET_WEBSITE}`);
    
    for (const ext of extensions) {
      if (ext.id === chrome.runtime.id) continue;
      
      if (!ext.enabled) continue;
      
      const canAccess = canAccessTargetWebsite(ext);
      
      if (!canAccess) {
        continue;
      }
      
      console.log(`[IntegrityWatch] Extension "${ext.name}" can access ${TARGET_WEBSITE}`);
      
      const riskyPerms = hasHighRiskPermissions(ext);
      
      if (riskyPerms.length > 0) {
        console.warn(`[IntegrityWatch] SUSPICIOUS EXTENSION: ${ext.name}`);
        console.warn(`[IntegrityWatch] Risky permissions: ${riskyPerms.join(', ')}`);
        
        sendToNative({
          type: 'VIOLATION',
          violationType: 'MALICIOUS_EXTENSION_DETECTED',
          timestamp: Date.now(),
          details: {
            extensionId: ext.id,
            extensionName: ext.name,
            permissions: riskyPerms,
            hostPermissions: ext.hostPermissions,
            canAccessTargetSite: true
          }
        });
      }
    }
    
    extensionScanDone = true;
    console.log('[IntegrityWatch] Extension scan complete');
    
  } catch (error) {
    console.error('[IntegrityWatch] Extension scan failed:', error);
  }
}

function handleNativeMessage(message) {
  switch (message.type) {
    case 'START_MONITORING':
      if (message.config && message.config.targetWebsite) {
        TARGET_WEBSITE = message.config.targetWebsite.replace('*', '').replace('*.', '');
        console.log(`[IntegrityWatch] Target website: ${TARGET_WEBSITE}`);
      }
      if (message.config && message.config.suspiciousDomains) {
        SUSPICIOUS_DOMAINS = message.config.suspiciousDomains
      }
      
      startMonitoring(message.config || {});
      
      scanInstalledExtensions();
      break;
      
    case 'STOP_MONITORING':
      stopMonitoring();
      break;
      
    case 'PING':
      sendToNative({type: 'PONG', timestamp: Date.now()});
      break;
      
    default:
      console.warn('[IntegrityWatch] Unknown message type:', message.type);
  }
}