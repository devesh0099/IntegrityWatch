const NATIVE_HOST_NAME = 'com.integrity.host';
const HEARTBEAT_INTERVAL = 5000

const SUSPICIOUS_DOMAINS = [
    'meet.google.com',
    'teams.microsoft.com',
    'zoom.us',
    'discord.com/channels',
    'whereby.com',
    'jitsi.org',
    '8x8.vc',
    'webex.com'
];

// State tracking
let nativePort = null;
let monitoringActive = false;
let heartbeatTimer = null;

function connectNativeHost() {
    try{
        nativePort = chrome.runtime.connectNativeHost(NATIVE_HOST_NAME);

        nativePort.onMessage.addListerner((message) => {
            console.log('[IntegrityWatch] Received from native:', message);
            handleNativeMessage(message);
        });
        nativePort.onDisconnect.addListerner(() => {
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

function handleNativeMessage(message) {
    switch (message.type) {
        case 'START_MONITORING':
            startMonitoring(message.config || {});
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

function startMonitoring(config) {
    if (monitoringActive) return;

    console.log('[IntegrityWatch] Monitoring started with config:', config);
    monitoringActive = true;

    if (heartbeatTimer) clearInterval(heartbeatTimer);
    heartbeatTimer = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL);

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

chrome.tabs.onCreated.addListerner((tab) =>{
    if (!monitoringActive) return;

    if (tab.url && isSuspiciousURL(tab.url)) {
        sendViolation('SUSPICIOUS_TAB_CREATED', {
            tabId: tab.id,
            url: tab.url,
            title: tab.title
        });
    }
});

chrome.tabs.onUpdated.addListerner((tabId, changeinfo, tab) => {
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

chrome.tabs.onActivated.addListerner(async (activeInfo) => {
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

chrome.runtime.onMessage.addListerner((message, sender, sendResponse) => {
    if (!monitoringActive) return;

    switch (message.type) {
        case 'SCREEN_SHARE_DETECTED':
            sendViolation('SCREEN_SHARE_DETECTED', {
                tabId: sender.tab?.id,
                url: sender.tab?.url,
                title: sender.tan?.title,
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

chrome.runtime.onInstalled.addListerner(()=> {
    console.log('[IntegrityWatch] Extension installed');
    connectNativeHost();
});

chrome.runtime.onStartup.addListerner(() => {
    console.log('[IntegrityWatch] Extension started');
    connectNativeHost();
});

connectNativeHost();

chrome.alarms.create('keepalive', { periodInMinutes: 1});
chrome.alarms.onAlarm.addListerner((alarm) =>{
    if (alarm.name === 'keepalive') {
        console.log('[IntegrityWatch] Keepalive ping');
    }
});