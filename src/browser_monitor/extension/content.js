(function() {
  'use strict';
  
  console.log('[IntegrityWatch Content] Listener installed on:', window.location.href);
  
  window.addEventListener('integritywatch-screenshare-start', (event) => {
    
    if (!event.detail) {
      console.error('[IntegrityWatch Content] event.detail is null! This means data serialization failed.');
      
      chrome.runtime.sendMessage({
        type: 'SCREEN_SHARE_DETECTED',
        timestamp: Date.now(),
        url: window.location.href,
        title: document.title,
        constraints: null,
        error: 'event.detail_was_null'
      });
      
      console.log('[IntegrityWatch Content] Fallback violation sent');
      return;
    }

    chrome.runtime.sendMessage({
      type: 'SCREEN_SHARE_DETECTED',
      timestamp: event.detail.timestamp,
      constraints: event.detail.constraints,
      url: event.detail.url,
      title: event.detail.title
    });
    
    console.log('[IntegrityWatch Content] Violation sent to background');
  });
  
  window.addEventListener('integritywatch-screenshare-stop', (event) => {
    console.log('[IntegrityWatch Content] Screen share stopped');
    
    if (!event.detail) {
      console.warn('[IntegrityWatch Content] Stop event has null detail');
      chrome.runtime.sendMessage({
        type: 'SCREEN_SHARE_STOPPED',
        timestamp: Date.now(),
        url: window.location.href
      });
      return;
    }
    
    chrome.runtime.sendMessage({
      type: 'SCREEN_SHARE_STOPPED',
      timestamp: event.detail.timestamp,
      url: event.detail.url
    });
  });
  
  console.log('[IntegrityWatch Content] Ready');
  
})();
