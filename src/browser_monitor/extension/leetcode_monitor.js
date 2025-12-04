(function() {
    'use strict';

    console.log('[IntegrityWatch LeetCode] Monitor installed on:', window.location.href);

    let pageLoaded = false;

    window.addEventListener('load', () => {
        pageLoaded = true;
        console.log('[IntegrityWatch LeetCode] Page loaded, monitoring started');
    });

    function sendViolation(type, details) {
        const message = {
            type: 'DOM_MANIPULATION_DETECTED',
            violationType: type,
            timestamp: Date.now(),
            url: window.location.href,
            details: details || {}
        };
        
        try {
            chrome.runtime.sendMessage(message);
            console.log('[IntegrityWatch LeetCode] ✓ Violation sent:', type);
        } catch (error) {
            console.error('[IntegrityWatch LeetCode] Send failed:', error.message);
        }
    }


    function isForeignExtensionElement(element) {
        if (!element) return false;
        
        const attrs = ['src', 'href', 'id', 'class', 'data-extension'];
        for (const attr of attrs) {
            const value = element.getAttribute?.(attr);
            if (value && typeof value === 'string' && value.includes('chrome-extension://')) {
                const extensionId = value.match(/chrome-extension:\/\/([a-z]+)/)?.[1];
                
                if (extensionId === chrome.runtime.id) {
                    return false;
                }
                return true;
            }
        }
        
        const elementId = element.id || '';
        const elementClass = element.className?.toString() || '';
        
        if (elementId.includes('integritywatch') || elementClass.includes('integritywatch')) {
            return false;
        }
        
        const suspiciousPatterns = ['extension', 'chrome-ext', 'plugin', 'addon', 'helper', 'assistant'];
        for (const pattern of suspiciousPatterns) {
            if (elementId.includes(pattern) || elementClass.includes(pattern)) {
                return true;
            }
        }
        
        return false;
    }

    function isForeignExtensionScript(script) {
        if (!script.src) return false;
        
        if (script.src.startsWith('chrome-extension://')) {
            const extensionId = script.src.split('/')[2];
            return extensionId !== chrome.runtime.id;
        }
        
        return false;
    }

    function isSuspiciousOverlay(element) {
        try {
            const style = window.getComputedStyle(element);
            const zIndex = parseInt(style.zIndex);
            const position = style.position;
            
            if ((position === 'fixed' || position === 'absolute') && zIndex > 9999) {
                return true;
            }
        } catch (e) {
        }
        
        return false;
    }

    const observer = new MutationObserver((mutations) => {
        if (!pageLoaded) return;
        
        for (const mutation of mutations) {
            mutation.addedNodes.forEach(node => {
                if (node.nodeType !== Node.ELEMENT_NODE) return;
                
                if (node.tagName === 'SCRIPT' && isForeignExtensionScript(node)) {
                    sendViolation('FOREIGN_EXTENSION_SCRIPT', {
                        detected: true,
                        message: 'External extension script detected on page'
                    });
                }
                
                if (isForeignExtensionElement(node)) {
                    sendViolation('EXTENSION_ELEMENT_INJECTED', {
                        detected: true,
                        message: 'External extension modified page DOM',
                        tagName: node.tagName || 'unknown'
                    });
                }
                
                if (isSuspiciousOverlay(node)) {
                    sendViolation('SUSPICIOUS_OVERLAY', {
                        detected: true,
                        message: 'High z-index overlay detected - possible screen capture',
                        tagName: node.tagName || 'unknown'
                    });
                }
            });
        }
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['src', 'href', 'id', 'class', 'style']
    });

    document.addEventListener('paste', (event) => {
        const pastedText = event.clipboardData.getData('text');
        const target = event.target;
        
        const isCodeEditor = target.closest?.('.monaco-editor') || 
                            target.closest?.('[data-keybinding-context]') ||
                            target.tagName === 'TEXTAREA';
        
        if (isCodeEditor && pastedText.length > 100) {
            sendViolation('LARGE_CODE_PASTE', {
                detected: true,
                message: 'Large code paste detected',
                length: pastedText.length
            });
        }
    }, true);

    document.addEventListener('input', (event) => {
        if (!event.isTrusted) {
            sendViolation('PROGRAMMATIC_INPUT', {
                detected: true,
                message: 'Code was entered programmatically (not by user)'
            });
        }
    }, true);

    console.log('[IntegrityWatch LeetCode] DOM monitoring active');

})();
