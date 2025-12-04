(function() {
    'use strict';

    console.log('[IntegrityWatch LeetCode] Monitor installed on:', window.location.href);

    let originalElements = new Set();
    let pageLoaded = false;

    window.addEventListener('load', () => {
    pageLoaded = true;
    captureOriginalState();
    console.log('[IntegrityWatch LeetCode] Page loaded, monitoring started');
    });

    function captureOriginalState() {
    const allElements = document.querySelectorAll('*');
    allElements.forEach(el => {
        originalElements.add(el);
    });
    console.log(`[IntegrityWatch LeetCode] Captured ${originalElements.size} original elements`);
    }

    function isExtensionElement(element) {
    if (!element) return false;
    
    const checkAttributes = ['src', 'href', 'data-extension', 'id', 'class'];
    for (const attr of checkAttributes) {
        const value = element.getAttribute?.(attr);
        if (value && value.includes('chrome-extension://')) {
        const match = value.match(/chrome-extension:\/\/([a-z]+)/);
        if (match && match[1] === chrome.runtime.id) {
            return false;
        }
        return true; 
        }
    }
    
    const suspiciousPatterns = [
        'extension',
        'chrome-extension',
        'plugin',
        'injected',
        'helper',
        'assistant'
    ];
    
    const elementId = element.id?.toLowerCase() || '';
    const elementClass = element.className?.toString()?.toLowerCase() || '';
    
    if (elementId.includes('integritywatch') || elementClass.includes('integritywatch')) {
        return false;
    }
    
    for (const pattern of suspiciousPatterns) {
        if (elementId.includes(pattern) || elementClass.includes(pattern)) {
        return true;
        }
    }
    
    const zIndex = parseInt(window.getComputedStyle(element).zIndex);
    if (zIndex > 999999) {
        return true;
    }
    
    return false;
    }


    function isForeignExtensionScript(script) {
    if (!script.src) return false;
    
    if (script.src.startsWith('chrome-extension://')) {
        const extensionId = script.src.split('/')[2];
        
        if (extensionId === chrome.runtime.id) {
        return false;
        }
        
        return true;
    }
    
    return false;
    }


    function sendViolation(type, details) {
        chrome.runtime.sendMessage({
        type: 'DOM_MANIPULATION_DETECTED',
        violationType: type,
        timestamp: Date.now(),
        url: window.location.href,
        details: details
        }, (response) => {
        if (chrome.runtime.lastError) {
            console.error('[IntegrityWatch LeetCode] Failed to send violation:', chrome.runtime.lastError);
        }
        });
    }

    const observer = new MutationObserver((mutations) => {
        if (!pageLoaded) return;
        
        for (const mutation of mutations) {
        mutation.addedNodes.forEach(node => {
            if (node.nodeType !== Node.ELEMENT_NODE) return;
            
            if (node.tagName === 'SCRIPT' && isForeignExtensionScript(node)) {
            console.warn('[IntegrityWatch LeetCode] Foreign extension script detected:', node.src);
            sendViolation('FOREIGN_EXTENSION_SCRIPT', {
                scriptSrc: node.src,
                extensionId: node.src.split('/')[2]
            });
            }
            
            if (isExtensionElement(node)) {
            console.warn('[IntegrityWatch LeetCode] Extension element injected:', node);
            sendViolation('EXTENSION_ELEMENT_INJECTED', {
                tagName: node.tagName,
                id: node.id,
                className: node.className,
                innerHTML: node.innerHTML?.substring(0, 200) 
            });
            }
            
            const style = window.getComputedStyle(node);
            if (style.position === 'fixed' && parseInt(style.zIndex) > 9999) {
            console.warn('[IntegrityWatch LeetCode] High z-index overlay detected:', node);
            sendViolation('SUSPICIOUS_OVERLAY', {
                tagName: node.tagName,
                zIndex: style.zIndex,
                position: style.position,
                content: node.textContent?.substring(0, 100)
            });
            }
        });
        
        if (mutation.type === 'characterData' || mutation.type === 'childList') {
            const target = mutation.target;
            
            const isCodeEditor = target.closest?.('.monaco-editor') || 
                                target.closest?.('[data-keybinding-context]');
            
            if (isCodeEditor) {
            console.log('[IntegrityWatch LeetCode] Code editor modified');    
            }
        }
        }
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true,
        characterData: true,
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
        console.warn('[IntegrityWatch LeetCode] Large paste detected:', pastedText.length, 'characters');
        
        sendViolation('LARGE_CODE_PASTE', {
            length: pastedText.length,
            contentPreview: pastedText.substring(0, 100),
            target: target.tagName
        });
        }
    }, true);

    document.addEventListener('input', (event) => {
        if (!event.isTrusted) {
        console.warn('[IntegrityWatch LeetCode] Untrusted input event detected (programmatic)');
        
        sendViolation('PROGRAMMATIC_INPUT', {
            target: event.target.tagName,
            value: event.target.value?.substring(0, 100)
        });
        }
    }, true);

    console.log('[IntegrityWatch LeetCode] DOM monitoring active');

    })();
