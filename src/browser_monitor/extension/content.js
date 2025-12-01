(function() {
    'use strict';

    console.log('[IntegrityWatch Content] Injected into:', window.location.href);

    if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
        const originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);

        navigator.mediaDevices.getDisplayMedia = function(constraints) {
            console.warn('[IntegrityWatch] SCREEN SHARING DETECTED');
            console.warn('[IntegrityWatch] Constraints:', constraints);

            chrome.runtime.sendMessage({
                type: 'SCREEN_SHARE_DETECTED',
                timestamp: Date.now(),
                constraints: constraints,
                url: window.location.href,
                title: document.title
            });

            const mediaStreamPromise = originalGetDisplayMedia(constraints);

            mediaStreamPromise.then(stream => {
                console.warn('[IntegrityWatch] Screen Sharing Stream obtained');

                stream.getVideoTracks().forEach(track => {
                    track.addEventListener('ended', () => {
                        console.log('[IntegrityWatch] Screen Sharing Stopped');
                        chrome.runtime.sendMessage({
                            type: 'SCREEN_SHARE_STOPPED',
                            timestamp: Date.now(),
                            url: window.location.href
                        });
                    });
                });
            }).catch(err => {
                console.log('[IntegrityWatch] Screen sharing denied by user:', err);
            });
            return mediaStreamPromise;
        }
    console.log('[IntegrityWatch Content] getDisplayMedia() override installed');
    }

    //TODO: Camera/Mic access + tab switching



})