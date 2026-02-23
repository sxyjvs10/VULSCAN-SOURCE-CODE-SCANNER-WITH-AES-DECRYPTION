(function() {
    console.log("✅ VULSCAN: Live Exploit Script Loaded");

    // 0. Intercept atob
    const origAtob = window.atob;
    window.atob = function(str) {
        const res = origAtob(str);
        if (res.length > 5) {
            console.log("🔓 atob intercepted:", str.slice(0, 50), "->", res.slice(0, 50));
        }
        return res;
    };

    // Helper: Convert Hex to ASCII
    window.hexToAscii = function(hex) {
        var str = '';
        for (var i = 0; i < hex.length; i += 2) {
            var charCode = parseInt(hex.substr(i, 2), 16);
            if (charCode >= 32 && charCode <= 126) {
                str += String.fromCharCode(charCode);
            } else {
                str += '.';
            }
        }
        return str;
    };

    // 1. Check for specific global variables & Storage
    function checkGlobals() {
        if (typeof aesValu !== 'undefined') console.log("=== FOUND GLOBAL: aesValu ===", aesValu);
        if (typeof juKu !== 'undefined') console.log("=== FOUND GLOBAL: juKu ===", juKu);
        if (typeof aesiv !== 'undefined') console.log("=== FOUND GLOBAL: aesiv ===", aesiv);

        if (!window.storageDumped) {
            console.log("💾 STORAGE DUMP (Cookies):", document.cookie);
            try {
                console.log("💾 STORAGE DUMP (Local):", JSON.stringify(localStorage));
                console.log("💾 STORAGE DUMP (Session):", JSON.stringify(sessionStorage));
            } catch(e) {}
            window.storageDumped = true;
        }
    }

    // 2. Install Interceptor (Precise Strategy Matching User Request)
    const origApply = Function.prototype.apply;

    Function.prototype.apply = function(ctx, args) {
        try {
            // Detect CryptoJS AES.encrypt call pattern
            if (
                args &&
                args.length >= 3 &&
                args[1] &&
                args[2] &&
                args[2].iv &&
                args[2].mode &&
                args[2].padding
            ) {
                const key = args[1];
                const cfg = args[2];
                const msg = args[0];

                console.group("🔥 AES CALL INTERCEPTED");
                
                const kHex = key?.toString?.();
                console.log("🔑 KEY (hex):", kHex);
                
                // Try UTF8 (User requested)
                try {
                    // Try direct wordarray to utf8 conversion if CryptoJS is available
                    if (window.CryptoJS && window.CryptoJS.enc && window.CryptoJS.enc.Utf8) {
                        console.log("🔑 KEY (utf8):", key.toString(window.CryptoJS.enc.Utf8));
                    } else {
                        // Fallback to our hexToAscii helper
                        console.log("🔑 KEY (ascii):", window.hexToAscii(kHex));
                    }
                } catch(e) {}

                console.log("🧩 IV (hex):", cfg.iv?.toString?.());
                console.log("📦 PLAINTEXT:", msg?.toString?.());
                console.groupEnd();
            }
        } catch (e) {}

        return origApply.call(this, ctx, args);
    };

    // Intercept Web Crypto API
    if (window.crypto && window.crypto.subtle) {
        const origImportKey = window.crypto.subtle.importKey;
        window.crypto.subtle.importKey = function(format, keyData, algorithm, extractable, keyUsages) {
            try {
                console.log("🔥 WEB CRYPTO importKey INTERCEPTED");
                if (format === 'raw') {
                    const hex = Array.prototype.map.call(new Uint8Array(keyData), x => ('00' + x.toString(16)).slice(-2)).join('');
                    console.log("🔑 KEY (hex):", hex);
                    console.log("🔑 KEY (ascii):", window.hexToAscii(hex));
                }
            } catch (e) {}
            return origImportKey.apply(this, arguments);
        };
        console.log("✅ VULSCAN: Web Crypto interceptor installed.");
    }

    console.log("✅ VULSCAN: Global AES interceptor installed. Now login / call API.");
    setInterval(checkGlobals, 2000);
})();
