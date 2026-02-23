(function() {
    console.log("✅ VULSCAN: Live Exploit Script Loaded");

    // Log all script tags
    document.querySelectorAll('script').forEach(s => {
        if (s.src) console.log("📜 SCRIPT SRC:", s.src);
    });

    // 0. Intercept Fetch to debug
    const origFetch = window.fetch;
    window.fetch = function() {
        const url = arguments[0];
        // console.log("🌐 FETCH CALL:", url);
        return origFetch.apply(this, arguments).then(response => {
            const clone = response.clone();
            clone.text().then(body => {
                if (body.includes('"key"') || body.includes('"d"')) {
                    console.log("📦 VULSCAN: Interesting Body Detected in", url);
                    console.log("📦 BODY:", body.slice(0, 200));
                    
                    // Specific strategy for MISReport XOR
                    try {
                        const data = JSON.parse(body);
                        const encKey = (data.d && data.d.key) || data.key;
                        if (encKey) {
                            const xorKey = "XOR2024";
                            const decoded = atob(encKey);
                            let decrypted = "";
                            for(let i=0; i<decoded.length; i++) {
                                decrypted += String.fromCharCode(decoded.charCodeAt(i) ^ xorKey.charCodeAt(i % xorKey.length));
                            }
                            console.log("🔥 VULSCAN: Auto-Decrypted XOR Key:", decrypted);
                        }
                    } catch(e) {}
                }
            });
            return response;
        });
    };

    // Hook atob
    const origAtob = window.atob;
    window.atob = function(str) {
        const res = origAtob(str);
        if (res.length > 5) {
            console.log("🔓 atob intercepted:", str.slice(0, 50), "->", res.slice(0, 50));
        }
        return res;
    };
    window.wordArrayToString = function(wordArray) {
        if (!wordArray) return "";
        var words = wordArray.words;
        var sigBytes = wordArray.sigBytes;
        var str = '';
        for (var i = 0; i < sigBytes; i++) {
            var byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            str += String.fromCharCode(byte);
        }
        return str;
    };

    // Helper: Convert WordArray to Hex
    window.wordArrayToHex = function(wordArray) {
        if (!wordArray) return "";
        var words = wordArray.words;
        var sigBytes = wordArray.sigBytes;
        var hex = '';
        for (var i = 0; i < sigBytes; i++) {
            var byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            hex += ('0' + byte.toString(16)).slice(-2);
        }
        return hex;
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

    // 1. Check for specific global variables mentioned by user (aesValu, juKu, aesiv, Tkl)
    function checkGlobals() {
        // console.log("⏱️ VULSCAN: Global Check Running...");
        if (typeof aesValu !== 'undefined') {
            var hex = window.wordArrayToHex(aesValu);
            console.log("=== FOUND GLOBAL: aesValu ===");
            console.log("🔑 KEY (hex):", hex);
            console.log("🔑 KEY (ascii):", window.hexToAscii(hex));
        }
        if (typeof juKu !== 'undefined') {
            var hex = window.wordArrayToHex(juKu);
            console.log("=== FOUND GLOBAL: juKu ===");
            console.log("🔑 KEY (hex):", hex);
            console.log("🔑 KEY (ascii):", window.hexToAscii(hex));
        }
        if (typeof aesiv !== 'undefined') {
            var hex = window.wordArrayToHex(aesiv);
            console.log("=== FOUND GLOBAL: aesiv ===");
            console.log("🧩 IV (hex):", hex);
            console.log("🧩 IV (ascii):", window.hexToAscii(hex));
        }
        if (typeof iv !== 'undefined') {
            var hex = window.wordArrayToHex(iv);
            console.log("=== FOUND GLOBAL: iv ===");
            console.log("🧩 IV (hex):", hex);
            console.log("🧩 IV (ascii):", window.hexToAscii(hex));
        }
        if (typeof Tkl !== 'undefined') {
            console.log("=== FOUND GLOBAL: Tkl ===");
            try {
                if (typeof Tkl === 'object' && Tkl.sigBytes) {
                    var hex = window.wordArrayToHex(Tkl);
                    console.log("🔑 KEY (hex):", hex);
                    console.log("🔑 KEY (ascii):", window.hexToAscii(hex));
                } else {
                    console.log("Value:", Tkl.toString());
                }
            } catch(e) {
                console.log("Value (Raw):", Tkl);
            }
        }
    }

    // 2. Install Interceptor
    const origApply = Function.prototype.apply;
    
    // Helper: Buffer to Hex
    function bufToHex(buffer) {
        return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
    }

    // Intercept CryptoJS
    Function.prototype.apply = function(ctx, args) {
        try {
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

                console.log("🔥 AES CALL INTERCEPTED (CryptoJS)");
                try { 
                    var kHex = key.toString();
                    console.log("🔑 KEY (hex):", kHex);
                    console.log("🔑 KEY (ascii):", window.hexToAscii(kHex));
                } catch(e) {}
                try { 
                    var iHex = cfg.iv.toString();
                    console.log("🧩 IV (hex):", iHex);
                    console.log("🧩 IV (ascii):", window.hexToAscii(iHex));
                } catch(e) {}
                try { console.log("📦 PLAINTEXT:", msg.toString()); } catch(e) {}
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
                console.log("🛠 Format:", format);
                console.log("🛠 Algorithm:", JSON.stringify(algorithm));
                
                if (format === 'raw') {
                    const hex = bufToHex(keyData);
                    console.log("🔑 KEY (hex):", hex);
                    console.log("🔑 KEY (ascii):", window.hexToAscii(hex));
                }
            } catch (e) {}
            return origImportKey.apply(this, arguments);
        };
        console.log("✅ VULSCAN: Web Crypto interceptor installed.");
    }

    console.log("✅ VULSCAN: Global AES interceptor installed.");
    
    // Check globals periodically
    setInterval(checkGlobals, 2000);
})();
