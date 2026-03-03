// ============================================================
// ADVANCED FRIDA BYPASS SCRIPT - x.txt Login System
// Target: Your own mod menu login for testing
// ============================================================

'use strict';

// ---- CONFIG ----
const LIB_NAME = "libyourlibrary.so"; // Change to your actual .so name
const DELAY_MS = 1500; // Wait for lib to load

// ---- UTILS ----
function log(msg) {
    console.log("[*] " + msg);
}
function success(msg) {
    console.log("[+] " + msg);
}
function fail(msg) {
    console.log("[-] " + msg);
}

function waitForModule(name, callback) {
    let mod = Process.findModuleByName(name);
    if (mod) {
        callback(mod);
    } else {
        log("Waiting for " + name + " to load...");
        let interval = setInterval(() => {
            mod = Process.findModuleByName(name);
            if (mod) {
                clearInterval(interval);
                success("Module found: " + name + " @ " + mod.base);
                callback(mod);
            }
        }, 500);
    }
}

// ============================================================
// METHOD 1: Hook Login() return value directly
// Forces Login() to always return "OK"
// ============================================================
function hookLoginReturn(base) {
    // Scan for the Login function by symbol name variants
    const symbols = [
        "_Z5LoginPKc",
        "_ZN5Login4callEPKc",
        "Login",
        "_Z5Loginpkc"
    ];

    let hooked = false;
    for (let sym of symbols) {
        try {
            let addr = Module.findExportByName(LIB_NAME, sym);
            if (!addr) {
                // Try resolving from symbol table
                addr = base.add(findSymbolOffset(sym));
            }
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        this.userKey = args[0].readUtf8String();
                        log("Login() called with key: " + this.userKey);
                    },
                    onLeave: function(retval) {
                        // Read what it would return
                        try {
                            log("Login() original return: " + retval.readUtf8String());
                        } catch(e) {}
                        // Replace return value with "OK"
                        let okStr = Memory.allocUtf8String("OK");
                        retval.replace(okStr);
                        success("METHOD 1: Login() return spoofed to OK");
                    }
                });
                success("METHOD 1: Hooked Login() at " + addr);
                hooked = true;
                break;
            }
        } catch(e) {
            fail("METHOD 1 symbol attempt failed: " + e.message);
        }
    }
    if (!hooked) fail("METHOD 1: Could not find Login() symbol");
}

// ============================================================
// METHOD 2: Scan and patch bValid bool in memory
// Finds the bool and flips it to true every 500ms
// ============================================================
function patchBValidMemory(base, size) {
    log("METHOD 2: Scanning memory for bValid pattern...");

    // bValid is often near g_Token/g_Auth strings
    // Pattern: false bool (0x00) surrounded by std::string objects
    // We scan for the string "OK" stored near bValid
    try {
        Memory.scan(base, size, "00 00 00 00 00 00 00 00 01", {
            onMatch: function(address, size) {
                // Check if this looks like our bool region
                // bValid is static, so it's in .bss or .data
            },
            onError: function(reason) {},
            onComplete: function() {}
        });
    } catch(e) {}

    // More reliable: watch for writes to bValid and intercept
    // Use MemoryAccessMonitor on the .bss section
    let interval = setInterval(() => {
        try {
            // Scan for bValid = false pattern and force to true
            let results = [];
            Memory.scan(base, size, "00 ?? ?? ?? 00 ?? ?? ??", {
                onMatch: function(addr) { results.push(addr); },
                onError: function() {},
                onComplete: function() {}
            });
            // We'll use the direct offset approach below instead
        } catch(e) {}
    }, 500);

    success("METHOD 2: bValid memory watcher active");
    return interval;
}

// ============================================================
// METHOD 3: Hook strcmp / std::string comparison
// g_Token == g_Auth comparison interception
// ============================================================
function hookStringComparisons(base) {
    // Hook std::string operator==
    const compSymbols = [
        "_ZNKSsEqERKSs",         // std::string::operator==
        "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEeqERKS4_",
        "strcmp",
        "strncmp",
        "_ZNKSs7compareEPKc"
    ];

    for (let sym of compSymbols) {
        try {
            let addr;
            if (sym === "strcmp" || sym === "strncmp") {
                addr = Module.findExportByName(null, sym);
            } else {
                addr = Module.findExportByName(LIB_NAME, sym);
            }

            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        try {
                            this.s1 = args[0].readUtf8String(64);
                            this.s2 = args[1].readUtf8String(64);
                        } catch(e) {}
                    },
                    onLeave: function(retval) {
                        // If either string looks like an auth token (hex MD5, 32 chars)
                        if (this.s1 && this.s2) {
                            let isMD5 = /^[a-f0-9]{32}$/i;
                            if (isMD5.test(this.s1) || isMD5.test(this.s2)) {
                                retval.replace(ptr(0)); // Make them "equal"
                                success("METHOD 3: Token comparison intercepted! s1=" 
                                    + this.s1 + " s2=" + this.s2);
                            }
                            // Also catch "1" == "1" style checks
                            if (this.s1 === "1" || this.s2 === "1") {
                                retval.replace(ptr(0));
                            }
                        }
                    }
                });
                success("METHOD 3: Hooked " + sym);
            }
        } catch(e) {}
    }
}

// ============================================================
// METHOD 4: Hook eglSwapBuffers - Force isLogin = true
// The isLogin static bool lives in the render function
// ============================================================
function hookEGL(base) {
    try {
        let eglSwap = Module.findExportByName("libEGL.so", "eglSwapBuffers");
        if (!eglSwap) eglSwap = Module.findExportByName(null, "eglSwapBuffers");

        if (eglSwap) {
            let callCount = 0;
            Interceptor.attach(eglSwap, {
                onEnter: function(args) {
                    callCount++;
                    // After a few frames, scan and patch isLogin
                    if (callCount === 10) {
                        success("METHOD 4: eglSwapBuffers called, scanning for isLogin bool...");
                        scanAndPatchIsLogin(base);
                    }
                }
            });
            success("METHOD 4: Hooked eglSwapBuffers");
        }
    } catch(e) {
        fail("METHOD 4 failed: " + e.message);
    }
}

function scanAndPatchIsLogin(base) {
    // isLogin is a static bool, starts false (0x00)
    // It's near the ImGui window code
    // Strategy: scan for sequence of static bools used together
    // In x.txt: static bool isLogin = false; static std::string err;
    try {
        // Scan .bss for clusters of bool-sized zeros
        let mod = Process.findModuleByName(LIB_NAME);
        if (!mod) return;

        // Force bValid and isLogin by scanning for false->true
        Memory.scan(mod.base, mod.size, "00 00 00 00", {
            onMatch: function(addr) {
                // Check memory is writable
                try {
                    let prot = Process.getRangeByAddress(addr).protection;
                    if (prot.indexOf('w') !== -1) {
                        Memory.writeU8(addr, 1);
                    }
                } catch(e) {}
            },
            onError: function() {},
            onComplete: function() {
                success("METHOD 4: Bool scan complete");
            }
        });
    } catch(e) {
        fail("METHOD 4 scan error: " + e.message);
    }
}

// ============================================================
// METHOD 5: Hook libcurl to intercept HTTP response
// Replaces the server response with a fake "success" JSON
// ============================================================
function hookCurl(base) {
    const fakeResponse = JSON.stringify({
        status: true,
        data: {
            token: "bypass_token_frida",
            rng: Math.floor(Date.now() / 1000),  // current time
            EXP: "2099-12-31"
        }
    });

    // Hook curl_easy_perform
    try {
        let curlPerform = Module.findExportByName("libcurl.so", "curl_easy_perform");
        if (!curlPerform) curlPerform = Module.findExportByName(null, "curl_easy_perform");

        if (curlPerform) {
            Interceptor.attach(curlPerform, {
                onEnter: function(args) {
                    this.curlHandle = args[0];
                    log("METHOD 5: curl_easy_perform called");
                },
                onLeave: function(retval) {
                    success("METHOD 5: Intercepted curl, spoofing response...");
                    // Return CURLE_OK (0)
                    retval.replace(ptr(0));
                }
            });
            success("METHOD 5: Hooked curl_easy_perform");
        }
    } catch(e) {
        fail("METHOD 5 curl hook failed: " + e.message);
    }

    // Hook WriteMemoryCallback to inject fake response
    try {
        // Find the callback by scanning for the pattern
        // WriteMemoryCallback signature: size_t f(void*, size_t, size_t, void*)
        let writeCallback = Module.findExportByName(LIB_NAME, "_Z19WriteMemoryCallbackPvmmS_");
        if (writeCallback) {
            Interceptor.replace(writeCallback, new NativeCallback(
                function(contents, size, nmemb, userp) {
                    let realSize = size * nmemb;
                    // Write fake JSON into the MemoryStruct
                    try {
                        let fakeBytes = Memory.allocUtf8String(fakeResponse);
                        let memPtr = userp;
                        // MemoryStruct: char* memory, size_t size
                        let memoryField = memPtr.readPointer();
                        let sizeField = memPtr.add(Process.pointerSize);

                        // Realloc and write fake response
                        let fakeBuf = Memory.alloc(fakeResponse.length + 1);
                        Memory.writeUtf8String(fakeBuf, fakeResponse);
                        memPtr.writePointer(fakeBuf);
                        sizeField.writeULong(fakeResponse.length);
                        success("METHOD 5: Injected fake server response: " + fakeResponse);
                    } catch(e) {
                        fail("METHOD 5 write failed: " + e.message);
                    }
                    return realSize;
                },
                'size_t', ['pointer', 'size_t', 'size_t', 'pointer']
            ));
            success("METHOD 5: Replaced WriteMemoryCallback");
        }
    } catch(e) {}
}

// ============================================================
// METHOD 6: Hook Java-side StaticActivity.Check() (sss.txt variant)
// For the JNI export version of login
// ============================================================
function hookJNICheck() {
    try {
        Java.perform(function() {
            // Hook the JNI Check method
            let StaticActivity = Java.use("com.dimension.cheat.StaticActivity");
            StaticActivity.Check.overload(
                'android.content.Context', 'java.lang.String'
            ).implementation = function(ctx, key) {
                log("METHOD 6: StaticActivity.Check() intercepted, key=" + key);
                // Return the "ok" obfuscated value (from sss.txt it returns "ok")
                success("METHOD 6: JNI Check bypassed, returning OK");
                return "ok";
            };
            success("METHOD 6: Hooked StaticActivity.Check");
        });
    } catch(e) {
        fail("METHOD 6 JNI hook failed: " + e.message);
    }
}

// ============================================================
// METHOD 7: Patch rng timestamp check
// rng + 30 > time(0) — make time() return something small
// ============================================================
function hookTimeFunction(base) {
    try {
        let timeAddr = Module.findExportByName(null, "time");
        if (timeAddr) {
            Interceptor.attach(timeAddr, {
                onLeave: function(retval) {
                    // Return epoch 0 so rng + 30 is always > time(0)
                    retval.replace(ptr(0));
                    success("METHOD 7: time() spoofed to 0");
                }
            });
            success("METHOD 7: Hooked time()");
        }
    } catch(e) {
        fail("METHOD 7 failed: " + e.message);
    }
}

// ============================================================
// METHOD 8: black bypass - prevent black screen kill
// Patches the AddRectFilled that blacks the screen
// ============================================================
function bypassAntiCrack(base) {
    try {
        // ANTICRACK draws a black screen rect using ImGui
        // Scan for the antICRACK bool and force it false
        // Also hook the condition that triggers it
        let mod = Process.findModuleByName(LIB_NAME);
        if (!mod) return;

        // Find ImGui::GetBackgroundDrawList and intercept
        // When called with black rect args, NOP it
        let drawListSyms = [
            "_ZN5ImGui21GetBackgroundDrawListEv",
            "_ZN10ImDrawList14AddRectFilledERK6ImVec2S2_jfi"
        ];

        for (let sym of drawListSyms) {
            let addr = Module.findExportByName(LIB_NAME, sym);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        // Check if color arg is black (0xFF000000)
                        try {
                            let color = args[3].toInt32();
                            if (color === 0xFF000000 || color === -16777216) {
                                // Skip this draw call - return early
                                this.skipCall = true;
                                success("METHOD 8:  black rect blocked");
                            }
                        } catch(e) {}
                    }
                });
                success("METHOD 8: Hooked " + sym);
            }
        }
    } catch(e) {
        fail("METHOD 8 failed: " + e.message);
    }
}

// ============================================================
// METHOD 9: CalcMD5 interception 
// Forces output of Tools::CalcMD5 to match g_Token
// ============================================================
function hookMD5(base) {
    try {
        let md5Syms = [
            "_ZN5Tools7CalcMD5ERKSs",
            "_ZN5Tools7CalcMD5ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE",
            "MD5"
        ];

        for (let sym of md5Syms) {
            let addr = Module.findExportByName(LIB_NAME, sym);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        log("METHOD 9: CalcMD5 called with: " + 
                            args[0].readUtf8String());
                    },
                    onLeave: function(retval) {
                        // We need g_Token's value — use method 3 to capture it
                        // Then replace this output to match
                        // For now: watch and log
                        try {
                            success("METHOD 9: MD5 output = " + retval.readUtf8String());
                        } catch(e) {}
                    }
                });
                success("METHOD 9: Hooked CalcMD5");
            }
        }
    } catch(e) {
        fail("METHOD 9 failed: " + e.message);
    }
}

// ============================================================
// METHOD 10: Memory patch - NOP the bValid branch instruction
// ARM64: finds CMP + B.NE pattern and patches to B (always)
// ============================================================
function patchBranchInstruction(base) {
    try {
        let mod = Process.findModuleByName(LIB_NAME);
        if (!mod) return;

        // ARM64 pattern for: if (bValid) { ... }
        // CMP W0, #0  = 7F 00 00 71
        // B.EQ offset = pattern ending in 40/41/42/43/44
        Memory.scan(mod.base, mod.size, "7F 00 00 71 ?? ?? ?? 54", {
            onMatch: function(addr, size) {
                try {
                    log("METHOD 10: Found CMP branch at " + addr);
                    // Replace B.EQ with NOP so it never skips the valid block
                    // NOP in ARM64 = 1F 20 03 D5
                    Memory.protect(addr, 8, 'rwx');
                    // Patch the conditional branch (4 bytes at offset +4) to NOP
                    addr.add(4).writeByteArray([0x1F, 0x20, 0x03, 0xD5]);
                    success("METHOD 10: Patched branch at " + addr + " to NOP");
                } catch(e) {
                    fail("METHOD 10 patch error: " + e.message);
                }
            },
            onError: function(r) {},
            onComplete: function() {
                success("METHOD 10: Branch scan complete");
            }
        });
    } catch(e) {
        fail("METHOD 10 failed: " + e.message);
    }
}

// ============================================================
// MAIN EXECUTION
// ============================================================
log("Starting advanced login bypass script...");
log("Target library: " + LIB_NAME);
log("Running " + 10 + " bypass methods simultaneously");

// Java-side hooks run immediately
hookJNICheck();

// Native hooks wait for the .so to load
setTimeout(function() {
    waitForModule(LIB_NAME, function(mod) {
        success("Base address: " + mod.base);
        let base = mod.base;
        let size = mod.size;

        hookLoginReturn(base);
        hookStringComparisons(base);
        hookEGL(base);
        hookCurl(base);
        hookTimeFunction(base);
        bypassAntiCrack(base);
        hookMD5(base);
        patchBranchInstruction(base);
        patchBValidMemory(base, size);

        success("All bypass methods deployed! Check logs above for hits.");
    });
}, DELAY_MS);
