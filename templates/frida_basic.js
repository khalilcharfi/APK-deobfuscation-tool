/**
 * Basic Frida Hook Template
 * Description: Basic SSL pinning and root detection bypass
 * Author: Enhanced APK Deobfuscator
 * Version: 1.0
 */

Java.perform(() => {
    console.log("[+] Basic Frida script loaded");
    
    // Hook common security methods
    try {
        const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        if (RootBeer.isRooted) {
            RootBeer.isRooted.implementation = function() {
                console.log("[+] RootBeer.isRooted() called - returning false");
                return false;
            };
        }
    } catch (e) {
        console.log("[-] RootBeer not found");
    }
    
    // Hook SSL pinning
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        
        SSLContext.init.implementation = function(keyManager, trustManager, secureRandom) {
            console.log("[+] SSLContext.init() called - bypassing certificate validation");
            this.init.call(this, keyManager, null, secureRandom);
        };
    } catch (e) {
        console.log("[-] SSL hook failed:", e);
    }
    
    // Hook debugger detection
    try {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[+] Debug.isDebuggerConnected() called - returning false");
            return false;
        };
    } catch (e) {
        console.log("[-] Debug hook failed:", e);
    }
    
    // Hook package manager for app detection
    try {
        const PackageManager = Java.use("android.content.pm.PackageManager");
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            console.log("[+] PackageManager.getPackageInfo() called for:", packageName);
            return this.getPackageInfo.call(this, packageName, flags);
        };
    } catch (e) {
        console.log("[-] PackageManager hook failed:", e);
    }
}); 