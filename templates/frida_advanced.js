/**
 * Advanced Frida Hook Template
 * Description: Comprehensive network and file monitoring
 * Author: Enhanced APK Deobfuscator
 * Version: 1.0
 */

Java.perform(() => {
    console.log("[+] Advanced Frida script loaded");
    
    // Hook network requests
    try {
        const OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newCall.implementation = function(request) {
            console.log("[+] HTTP Request:", request.url().toString());
            console.log("[+] Method:", request.method());
            console.log("[+] Headers:", request.headers().toString());
            return this.newCall.call(this, request);
        };
    } catch (e) {
        console.log("[-] OkHttp hook failed");
    }
    
    // Hook file operations
    try {
        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
            console.log("[+] File opened:", path);
            return this.$init.call(this, path);
        };
        
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
            console.log("[+] File created/written:", path);
            return this.$init.call(this, path);
        };
    } catch (e) {
        console.log("[-] File hook failed");
    }
    
    // Hook encryption methods
    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload('[B').implementation = function(input) {
            console.log("[+] Encryption/Decryption called");
            console.log("[+] Input length:", input.length);
            console.log("[+] Algorithm:", this.getAlgorithm());
            return this.doFinal.call(this, input);
        };
    } catch (e) {
        console.log("[-] Crypto hook failed");
    }
    
    // Hook system calls
    try {
        const Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('java.lang.String').implementation = function(command) {
            console.log("[+] Runtime.exec() called:", command);
            return this.exec.call(this, command);
        };
        
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function(commandArray) {
            console.log("[+] Runtime.exec() called:", commandArray.join(' '));
            return this.exec.call(this, commandArray);
        };
    } catch (e) {
        console.log("[-] Runtime hook failed");
    }
    
    // Hook database operations
    try {
        const SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, selectionArgs) {
            console.log("[+] SQL Query:", sql);
            if (selectionArgs) {
                console.log("[+] SQL Args:", selectionArgs.join(', '));
            }
            return this.rawQuery.call(this, sql, selectionArgs);
        };
    } catch (e) {
        console.log("[-] SQLite hook failed");
    }
    
    // Hook shared preferences
    try {
        const SharedPreferences = Java.use("android.content.SharedPreferences");
        SharedPreferences.getString.implementation = function(key, defValue) {
            const result = this.getString.call(this, key, defValue);
            console.log("[+] SharedPreferences.getString:", key, "=", result);
            return result;
        };
        
        SharedPreferences.putString.implementation = function(key, value) {
            console.log("[+] SharedPreferences.putString:", key, "=", value);
            return this.putString.call(this, key, value);
        };
    } catch (e) {
        console.log("[-] SharedPreferences hook failed");
    }
    
    // Hook WebView
    try {
        const WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("[+] WebView.loadUrl:", url);
            return this.loadUrl.call(this, url);
        };
        
        WebView.evaluateJavascript.implementation = function(script, resultCallback) {
            console.log("[+] WebView.evaluateJavascript:", script);
            return this.evaluateJavascript.call(this, script, resultCallback);
        };
    } catch (e) {
        console.log("[-] WebView hook failed");
    }
    
    // Hook native library loading
    try {
        const System = Java.use("java.lang.System");
        System.load.implementation = function(filename) {
            console.log("[+] Native library loaded:", filename);
            return this.load.call(this, filename);
        };
        
        System.loadLibrary.implementation = function(libname) {
            console.log("[+] Native library loaded:", libname);
            return this.loadLibrary.call(this, libname);
        };
    } catch (e) {
        console.log("[-] Native library hook failed");
    }
}); 