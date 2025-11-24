// hook_url_setDoOutput_corrected.js
// Minimal Frida script:
// - Hooks java.net.URL(String) ctor (simple string ctor)
// - Hooks java.net.URLStreamHandler.setURL (both 6-arg and 9-arg overloads, corrected signatures)
// - Hooks java.net.URLConnection.setDoOutput(boolean)
// - Filters by TARGET_URL and prints the URL + a short Java stack trace when matched
// - Prints the uploaded log file path for reference (local path provided by you)
//
// Usage:
// frida -U -f com.crackme.app -l hook_url_setDoOutput_corrected.js --no-pause
//
// Change TARGET_URL if needed.

'use strict';

const TARGET_URL = "https://android.prod.cloud.netflix.com/graphql";
// Path to uploaded log (kept for your reference)

function printStackShort() {
  try {
    var Exception = Java.use('java.lang.Exception');
    var ex = Exception.$new();
    var st = ex.getStackTrace();
    // skip the first 2 frames (this helper & Exception constructor)
    // for (var i = 2; i < Math.min(st.length, 10); i++) {
    for (var i = 0; i < Math.min(st.length, 10); i++) {
      try {
        var f = st[i];
        console.log("    at " + f.getClassName() + "." + f.getMethodName() +
                    "(" + (f.getFileName() || "Unknown") + ":" + f.getLineNumber() + ")");
      } catch (e) {}
    }
  } catch (e) {}
}

Java.perform(function () {
  console.log("[info] TARGET_URL: " + TARGET_URL);

  // 1) Hook URL(String) constructor (simple string ctor)
  try {
    var URL = Java.use('java.net.URL');
    var ctor_str = URL.$init.overload('java.lang.String');
    ctor_str.implementation = function (spec) {
      // call original constructor
      var ret = ctor_str.call(this, spec);
      try {
        if (spec && spec.indexOf(TARGET_URL) !== -1) {
          console.log("\n[URL.<init>] Detected target URL in constructor: " + spec);
          printStackShort();
        }
      } catch (e) {}
      return ret;
    };
    console.log("[hook] java.net.URL.<init>(String) installed");
  } catch (e) {
    console.log("[warn] Failed to hook java.net.URL.<init>(String): " + e);
  }

  // 2) Hook URLStreamHandler.setURL overloads (6-arg and 9-arg)
  try {
    var URLStreamHandler = Java.use('java.net.URLStreamHandler');

    // 6-arg: setURL(URL u, String protocol, String host, int port, String file, String ref)
    try {
      URLStreamHandler.setURL
        .overload('java.net.URL', 'java.lang.String', 'java.lang.String', 'int', 'java.lang.String', 'java.lang.String')
        .implementation = function (urlObj, protocol, host, port, file, ref) {
          // call original first to preserve behavior
          var r = this.setURL(urlObj, protocol, host, port, file, ref);
          try {
            // Reconstruct a best-effort URL: protocol://host[:port] + file
            var proto = protocol ? protocol.toString() : "http";
            var hoststr = host ? host.toString() : "";
            var portpart = (port && port !== -1) ? (":" + port) : "";
            var filestr = file ? file.toString() : "";
            var full = proto + "://" + hoststr + portpart + filestr;
            if (full.indexOf(TARGET_URL) !== -1) {
              console.log("\n[URLStreamHandler.setURL] (6-arg) Detected target URL: " + full);
              printStackShort();
            }
          } catch (ee) {}
          return r;
        };
      console.log("[hook] URLStreamHandler.setURL (6-arg) installed");
    } catch (e) {
      console.log("[warn] Failed to install 6-arg setURL hook: " + e);
    }

    // 9-arg: setURL(URL u, String protocol, String host, int port, String authority,
    //                String userInfo, String path, String query, String ref)
    // Note: some JVMs use an overload with (URL, String, String, int, String, String, String, String, String)
    try {
      URLStreamHandler.setURL
        .overload(
          'java.net.URL',
          'java.lang.String',
          'java.lang.String',
          'int',
          'java.lang.String',
          'java.lang.String',
          'java.lang.String',
          'java.lang.String',
          'java.lang.String'
        )
        .implementation = function (urlObj, protocol, host, port, authority, userInfo, path, query, ref) {
          var r = this.setURL(urlObj, protocol, host, port, authority, userInfo, path, query, ref);
          try {
            // Reconstruct a best-effort URL:
            // authority typically contains "host" or "host:port"
            var proto = protocol ? protocol.toString() : "http";
            var auth = authority ? authority.toString() : (host ? host.toString() : "");
            var pathstr = path ? path.toString() : "";
            var q = query ? ("?" + query.toString()) : "";
            var full = proto + "://" + auth + pathstr + q;
            if (full.indexOf(TARGET_URL) !== -1) {
              console.log("\n[URLStreamHandler.setURL] (9-arg) Detected target URL: " + full);
              printStackShort();
            }
          } catch (ee) {}
          return r;
        };
      console.log("[hook] URLStreamHandler.setURL (9-arg) installed");
    } catch (e) {
      console.log("[warn] Failed to install 9-arg setURL hook: " + e);
    }

  } catch (e) {
    console.log("[warn] URLStreamHandler not available or hook failed: " + e);
  }

  // 3) Hook URLConnection.setDoOutput(boolean) and filter by URL
  try {
    var URLConnection = Java.use('java.net.URLConnection');
    var setDoOutput = URLConnection.setDoOutput.overload('boolean');
    setDoOutput.implementation = function (flag) {
      try {
        var urlStr = null;
        try {
          var u = this.getURL();
          if (u) urlStr = u.toString();
        } catch (e) {}
        if (urlStr && urlStr.indexOf(TARGET_URL) !== -1) {
          console.log("\n[URLConnection.setDoOutput] URL: " + urlStr + "  setDoOutput(" + flag + ")");
          printStackShort();
        }
      } catch (e) {}
      return setDoOutput.call(this, flag);
    };
    console.log("[hook] java.net.URLConnection.setDoOutput(boolean) installed");
  } catch (e) {
    console.log("[warn] Failed to hook URLConnection.setDoOutput: " + e);
  }

  console.log("[*] Minimal hooks active.");
});
