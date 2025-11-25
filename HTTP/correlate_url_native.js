// correlate_url_native.js
// Correlate Java URLs with native connect/send events and print when native sends a request.
//
// Usage:
// frida -U -f com.target.pkg -l correlate_url_native.js --no-pause
//
// Notes:
// - Prints best-effort mapping between Java URLs and native IPs.
// - Captures DNS (InetAddress.getAllByName/getByName) to map host -> ips.
// - Hooks native connect() to know fd -> dest ip:port.
// - Hooks send/sendto/sendmsg and SSL_write/BIO_write (if exported) to capture payload for watched fds.
// - Resilient if symbols are missing. Truncates payloads.

'use strict';

const MAX_PREVIEW = 4096;         // bytes to preview from payload
const RECENT_URL_WINDOW_MS = 60000; // how long to keep URL records

// Data stores
var urlRecords = []; // {ts, url, host, port, path, resolved: [ips]}
var hostToIps = {};  // host -> Set(ip)
var ipToHosts = {};  // ip -> Set(host)
var threadLastUrl = {}; // tid -> last url string (best-effort)
var fdInfo = {}; // fd -> {ip, port, ts, candidates: [urlRecord indices]}

// helpers
function nowTs() { return (new Date()).toISOString().replace('T',' ').split('.')[0]; }
function shortTs() { return (new Date()).toTimeString().split(' ')[0]; }

function ensureSet(map, k) {
  if (!map[k]) map[k] = {};
  return map[k];
}

function addHostIp(host, ip) {
  if (!host) return;
  ensureSet(hostToIps, host)[ip] = true;
  ensureSet(ipToHosts, ip)[host] = true;
}

function trimOldUrls() {
  var cutoff = Date.now() - RECENT_URL_WINDOW_MS;
  urlRecords = urlRecords.filter(r => r.ts >= cutoff);
}

// safe UTF-8 or hex preview
function previewBuffer(ptr, len) {
  try {
    var toRead = Math.min(len || 0, MAX_PREVIEW);
    if (toRead <= 0) return "";
    // Try UTF-8 string
    try {
      return Memory.readUtf8String(ptr, toRead);
    } catch (e) {
      // fallback to hex preview
      var arr = new Uint8Array(Memory.readByteArray(ptr, Math.min(toRead, 256)));
      var hex = Array.from(arr).map(x => ('0' + x.toString(16)).slice(-2)).join(' ');
      return hex;
    }
  } catch (e) {
    return "<unreadable>";
  }
}

// pretty print candidate URLs for an IP
function findUrlCandidatesForIp(ip) {
  var res = [];
  // direct ip -> hosts -> urls
  if (ipToHosts[ip]) {
    Object.keys(ipToHosts[ip]).forEach(function(h) {
      // find urlRecords with that host
      for (var i = urlRecords.length - 1; i >= 0; i--) {
        var r = urlRecords[i];
        if (r.host === h) res.push(r);
      }
    });
  }
  // also consider any url whose resolved contains this ip
  for (var j = urlRecords.length - 1; j >= 0; j--) {
    var r2 = urlRecords[j];
    if (r2.resolved && r2.resolved.indexOf(ip) !== -1) res.push(r2);
  }
  // dedupe and limit
  var uniq = [];
  var seen = {};
  for (var k=0;k<res.length;k++) {
    var s = res[k].url + "@" + res[k].ts;
    if (!seen[s]) { seen[s]=1; uniq.push(res[k]); }
    if (uniq.length >= 5) break;
  }
  return uniq;
}

function prettyCandidates(cands) {
  if (!cands || cands.length===0) return "none";
  return cands.map(c => `${c.url}`).join(" | ");
}

// ---------------------------
// Java hooks: capture URL creation and DNS
// ---------------------------
Java.perform(function() {
  var URL = Java.use('java.net.URL');
  var InetAddress = Java.use('java.net.InetAddress');
  var Thread = Java.use('java.lang.Thread');

  // helper to record URL
  function recordUrl(javaUrl) {
    try {
      var urlStr = javaUrl.toString();
      var host = javaUrl.getHost ? javaUrl.getHost() : null;
      var port = javaUrl.getPort ? javaUrl.getPort() : -1;
      if (port === -1) {
        try { port = javaUrl.getDefaultPort(); } catch(e) {}
      }
      var path = javaUrl.getPath ? javaUrl.getPath() : null;
      var rec = { ts: Date.now(), url: urlStr, host: host, port: port, path: path, resolved: [] };
      urlRecords.push(rec);
      // tie to thread
      try { threadLastUrl[Thread.currentThread().getId()] = urlStr; } catch(e) {}
      console.log(`[URL] ${shortTs()} observed URL: ${urlStr} (host=${host} port=${port})`);
      trimOldUrls();
      return rec;
    } catch (e) { return null; }
  }

  // Hook URL ctor overloads to capture URL creations
  try {
    URL.$init.overload('java.lang.String').implementation = function(s) {
      var r = this.$init(s);
      try { recordUrl(this); } catch(e){}
      return r;
    };
  } catch (e) {}

  try {
    // other common overload
    URL.$init.overload('java.net.URL','java.lang.String').implementation = function(base, spec) {
      var r = this.$init(base, spec);
      try { recordUrl(this); } catch(e){}
      return r;
    };
  } catch (e) {}

  // Hook toString (often used)
  try {
    URL.toString.overload().implementation = function() {
      var s = this.toString();
      try { recordUrl(this); } catch(e) {}
      return s;
    };
  } catch (e) {}

  // URLStreamHandler.setURL may be used by OkHttp handlers - catch it
  try {
    var URLStreamHandler = Java.use('java.net.URLStreamHandler');
    URLStreamHandler.setURL.overload('java.net.URL','java.lang.String','java.lang.String','int','java.lang.String','java.lang.String','java.lang.String','java.lang.String').implementation = function(url, protocol, host, port, authority, userInfo, path, query) {
      try {
        // call original
        var r = this.setURL(url, protocol, host, port, authority, userInfo, path, query);
        // record
        try { recordUrl(url); } catch(e){}
        return r;
      } catch (e) {
        return this.setURL(url, protocol, host, port, authority, userInfo, path, query);
      }
    };
  } catch(e){}

  // Hook InetAddress.getAllByName to capture DNS results
  try {
    InetAddress.getAllByName.overload('java.lang.String').implementation = function(host) {
      var res = InetAddress.getAllByName(host);
      try {
        var list = Java.cast(res, Java.use('java.util.List'));
        var arr = list.toArray();
        var resolved = [];
        for (var i = 0; i < arr.length; i++) {
          try {
            var ip = arr[i].getHostAddress();
            resolved.push(ip);
            addHostIp(host, ip);
          } catch(e){}
        }
        // attach resolved to most recent urlRecords with same host
        for (var j=urlRecords.length-1;j>=0;j--) {
          if (urlRecords[j].host === host) {
            for (var z=0; z<resolved.length; z++) {
              if (urlRecords[j].resolved.indexOf(resolved[z]) === -1) urlRecords[j].resolved.push(resolved[z]);
            }
          }
        }
        console.log("[DNS] " + host + " -> " + resolved.join(", "));
      } catch(e){}
      return res;
    };
  } catch(e){}

  // getByName
  try {
    InetAddress.getByName.overload('java.lang.String').implementation = function(host) {
      var res = InetAddress.getByName(host);
      try {
        var ip = res.getHostAddress();
        addHostIp(host, ip);
        for (var j=urlRecords.length-1;j>=0;j--) if (urlRecords[j].host === host) {
          if (urlRecords[j].resolved.indexOf(ip) === -1) urlRecords[j].resolved.push(ip);
        }
        console.log("[DNS] getByName " + host + " -> " + ip);
      } catch(e){}
      return res;
    };
  } catch(e){}

  console.log("[*] Java URL & DNS hooks installed.");
}); // Java.perform end

// ---------------------------
// Native hooks: connect() to map fd -> ip:port, and send/sendto/sendmsg for payloads
// ---------------------------
(function() {
  // helper to read sockaddr for IPv4/IPv6
  function readSockaddr(saPtr) {
    try {
      var family = Memory.readU16(saPtr);
      if (family === 2) { // AF_INET
        var portBE = Memory.readU16(saPtr.add(2));
        var port = ((portBE & 0xFF) << 8) | ((portBE >>> 8) & 0xFF);
        var b0 = Memory.readU8(saPtr.add(4));
        var b1 = Memory.readU8(saPtr.add(5));
        var b2 = Memory.readU8(saPtr.add(6));
        var b3 = Memory.readU8(saPtr.add(7));
        var ip = [b0,b1,b2,b3].join('.');
        return {family:'AF_INET', ip:ip, port:port};
      } else if (family === 10) { // AF_INET6
        var portBE = Memory.readU16(saPtr.add(2));
        var port = ((portBE & 0xFF) << 8) | ((portBE >>> 8) & 0xFF);
        // read 16 bytes start at offset 8
        var bytes = Memory.readByteArray(saPtr.add(8), 16);
        var u = new Uint8Array(bytes);
        var parts = [];
        for (var i=0;i<16;i+=2) {
          parts.push(((u[i]<<8) | u[i+1]).toString(16));
        }
        var ip6 = parts.join(':');
        return {family:'AF_INET6', ip:ip6, port:port};
      } else {
        return {family:'UNKNOWN', ip:'?', port:0};
      }
    } catch(e) {
      return {family:'ERR', ip:'?', port:0};
    }
  }

  // connect
  var connectPtr = Module.findExportByName(null, "connect");
  if (connectPtr) {
    Interceptor.attach(connectPtr, {
      onEnter: function(args) {
        try {
          this.fd = args[0].toInt32();
          this.sa = args[1];
          this.addrlen = args[2].toInt32 ? args[2].toInt32() : parseInt(args[2]);
          this.info = readSockaddr(this.sa);
          // mark fd pending - will check onLeave
          this._watch = true;
          // store tentative info
          fdInfo[this.fd] = fdInfo[this.fd] || {};
          fdInfo[this.fd].pending = true;
          fdInfo[this.fd].tentative = { ip: this.info.ip, port: this.info.port, family: this.info.family, ts: Date.now() };
          // best-effort: try to get thread's last URL to tag candidate
          try {
            var tid = Process.getCurrentThreadId ? Process.getCurrentThreadId() : -1;
            if (tid !== -1 && threadLastUrl[tid]) {
              fdInfo[this.fd].threadUrl = threadLastUrl[tid];
            }
          } catch(e){}
        } catch(e){}
      },
      onLeave: function(ret) {
        try {
          if (!this._watch) return;
          var success = (ret.toInt32() === 0);
          var t = fdInfo[this.fd] = fdInfo[this.fd] || {};
          if (success) {
            t.ip = this.info.ip;
            t.port = this.info.port;
            t.family = this.info.family;
            t.connected_ts = Date.now();
            t.pending = false;
            // compute candidate URLs
            t.candidates = findUrlCandidatesForIp(t.ip);
            console.log(`[CONNECT] fd=${this.fd} -> ${t.ip}:${t.port}  candidates=${prettyCandidates(t.candidates)}`);
          } else {
            // failed connect (leave pending map)
            //console.log("[CONNECT-Fail] fd=" + this.fd + " ret=" + ret);
            delete fdInfo[this.fd];
          }
        } catch(e){}
      }
    });
    console.log("[*] Hooked native connect()");
  } else {
    console.log("[!] connect symbol not found");
  }

  // attach send-like functions
  function attachSendSym(symName) {
    var ptr = Module.findExportByName(null, symName);
    if (!ptr) {
      //console.log("[info] " + symName + " not found");
      return;
    }
    Interceptor.attach(ptr, {
      onEnter: function(args) {
        try {
          var fd = args[0].toInt32();
          // For sendto the buffer arg might be args[1] or args[2] depending on signature; we'll try common patterns
          var bufPtr = null;
          var len = 0;
          if (symName === "sendmsg") {
            // args[1] is msghdr*, need to parse iovec; heavy; attempt small approach: skip
            return;
          } else {
            // common: send(fd, buf, len, flags)
            bufPtr = args[1];
            len = args[2].toInt32 ? args[2].toInt32() : parseInt(args[2]);
          }
          if (!bufPtr) return;
          // if we have info on fd, log with candidate URLs
          var info = fdInfo[fd];
          var ip = info && info.ip ? info.ip : "<unknown>";
          var port = info && info.port ? info.port : "<?>";
          var candidates = info && info.candidates ? info.candidates : [];
          var threadTag = "";
          try {
            var tid = Process.getCurrentThreadId ? Process.getCurrentThreadId() : -1;
            if (tid !== -1 && threadLastUrl[tid]) threadTag = " threadUrl=" + threadLastUrl[tid];
          } catch(e){}
          var preview = previewBuffer(bufPtr, Math.min(len, MAX_PREVIEW));
          console.log(`\n[OUT] ${symName} fd=${fd} -> ${ip}:${port} ${threadTag}`);
          var cstr = prettyCandidates(candidates);
          console.log(`      url candidates: ${cstr}`);
          console.log("      payload preview:");
          console.log(preview);
          console.log("------");
        } catch(e){}
      }
    });
    console.log("[*] Hooked native " + symName);
  }

  ["send","sendto","sendmsg","write","writev"].forEach(attachSendSym);

  // Hook SSL_write / BIO_write if available (plaintext before TLS)
  ["SSL_write","BIO_write","mbedtls_ssl_write","SSL_write_ex","SSL_read"].forEach(function(sym) {
    var p = Module.findExportByName(null, sym);
    if (!p) return;
    try {
      Interceptor.attach(p, {
        onEnter: function(args) {
          try {
            // SSL_write(ssl, buf, num)
            var buf = args[1];
            var len = args[2].toInt32 ? args[2].toInt32() : parseInt(args[2]);
            var preview = previewBuffer(buf, Math.min(len, MAX_PREVIEW));
            console.log(`\n[TLS-OUT] ${sym} len=${len}`);
            console.log(preview);
            console.log("------");
          } catch(e){}
        }
      });
      console.log("[*] Hooked TLS symbol " + sym);
    } catch(e) {}
  });

  // Also hook recv/read to capture potential replies or TLS handshake
  ["recv","recvfrom","read","recvmsg","readv"].forEach(function(sym) {
    var p = Module.findExportByName(null, sym);
    if (!p) return;
    try {
      Interceptor.attach(p, {
        onEnter: function(args) {
          try {
            this._fd = args[0].toInt32 ? args[0].toInt32() : parseInt(args[0]);
            this._buf = args[1];
          } catch(e){}
        },
        onLeave: function(ret) {
          try {
            var fd = this._fd;
            var info = fdInfo[fd];
            if (!info) return;
            var len = ret.toInt32 ? ret.toInt32() : parseInt(ret);
            if (len <= 0) return;
            var preview = previewBuffer(this._buf, Math.min(len, MAX_PREVIEW));
            console.log(`\n[IN] ${sym} fd=${fd} from ${info.ip}:${info.port} len=${len}`);
            console.log(preview);
            console.log("------");
          } catch(e){}
        }
      });
      //console.log("[*] Hooked " + sym);
    } catch(e){}
  });

})(); // native hooks IIFE
