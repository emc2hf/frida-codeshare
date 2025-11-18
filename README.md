Frida codeshare scripts. Order is Category most interesting

# HTTP

| URL | Script | Location | Description |
|---|---|---|---|
| https://codeshare.frida.re/@Akramelbahar/native-request-module-offset-finder-/ | native_request_module_offset.js | [location](HTTP/native_request_module_offset.js) | hooks various SSL/TLS and socket-related functions to help identify where SSL/TLS operations are performed in native code |
| https://codeshare.frida.re/@rk00/httprecv/ | http_recv.js | [location](HTTP/http_recv.js) | trace TCP connections of Android apps. based on libc.so!connect(). adds Java backtrace if calling thread is attached to JVM |
| https://codeshare.frida.re/@KhanhPham2411/android-tcp-tracev2/ | tcp_tracev2.js | [location](HTTP/tcp_tracev2.js) | trace TCP connections of Android apps based on libc.so!connect(), with Java backtrace |
| https://codeshare.frida.re/@RadonCoding/frida-okhttp3-intercept/ | okhttp3_intercept.js | [location](HTTP/okhttp3_intercept.js) | Intercepts OkHttp3 requests and prints the requests |
| https://codeshare.frida.re/@yoavst/okhttp3-interceptor-obfuscated/ | okhttp_intercept_obfuscated_okio.js | [location](HTTP/okhttp_intercept_obfuscated_okio.js) | Hook okhttp3 even when okio package is obfuscated |
| https://codeshare.frida.re/@owen800q/okhttp3-interceptor/ | okhttp3_intercept2.js | [location](HTTP/okhttp3_intercept2.js) | Implementation of OkHttp3 network interceptor |
| https://codeshare.frida.re/@nneonneo/android-okhttp3-logger/ | okhttp_intercept3.js | [location](HTTP/okhttp_intercept3.js) | Log requests and responses made using okhttp3 |
| https://codeshare.frida.re/@bsxp/okhttp-logging/ | okhttp_logging2.js | [location](HTTP/okhttp_logging2.js) | Log all http/https requests and responses of okhttp |
| https://codeshare.frida.re/@helviojunior/okhttp-logging/ | okhttp_logging.js | [location](HTTP/okhttp_logging.js) | Log all http/https requests and responses of okhttp |
| https://codeshare.frida.re/@lolicon/https-stalker/ | https_stalker.js | [location](HTTP/https_stalker.js) | trace https payloads |
| https://codeshare.frida.re/@scrool/okhttp3-log-retry-and-follow-up-requests/ | okhttp3_log_retry.js | [location](HTTP/okhttp3_log_retry.js) | Log OkHttp3 communication behind RetryAndFollowUpInterceptor |
| https://codeshare.frida.re/@federicodotta/okhttp-hostname-verifier-bypass/ | okhttp_hostname_verifier_bypass.js | [location](HTTP/okhttp_hostname_verifier_bypass.js) | OkHttp Hostname Verifier bypass |
| https://codeshare.frida.re/@ninjadiary/okhttp/ | okhttp_general_intercept.js | [location](HTTP/okhttp_general_intercept.js) | Network interceptor for OkHttp3 – logs all metadata and bodies |
| https://codeshare.frida.re/@Linuxinet/frida-traffic-interceptor/ | webview_url_logger.js | [location](HTTP/webview_url_logger.js) | Intercepts network traffic + WebView URL loads |
| https://codeshare.frida.re/@gru122121/tls-dumper/ | TLS_dumper.js | [location](HTTP/TLS_dumper.js) | Dumps TLS ClientHello from libssl.so |
| https://codeshare.frida.re/@ninjadiary/frinja---sockets/ | frinja_sockets.js | [location](HTTP/frinja_sockets.js) | Records all socket operations (create/bind/connect/etc) |
| https://codeshare.frida.re/@mame82/android-tcp-trace/ | TCP_trace.js | [location](HTTP/TCP_trace.js) | Log Android TCP connections (with Java call traces) |
| https://codeshare.frida.re/@fdciabdul/frida-tracer/ | HTTP_UDP_general_tracer.js | [location](HTTP/HTTP_UDP_general_tracer.js) | trace HTTP POST and UDP calls with request/response data |

# Native

| URL | Script | Location | Description |
|---|---|---|---|
| https://codeshare.frida.re/@Hyupai/tracedlopen/ | trace_dlopen.js | [location](Native/trace_dlopen.js) | Traces dlopen calls |
| https://codeshare.frida.re/@SNGWN/native-lib-functions/ | native_lib_functions.js | [location](Native/native_lib_functions.js) | get list of all loaded libraries from the application |
| https://codeshare.frida.re/@Hyupai/hook-openat/ | openat_hook.js | [location](Native/openat_hook.js) | Hook OpenAt |
| https://codeshare.frida.re/@Hyupai/classloader/ | classloader.js | [location](Native/classloader.js) | Unknown / classloader exploration |
| https://codeshare.frida.re/@P0r0/very-early-instrumentation-of-native-code/ | early_instrumentation.js | [location](Native/early_instrumentation.js) | Early native instrumentation via constructor hooking |
| https://codeshare.frida.re/@chame1eon/jnitrace/ | jnitrace.js | [location](Native/jnitrace.js) | Trace JNI API interactions |
| https://codeshare.frida.re/@dzonerzy/whereisnative/ | where_is_native.js | [location](Native/where_is_native.js) | Check for native library calls and return stacktrace |
| https://codeshare.frida.re/@hyugogirubato/android-native-interceptor/ | native_interceptor.js | [location](Native/native_interceptor.js) | Intercept and monitor function calls inside native libs |
| https://codeshare.frida.re/@oleavr/who-does-it-call/ | universal_who_calls_function.js | [location](Native/universal_who_calls_function.js) | Find out which functions a given function calls next (Android/iOS) |

# Strings

| URL | Script | Location | Description |
|---|---|---|---|
| https://codeshare.frida.re/@DiegoCaridei/search-for-the-string-in-memory/ | inmemory_strings.js | [location](Strings/inmemory_strings.js) | Search for string in memory |
| https://codeshare.frida.re/@Alkeraithe/encryptedsharedpreferences/ | encrypted_shared_preferences.js | [location](Strings/encrypted_shared_preferences.js) | Dump values saved into EncryptedSharedPreferences |
| https://codeshare.frida.re/@abduxg/strwrt/ | strwrt.js | [location](Strings/strwrt.js) | Unknown / pending description |

# Trace

| URL | Script | Location | Description |
|---|---|---|---|
| https://codeshare.frida.re/@Hyupai/registernativesdump/ | RegisterNatives_dump.js | [location](Trace/RegisterNatives_dump.js) | Dump registerNatives calls |
| https://codeshare.frida.re/@LAripping/trace-registernatives/ | trace_registerNatives.js | [location](Trace/trace_registerNatives.js) | Trace RegisterNatives JNI API invocations |
| https://codeshare.frida.re/@k7eon/android-full-class-path/ | full_class_path.js | [location](Trace/full_class_path.js) | find full class path for Java.use() |
| https://codeshare.frida.re/@ahmsabryy/discover-exported-components/ | exported_components.js | [location](Trace/exported_components.js) | Discover exported Android components |
| https://codeshare.frida.re/@Serhatcck/java-crypto-viewer/ | java_crypto_viewer.js | [location](Trace/java_crypto_viewer.js) | View Java crypto operations |
| https://codeshare.frida.re/@LaiKash/getinfofromclass/ | get_info_class.js | [location](Trace/get_info_class.js) | Inspect class and list method signatures |
| https://codeshare.frida.re/@dzonerzy/dereflector/ | dereflector.js | [location](Trace/dereflector.js) | Show reflection-loaded methods/classes |
| https://codeshare.frida.re/@Alkeraithe/monitorsql/ | monitorSQL.js | [location](Trace/monitorSQL.js) | Print SQL queries (sqlite/sqlcipher) |
| https://codeshare.frida.re/@lateralusd/uibutton-method/ | UIbutton.js | [location](Trace/UIbutton.js) | Get method behind UIButton click |
| https://codeshare.frida.re/@stish834/tracesensitivedata/ | trace_sensitive_data.js | [location](Trace/trace_sensitive_data.js) | Trace sensitive data events |
| https://codeshare.frida.re/@luoyesiqiu/android-native-log/ | liblog.js | [location](Trace/liblog.js) | Use liblog.so to output logs |
| https://codeshare.frida.re/@SecFathy/sqlite-data-monitor/ | sqlite_data_monitor.js | [location](Trace/sqlite_data_monitor.js) | Monitor SQLite database activity |
| https://codeshare.frida.re/@J-jaeyoung/getchildpid/ | get_child_pid.js | [location](Trace/get_child_pid.js) | Get child PID after fork |
| https://codeshare.frida.re/@sknux/viewing-all-read-and-write-files/ | read_write_files.js | [location](Trace/read_write_files.js) | View all files app reads/writes |
| https://codeshare.frida.re/@fadeevab/intercept-android-apk-crypto-operations/ | apk_crypto_operations.js | [location](Trace/apk_crypto_operations.js) | Intercepts Java crypto API & dumps keys |
| https://codeshare.frida.re/@leolashkevych/android-deep-link-observer/ | deeplink_observer.js | [location](Trace/deeplink_observer.js) | Dump deeplink URI data |
| https://codeshare.frida.re/@ma4the/android-deeplink-jsi-monitor/ | deeplink_jsi_monitor.js | [location](Trace/deeplink_jsi_monitor.js) | Monitor deeplink + WebView JSI calls |

# Bypass

| URL | Script | Location | Description |
|---|---|---|---|
| https://codeshare.frida.re/@fopina/piracy-checker-bypass/ | play_store_bypass.js | [location](Bypass/play_store_bypass.js) | Bypass “Installed from Play Store” check |
| https://codeshare.frida.re/@JockerNet-Dev/detectprotections/ | detect_protections.js | [location](Bypass/detect_protections.js) | Detect protections |
| https://codeshare.frida.re/@salecharohit/instrumenting-native-android-functions-using-frida/ | native_android_functions.js | [location](Bypass/native_android_functions.js) | Hooks native anti-root checks and returns false |
| https://codeshare.frida.re/@Raphkitue/android-debug-mode-bypass/ | debugger_mode_bypass.js | [location](Bypass/debugger_mode_bypass.js) | Bypasses debugging mode checks |

Pending:
https://codeshare.frida.re/@sdcampbell/unified-android-root-and-debugger-bypass/
https://codeshare.frida.re/@Surendrajat/anti-root/
https://codeshare.frida.re/@h4rithd/onerule-by-h4rithd/
https://codeshare.frida.re/@ibadfawa/bypass-decrypted-rom-integrity-checks---frida/
https://codeshare.frida.re/@zeroinside/extractcerts/
https://codeshare.frida.re/@khaledealrefaee/universal-android-security-bypass-suite-uasbs-v1-full-mobile-defense-disabler/
