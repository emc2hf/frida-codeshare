// https://www.notsosecure.com/instrumenting-native-android-functions-using-frida/ 


// Starts the Android app (com.devadvance.rootinspector) using Frida
// It spawns the app, attaches to it, and loads a Frida script into the process.

// Monitors when native libraries are loaded
// It watches for any dlopen() calls and prints the name of each library the app loads.

// Waits specifically for libnative2.so to be loaded
// Once this library appears, the script begins hooking its functions.

// Overrides root-detection functions inside the native library
// It hooks several native methods responsible for detecting root indicators (checking file existence, running commands like su, listing packages, etc.).

// For each of those functions, forces the return value to “not rooted”
// The script replaces all results with 0, meaning “false,” effectively bypassing the app’s native root-detection mechanisms.

// Keeps the script running and printing messages
// It receives logs from Frida and prevents the app from freezing.

var didHookApis = false;
Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter: function(args) {
        this.path = Memory.readUtf8String(args[0]);
        console.log(this.path);
    },
    onLeave: function(retval) {
        if (!retval.isNull() && this.path.indexOf('libnative2.so') !== -1 && !didHookApis) {
            didHookApis = true;
            console.log("File loaded hooking");
            hooknative2();
            // ...
        }
    }
});

function hooknative2() {
    Interceptor.attach(Module.findExportByName("libnative2.so", "Java_com_devadvance_rootinspector_Root_checkifstream"), {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
    Interceptor.attach(Module.findExportByName("libnative2.so", "Java_com_devadvance_rootinspector_Root_checkfopen"), {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
    Interceptor.attach(Module.findExportByName("libnative2.so", "Java_com_devadvance_rootinspector_Root_checkfopen"), {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
    Interceptor.attach(Module.findExportByName("libnative2.so", "Java_com_devadvance_rootinspector_Root_statfile"), {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
    Interceptor.attach(Module.findExportByName("libnative2.so", "Java_com_devadvance_rootinspector_Root_runsu"), {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
    Interceptor.attach(Module.findExportByName("libnative2.so", "Java_com_devadvance_rootinspector_Root_runls"), {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
    Interceptor.attach(Module.findExportByName("libnative2.so", "Java_com_devadvance_rootinspector_Root_runpmlist"), {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
}