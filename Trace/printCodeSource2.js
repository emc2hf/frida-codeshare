// detect_class_loading_sig_minimal.js
'use strict';

// Configure target here
// globalThis.TARGET_CLASS = "com.erev0s.randomnumber.RandomNumber3";
// globalThis.TARGET_METHOD_NAME = "getRandomNumber";               // set to method name (e.g. "getRandomNumber") or "" to ignore name
// globalThis.TARGET_METHOD_SIG  = [];

// globalThis.TARGET_CLASS = "com.erev0s.myapplicationclassloader.MainActivity";
// globalThis.TARGET_METHOD_NAME = "path_cl";               // set to method name (e.g. "getRandomNumber") or "" to ignore name
// globalThis.TARGET_METHOD_SIG  = ['java.lang.String'];


globalThis.TARGET_CLASS = "o.gdG";
globalThis.TARGET_METHOD_NAME = "d";
globalThis.TARGET_METHOD_SIG = ['java.lang.String', 'o.duC$e', 'java.util.Map', 'java.lang.Object', 'java.util.List'];

(function(){
    function toStr(x){ try { return x === null ? 'null' : x === undefined ? 'undefined' : x.toString(); } catch(e){ return '<err>'; } }

    Java.perform(function(){
        var found = false;

        var TARGET_SIG = globalThis.TARGET_METHOD_SIG;
        var TARGET_NAME = (globalThis.TARGET_METHOD_NAME || '') + '';

        function methodMatchesExact(methodObj) {
            try {
                // name check (if requested)
                if (TARGET_NAME.length > 0) {
                    var mn = '<err>';
                    try { mn = methodObj.getName(); } catch(_) {}
                    if (mn !== TARGET_NAME) return false;
                }
                // signature check (if requested)
                if (TARGET_SIG.length > 0) {
                    var pTA = methodObj.getParameterTypes();
                    var plen = pTA ? pTA.length : 0;
                    if (plen !== TARGET_SIG.length) return false;
                    for (var i = 0; i < plen; i++) {
                        var name = pTA[i].getName();
                        if (name !== TARGET_SIG[i]) return false;
                    }
                }
                // if neither requested, do not match
                if (TARGET_NAME.length === 0 && TARGET_SIG.length === 0) return false;
                return true;
            } catch(e) {
                return false;
            }
        }

        function inspectReturnedClass(returnedClass, loadPoint) {
            if (!returnedClass || found) return;
            try {
                var methods = returnedClass.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    try {
                        var m = methods[i];
                        if (methodMatchesExact(m)) {
                            var pnameList = [];
                            var pTA = m.getParameterTypes();
                            for (var j = 0; j < (pTA? pTA.length:0); j++) pnameList.push(pTA[j].getName());
                            var rtype = '<unknown>';
                            try { rtype = m.getReturnType().getName(); } catch(_) {}
                            var mname = '<ref>';
                            try { mname = m.getName(); } catch(_) {}
                            console.log('[FOUND] ' + returnedClass.getName() + ' :: ' + mname +
                                        ' (' + pnameList.join(',') + ') -> ' + rtype + '  [' + loadPoint + ']');
                            found = true;
                            return true;
                        }
                    } catch(_) { /* skip */ }
                }
            } catch(e) {}
            return false;
        }

        function maybeLogArg(hookName, maybeName) {
            try {
                if (typeof maybeName === 'string' && maybeName === globalThis.TARGET_CLASS) {
                    console.log('[HOOK] ' + hookName + ' arg==TARGET_CLASS -> ' + maybeName);
                }
            } catch(e){}
        }

        // Hook ClassLoader.loadClass(String)
        try {
            var CL = Java.use('java.lang.ClassLoader');
            var cl_load = CL.loadClass.overload('java.lang.String');
            cl_load.implementation = function(name) {
                maybeLogArg('ClassLoader.loadClass (pre)', name);
                var ret = cl_load.apply(this, arguments);
                try { inspectReturnedClass(ret, 'ClassLoader.loadClass'); } catch(e){}
                maybeLogArg('ClassLoader.loadClass (post)', name);
                return ret;
            };
        } catch(e){}

        // Hook Class.forName(String) and forName(String,boolean,ClassLoader)
        try {
            var CF = Java.use('java.lang.Class');
            // var forName1 = CF.forName.overload('java.lang.String');
            // forName1.implementation = function(name) {
                // console.log(`enter forname1: ${name}`);
                // maybeLogArg('Class.forName', name);
                // try {
                //     var ret = forName1.apply(this, arguments);
                //     try { 
                //         inspectReturnedClass(ret, 'Class.forName'); 
                //     } catch(e) {
                //         console.log("err");
                //     }
                //     return ret;
                // } catch (e) {
                //     console.log("Class.forName exception caught: " + e);
                //     return null; // Return null to avoid crash
                // }
            // };
            try {
                var forName3 = CF.forName.overload('java.lang.String','boolean','java.lang.ClassLoader');
                forName3.implementation = function(name, initialize, loader) {
                    maybeLogArg('Class.forName(3)', name);
                    var ret = forName3.apply(this, arguments);
                    try { inspectReturnedClass(ret, 'Class.forName(3)'); } catch(e){}
                    return ret;
                };
            } catch(e2){console.log(2);}
        } catch(e){console.log(1);}

        // DexFile.loadClass(String, ClassLoader)
        try {
            var DexFile = Java.use('dalvik.system.DexFile');
            var df_load = DexFile.loadClass.overload('java.lang.String','java.lang.ClassLoader');
            df_load.implementation = function(name, loader) {
                maybeLogArg('DexFile.loadClass', name);
                var ret = df_load.apply(this, arguments);
                try { inspectReturnedClass(ret, 'DexFile.loadClass'); } catch(e){}
                return ret;
            };
        } catch(e){}

        // Hook constructors (show file path) and try to call this.loadClass(TARGET_CLASS)
        function hookCtor(className, overloadSig, label, logFilePathIndex) {
            try {
                var Cls = Java.use(className);
                var ctor = Cls.$init.overload.apply(Cls.$init, overloadSig);
                ctor.implementation = function() {
                    try {
                        if (typeof logFilePathIndex === 'number') {
                            var arg = arguments[logFilePathIndex];
                            if (arg) console.log('[FILE] ' + label + ' -> ' + toStr(arg));
                        } else {
                            console.log('[HOOK] ' + label + ' ctor called');
                        }
                    } catch(e){}
                    var r = ctor.apply(this, arguments);
                    try {
                        try {
                            var cls = this.loadClass ? this.loadClass(globalThis.TARGET_CLASS) : null;
                            if (cls) inspectReturnedClass(cls, label + '.ctor->loadClass');
                        } catch(_) {}
                    } catch(e){}
                    return r;
                };
            } catch(e){}
        }

        hookCtor('dalvik.system.DexClassLoader',
                 ['java.lang.String','java.lang.String','java.lang.String','java.lang.ClassLoader'],
                 'DexClassLoader', 0);

        try {
            hookCtor('dalvik.system.PathClassLoader',
                     ['java.lang.String','java.lang.ClassLoader'],
                     'PathClassLoader', 0);
        } catch(e) {
            hookCtor('dalvik.system.PathClassLoader',
                     ['java.lang.String','java.lang.String','java.lang.ClassLoader'],
                     'PathClassLoader', 0);
        }

        hookCtor('dalvik.system.InMemoryDexClassLoader',
                 ['java.nio.ByteBuffer','java.lang.ClassLoader'],
                 'InMemoryDexClassLoader', null);

        try {
            var B = Java.use('dalvik.system.BaseDexClassLoader');
            var findClass = B.findClass.overload('java.lang.String');
            findClass.implementation = function(name) {
                maybeLogArg('BaseDexClassLoader.findClass', name);
                var ret = findClass.apply(this, arguments);
                try { inspectReturnedClass(ret, 'BaseDexClassLoader.findClass'); } catch(e){}
                return ret;
            };
        } catch(e){}

        // pre-check: if class already present inspect it
        try {
            var CFref = Java.use('java.lang.Class');
            try {
                var c = CFref.forName.overload('java.lang.String','boolean','java.lang.ClassLoader').call(null, globalThis.TARGET_CLASS, false, Java.use('java.lang.Thread').currentThread().getContextClassLoader());
                if (c) {
                    try {
                        var cl = c.getClassLoader();
                        var ln = cl ? cl.getClass().getName() : 'null';
                        var lt = cl ? toStr(cl.toString()) : '-';
                        console.log('[SOURCE] classloader = ' + ln + ' ; toString=' + lt);
                    } catch(_) {}
                    inspectReturnedClass(c, 'pre-check');
                }
            } catch(e2) {}
        } catch(e3){}

    }); // Java.perform
})();
