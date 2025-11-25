// detect_class_source_sig.js
// Minimal: prints classloader/source and finds a method by exact signature and/or name (prints once).
'use strict';

// Configure
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
    function s(x){ try { return x === null ? 'null' : x === undefined ? 'undefined' : x.toString(); } catch(e){ return '<err>'; } }

    Java.perform(function(){
        var printedSource = false;
        var foundAlready = false;

        var TARGET_SIG = globalThis.TARGET_METHOD_SIG;
        var TARGET_NAME = (globalThis.TARGET_METHOD_NAME || '') + '';

        function printSource(Clazz) {
            if (printedSource) return;
            printedSource = true;
            try {
                var cl = Clazz.getClassLoader();
                if (cl === null) {
                    console.log('[SOURCE] classloader = null (bootstrap/bootclasspath/system)');
                } else {
                    var loaderClassName = cl.getClass().getName();
                    var loaderToStr = '-';
                    try { loaderToStr = cl.toString(); } catch(_) {}
                    console.log('[SOURCE] classloader = ' + loaderClassName + ' ; toString=' + loaderToStr);
                }
                try {
                    var pd = Clazz.getProtectionDomain();
                    if (pd !== null) {
                        var cs = pd.getCodeSource();
                        if (cs !== null) {
                            var loc = cs.getLocation();
                            if (loc !== null) console.log('[SOURCE] codesource=' + loc.toString());
                        }
                    }
                } catch(_) {}
            } catch(e) {}
        }

        function methodMatches(m) {
            try {
                // name check (if requested)
                if (TARGET_NAME.length > 0) {
                    var mname = '<err>';
                    try { mname = m.getName(); } catch(_) {}
                    if (mname !== TARGET_NAME) return false;
                }
                // signature check (if requested)
                if (TARGET_SIG.length > 0) {
                    var pTA = m.getParameterTypes();
                    var plen = pTA ? pTA.length : 0;
                    if (plen !== TARGET_SIG.length) return false;
                    for (var i = 0; i < plen; i++) {
                        var nm = pTA[i].getName();
                        if (nm !== TARGET_SIG[i]) return false;
                    }
                }
                // if neither name nor sig requested, nothing to match -> don't match
                if (TARGET_NAME.length === 0 && TARGET_SIG.length === 0) return false;
                return true;
            } catch(e) { return false; }
        }

        function checkAndPrint(Clazz) {
            if (foundAlready) return;
            try {
                var methods = Clazz.getDeclaredMethods();
                for (var i = 0; i < methods.length; i++) {
                    try {
                        var m = methods[i];
                        if (methodMatches(m)) {
                            var pTA = m.getParameterTypes();
                            var params = [];
                            for (var j = 0; j < (pTA? pTA.length:0); j++) try { params.push(pTA[j].getName()); } catch(_) { params.push('<err>'); }
                            var rtype = '<unknown>';
                            try { rtype = m.getReturnType().getName(); } catch(_) {}
                            var mname = '<ref>';
                            try { mname = m.getName(); } catch(_) {}
                            console.log('[FOUND] ' + globalThis.TARGET_CLASS + ' :: ' + mname +
                                        ' (' + params.join(',') + ') -> ' + rtype);
                            foundAlready = true;
                            return true;
                        }
                    } catch(_) {}
                }
            } catch(e) {}
            return false;
        }

        // try Java.use
        try {
            var C = Java.use(globalThis.TARGET_CLASS);
            var Clazz = C.class;
            printSource(Clazz);
            checkAndPrint(Clazz);
            return;
        } catch(e) {
            // fallback to Class.forName
            try {
                var CF = Java.use('java.lang.Class');
                var klass = CF.forName.overload('java.lang.String').call(null, globalThis.TARGET_CLASS);
                if (klass) {
                    printSource(klass);
                    checkAndPrint(klass);
                }
            } catch(e2) { /* silent */ }
        }
    });
})();
