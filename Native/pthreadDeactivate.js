// Replace these with actual offsets or addresses from your binary (e.g., from Ghidra/IDA)
// var detectThreatLoopOffset = ptr(0xabcde);  // Example offset for detect_threat_loop
// var detectRootLoopOffset = ptr(0x12345);    // Example offset for detect_root_loop

// var module = Process.findModuleByName('libnative-lib.so');
// if (module) {
//     var detectThreatLoopAddr = module.base.add(detectThreatLoopOffset);
//     var detectRootLoopAddr = module.base.add(detectRootLoopOffset);
//     console.log('Detection functions: threat@' + detectThreatLoopAddr + ', root@' + detectRootLoopAddr);
// } else {
//     console.log('Module not found; cannot compute detection addresses');
//     return;  // Exit if module not loaded yet
// }


var pthreadCreatePtr = Module.findExportByName('libc.so', 'pthread_create');
if (pthreadCreatePtr) {
    var originalPthreadCreate = new NativeFunction(pthreadCreatePtr, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    
    Interceptor.replace(pthreadCreatePtr, new NativeCallback(function(threadPtr, attr, startRoutine, arg) {
        // console.log('Intercepted pthread_create with start_routine: ' + startRoutine);
        
        // Filter specific instruction address
        // Check if start_routine matches a detection loop
        // if (startRoutine.equals(detectThreatLoopAddr) || startRoutine.equals(detectRootLoopAddr)) {
        //     console.log('Skipping detection thread creation');
        //     // Optionally set threadPtr to a dummy value if needed
        //     Memory.writePointer(threadPtr, ptr(0));  // Set thread ID to 0 (dummy)
        //     return 0;  // Return success without creating the thread
        // }

        var routineMod = Process.findModuleByAddress(startRoutine);
        if (routineMod && routineMod.name === 'libnative-lib.so') {
            console.log(`Skipping pthread_create as start_routine is in libnative-lib.so at ${startRoutine}`);
            Memory.writePointer(threadPtr, ptr(0));
            return 0;  // Return success without creating the thread
        }
        
        // Otherwise, call original
        return originalPthreadCreate(threadPtr, attr, startRoutine, arg);
    }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']));
} else {
    console.log('pthread_create not found');
}