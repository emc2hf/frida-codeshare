/*
 * Cross-platform function call tracer (iOS + Android)
 * Dynamically selects ObjC mode or Android/native mode.
 */

/**
 * ✔ Keeps the original iOS version (Objective-C + native)
✔ Adds a full Android-compatible version (native function tracing)
✔ Automatically detects platform using:

ObjC.available → iOS

Java.available → Android

Falls back to generic native if needed

✔ Exposes the same start() and stop() API
✔ Uses Stalker on both platforms
✔ Works on exported symbols, raw addresses, or patterns

This script is a generic function-call tracer using Frida’s Stalker engine.
Its purpose is:

To capture and list EVERY function that a chosen function calls the next time it runs.

You can use it on:

Objective-C methods

Swift methods

C / C++ functions

Exported functions

Any address you specify
 */

let listeners = [];
let activated = false;

/* ================================
 *  PLATFORM DETECTION
 * ================================ */
const isIOS = (typeof ObjC !== "undefined") && ObjC.available;
const isAndroid = (typeof Java !== "undefined") && Java.available;

console.log("[*] Platform detection:");
console.log("    iOS:      " + isIOS);
console.log("    Android:  " + isAndroid);
console.log("");

/* ================================
 *  PUBLIC API
 * ================================ */

function start(target) {
    stop();

    if (typeof target === "string") {
        resolvePatternAndStalk(target);
    } else {
        stalkMethod(target.toString(), ptr(target));
    }
}

function stop() {
    for (const listener of listeners)
        listener.detach();
    listeners = [];
    activated = false;
}

/* ================================
 *  PATTERN RESOLUTION
 * ================================ */

function resolvePatternAndStalk(pattern) {
    let resolverType;

    // iOS Objective-C method pattern
    if (isIOS && pattern.includes("[")) {
        resolverType = "objc";
    } else {
        resolverType = "module"; // Android or generic
    }

    const resolver = new ApiResolver(resolverType);
    const matches = resolver.enumerateMatchesSync(pattern);
    if (matches.length === 0)
        throw new Error("No matching functions found for pattern: " + pattern);

    for (const { name, address } of matches)
        stalkMethod(name, address);
}

/* ================================
 *  STALKING LOGIC
 * ================================ */

function stalkMethod(name, impl) {
    console.log("Stalking next call to " + name);

    const listener = Interceptor.attach(impl, {
        onEnter(args) {
            if (activated) return;
            activated = true;

            const targets = {};
            this.targets = targets;

            console.log("\n\nStalker activated for: " + name);

            Stalker.follow({
                events: { call: true },
                onCallSummary(summary) {
                    for (const [target, count] of Object.entries(summary))
                        targets[target] = (targets[target] || 0) + count;
                }
            });
        },
        onLeave(retval) {
            const { targets } = this;
            if (!targets) return;

            Stalker.flush();
            Stalker.unfollow();
            console.log("Stalker deactivated for: " + name);

            printSummary(targets);
        }
    });

    listeners.push(listener);
}

/* ================================
 *  SUMMARY OUTPUT
 * ================================ */

function printSummary(targets) {
    const items = [];
    let total = 0;

    for (const [addr, count] of Object.entries(targets)) {
        const name = DebugSymbol.fromAddress(ptr(addr)).toString();
        const tokens = name.split(" ", 2).map(t => t.toLowerCase());
        items.push([name, count, tokens]);
        total += count;
    }

    items.sort((a, b) => {
        const aTokens = a[2], bTokens = b[2];
        if (aTokens.length === bTokens.length)
            return aTokens[aTokens.length - 1].localeCompare(bTokens[bTokens.length - 1]);
        return aTokens.length > bTokens.length ? -1 : 1;
    });

    if (items.length > 0) {
        console.log("\nCOUNT\tNAME\n-----\t----");
        for (const [name, count] of items)
            console.log(count + "\t" + name);
    }

    console.log("\nUnique functions called: " + items.length);
    console.log("Total function calls:    " + total + "\n");
}

/* ================================
 *  EXPORT GLOBAL API
 * ================================ */

globalThis.start = start;
globalThis.stop = stop;

console.log("[+] Cross-platform stalker initialized.\n");
