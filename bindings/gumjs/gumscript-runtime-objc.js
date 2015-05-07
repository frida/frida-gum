(function () {
    "use strict";

    let _runtime = null;
    let _api = null;
    const pointerSize = Process.pointerSize;
    const scratchBuffer = Memory.alloc(pointerSize);
    const msgSendBySignatureId = {};

    Object.defineProperty(this, 'ObjC', {
        enumerable: true,
        get: function () {
            if (_runtime === null) {
                _runtime = new Runtime();
            }
            return _runtime;
        }
    });

    function Runtime() {
        const api = getApi();
        const registry = new Registry(api);
        const scheduledCallbacks = [];

        Object.defineProperty(this, 'available', {
            enumerable: true,
            get: function () {
                return api !== null;
            }
        });

        Object.defineProperty(this, 'classes', {
            enumerable: true,
            value: registry
        });

        Object.defineProperty(this, 'mainQueue', {
            enumerable: true,
            get: function () {
                return api._dispatch_main_q;
            }
        });

        Object.defineProperty(this, 'Object', {
            enumerable: true,
            value: function (handle) {
                return new ObjCObject(handle, null, api, registry);
            }
        });

        this.schedule = function (queue, work) {
            const NSAutoreleasePool = this.classes.NSAutoreleasePool;
            const workCallback = new NativeCallback(function () {
                const pool = NSAutoreleasePool.alloc().init();
                let pendingException = null;
                try {
                    work();
                } catch (e) {
                    pendingException = e;
                }
                pool.release();
                setTimeout(function () {
                    scheduledCallbacks.splice(scheduledCallbacks.indexOf(workCallback), 1);
                }, 0);
                if (pendingException !== null) {
                    throw pendingException;
                }
            }, 'void', ['pointer']);
            scheduledCallbacks.push(workCallback);
            api.dispatch_async_f(queue, NULL, workCallback);
        };

        this.implement = function (method, fn) {
            return new NativeCallback(fn, method.returnType, method.argumentTypes);
        };

        this.selector = function (name) {
            return api.sel_registerName(Memory.allocUtf8String(name));
        };

        this.selectorAsString = function (sel) {
            return Memory.readUtf8String(api.sel_getName(sel));
        };
    }

    const registryBuiltins = {
        "hasOwnProperty": true,
        "toJSON": true,
        "toString": true,
        "valueOf": true
    };

    function Registry(api) {
        const cachedClasses = {};
        let numCachedClasses = 0;

        const registry = Proxy.create({
            has(name) {
                if (registryBuiltins[name] !== undefined)
                    return true;
                return findClass(name) !== null;
            },
            get(target, name) {
                switch (name) {
                    case "hasOwnProperty":
                        return this.has;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                        return toString;
                    case "valueOf":
                        return valueOf;
                    default:
                        return getClass(name);
                }
            },
            set(target, name, value) {
                throw new Error("Invalid operation");
            },
            enumerate() {
                return this.keys();
            },
            iterate() {
                const props = this.keys();
                let i = 0;
                return {
                    next() {
                        if (i === props.length)
                            throw StopIteration;
                        return props[i++];
                    }
                };
            },
            keys() {
                let numClasses = api.objc_getClassList(NULL, 0);
                if (numClasses !== numCachedClasses) {
                    // It's impossible to unregister classes in ObjC, so if the number of
                    // classes hasn't changed, we can assume that the list is up to date.
                    const rawClasses = Memory.alloc(numClasses * pointerSize);
                    numClasses = api.objc_getClassList(rawClasses, numClasses);
                    for (let i = 0; i !== numClasses; i++) {
                        const handle = Memory.readPointer(rawClasses.add(i * pointerSize));
                        const name = Memory.readUtf8String(api.class_getName(handle));
                        cachedClasses[name] = handle;
                    }
                }
                return Object.keys(cachedClasses);
            }
        });

        function getClass(name) {
            const cls = findClass(name);
            if (cls === null)
                throw new Error("Unable to find class '" + name + "'");
            return cls;
        }

        function findClass(name) {
            let handle = cachedClasses[name];
            if (handle === undefined)
                handle = api.objc_lookUpClass(Memory.allocUtf8String(name));
            if (handle.isNull())
                return null;
            return new ObjCObject(handle, true, api, registry);
        }

        function toJSON() {
            return {};
        }

        function toString() {
            return "Registry";
        }

        function valueOf() {
            return "Registry";
        }

        return registry;
    }

    const objCObjectBuiltins = {
        "handle": true,
        "hasOwnProperty": true,
        "toJSON": true,
        "toString": true,
        "valueOf": true
    };

    function ObjCObject(handle, cachedIsClass, api, registry) {
        let cachedClassHandle = null;
        let hasCachedMethodHandles = false;
        const cachedMethodHandles = {};
        const cachedMethodWrappers = {};

        return Proxy.create({
            has(name) {
                if (objCObjectBuiltins[name] !== undefined)
                    return true;
                return findMethodHandle(name) !== null;
            },
            get(target, name) {
                switch (name) {
                    case "handle":
                        return handle;
                    case "hasOwnProperty":
                        return this.has;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                        return target.description().UTF8String;
                    case "valueOf":
                        return handle.toString;
                    default:
                        return getMethodWrapper(name);
                }
            },
            set(target, name, value) {
                throw new Error("Invalid operation");
            },
            enumerate() {
                return this.keys();
            },
            iterate() {
                const props = this.keys();
                let i = 0;
                return {
                    next() {
                        if (i === props.length)
                            throw StopIteration;
                        return props[i++];
                    }
                };
            },
            keys() {
                if (!hasCachedMethodHandles) {
                    let cur = api.object_getClass(handle);
                    do {
                        const methodHandles = api.class_copyMethodList(cur, scratchBuffer);
                        try {
                            const numMethods = Memory.readU32(scratchBuffer);
                            for (let i = 0; i !== numMethods; i++) {
                                const methodHandle = Memory.readPointer(methodHandles.add(i * pointerSize));
                                const sel = api.method_getName(methodHandle);
                                let name = jsMethodName(Memory.readUtf8String(api.sel_getName(sel)));
                                let serial = 1;
                                let n = name;
                                while (objCObjectBuiltins[n] !== undefined || cachedMethodHandles[n] !== undefined) {
                                    serial++;
                                    n = name + serial;
                                }
                                cachedMethodHandles[n] = methodHandle;
                            }
                        } finally {
                            api.free(methodHandles);
                        }
                        cur = api.class_getSuperclass(cur);
                    } while (!cur.isNull());

                    hasCachedMethodHandles = true;
                }
                return Object.keys(objCObjectBuiltins).concat(Object.keys(cachedMethodHandles));
            }
        });

        function classHandle() {
            if (cachedClassHandle === null)
                cachedClassHandle = isClass() ? handle : api.object_getClass(handle);
            return cachedClassHandle;
        }

        function isClass() {
            if (cachedIsClass === null)
                cachedIsClass = api.object_isClass(handle);
            return cachedIsClass;
        }

        function findMethodHandle(rawName) {
            let methodHandle = cachedMethodHandles[rawName];
            if (methodHandle !== undefined)
                return methodHandle;

            const details = parseMethodName(rawName);
            const kind = details[0];
            const name = details[1];
            const defaultKind = isClass() ? '+' : '-';

            const sel = api.sel_registerName(Memory.allocUtf8String(name));
            methodHandle = (kind === '+')
                ? api.class_getClassMethod(classHandle(), sel)
                : api.class_getInstanceMethod(classHandle(), sel);
            if (methodHandle.isNull())
                return null;

            if (kind === defaultKind)
                cachedMethodHandles[jsMethodName(name)] = methodHandle;

            return methodHandle;
        }

        function getMethodWrapper(name) {
            const method = findMethodWrapper(name);
            if (method === null)
                throw new Error("Unable to find method '" + name + "'");
            return method;
        }

        function findMethodWrapper(rawName) {
            let wrapper = cachedMethodWrappers[rawName];
            if (wrapper !== undefined)
                return wrapper;

            const details = parseMethodName(rawName);
            const kind = details[0];
            const name = details[1];
            const fullName = details[2];

            wrapper = cachedMethodWrappers[fullName];
            if (wrapper !== undefined)
                return wrapper;

            const sel = api.sel_registerName(Memory.allocUtf8String(name));
            const methodHandle = (kind === '+')
                ? api.class_getClassMethod(classHandle(), sel)
                : api.class_getInstanceMethod(classHandle(), sel);
            if (methodHandle.isNull())
                return null;
            wrapper = makeMethodWrapper(methodHandle, sel, api, registry);

            cachedMethodWrappers[fullName] = wrapper;

            return wrapper;
        }

        function parseMethodName(rawName) {
            const match = /([+-])\s?(\S+)/.exec(rawName);
            let name, kind;
            if (match === null) {
                kind = isClass() ? '+' : '-';
                name = objcMethodName(rawName);
            } else {
                kind = match[1];
                name = match[2];
            }
            const fullName = kind + name;
            return [kind, name, fullName];
        }

        function toJSON() {
            return {
                handle: handle.toString()
            };
        }
    }

    function makeMethodWrapper(handle, sel, api, registry) {
        const signature = parseSignature(Memory.readUtf8String(api.method_getTypeEncoding(handle)));
        const retType = signature.retType;
        const argTypes = signature.argTypes.slice(2);
        const objc_msgSend = getMsgSendImpl(signature, api);

        const argVariableNames = argTypes.map(function (t, i) {
            return "a" + (i + 1);
        });
        const callArgs = [
            "this.handle",
            "sel"
        ].concat(argTypes.map(function (t, i) {
            if (t.toNative) {
                return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ", api, registry)";
            }
            return argVariableNames[i];
        }));
        let returnCaptureLeft;
        let returnCaptureRight;
        if (retType.type === 'void') {
            returnCaptureLeft = "";
            returnCaptureRight = "";
        } else if (retType.fromNative) {
            returnCaptureLeft = "return retType.fromNative.call(this, ";
            returnCaptureRight = ", api, registry)";
        } else {
            returnCaptureLeft = "return ";
            returnCaptureRight = "";
        }
        const m = eval("const m = function (" + argVariableNames.join(", ") + ") { " +
            returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
        " }; m;");

        Object.defineProperty(m, 'selector', {
            enumerable: true,
            value: sel
        });

        let implementation = null;
        Object.defineProperty(m, 'implementation', {
            enumerable: true,
            get: function () {
                return new NativeFunction(api.method_getImplementation(handle), m.returnType, m.argumentTypes);
            },
            set: function (imp) {
                implementation = imp;

                api.method_setImplementation(handle, imp);
            }
        });

        Object.defineProperty(m, 'returnType', {
            enumerable: true,
            value: retType.type
        });

        Object.defineProperty(m, 'argumentTypes', {
            enumerable: true,
            value: signature.argTypes.map(function (t) {
                return t.type;
            })
        });

        return m;
    }

    function objcMethodName(name) {
        return name.replace(/_/g, ":");
    }

    function jsMethodName(name) {
        return name.replace(/:/g, "_");
    }

    function getMsgSendImpl(signature, api) {
        let impl = msgSendBySignatureId[signature.id];
        if (!impl) {
            const argTypes = [];
            signature.argTypes.forEach(function (t, i) {
                argTypes.push(t.type);
                if (i == 1) {
                    argTypes.push('...');
                }
            });
            impl = new NativeFunction(api.objc_msgSend, signature.retType.type, argTypes);
            msgSendBySignatureId[signature.id] = impl;
        }

        return impl;
    }

    function parseSignature(sig) {
        let id = "";

        let t = nextType(sig);
        const retType = parseType(t[0]);
        id += retType.type;

        const argTypes = [];
        while (t[1].length > 0) {
            t = nextType(t[1]);
            const argType = parseType(t[0]);
            id += argType.type;
            argTypes.push(argType);
        }

        return {
            id: id,
            retType: retType,
            argTypes: argTypes
        };
    }

    function parseType(t) {
        const qualifiers = [];
        while (t.length > 0) {
            const q = qualifierById[t[0]];
            if (q === undefined)
                break;
            qualifiers.push(q);
            t = t.substring(1);
        }
        const converter = converterById[simplifyType(t)];
        if (converter === undefined)
            throw new Error("No parser for type " + t);
        return converter;
    }

    function simplifyType(t) {
        if (t[0] === '^') {
            switch (t[1]) {
                case '[':
                case '{':
                case '(':
                    return t.substring(0, 2) + t.substring(t.length - 1);
            }
        }
        return t;
    }

    function nextType(t) {
        let type = "";
        let n = 0;
        let scope = null;
        let depth = 0;
        let foundFirstDigit = false;
        while (n < t.length) {
            const c = t[n];
            if (scope !== null) {
                type += c;
                if (c === scope[0]) {
                    depth++;
                } else if (c === scope[1]) {
                    depth--;
                    if (depth === 0) {
                        scope = null;
                    }
                }
            } else {
                const v = t.charCodeAt(n);
                const isDigit = v >= 0x30 && v <= 0x39;
                if (!foundFirstDigit) {
                    foundFirstDigit = isDigit;
                    if (!isDigit) {
                        type += t[n];
                        if (c === '[') {
                            scope = '[]';
                            depth = 1;
                        } else if (c === '{') {
                            scope = '{}';
                            depth = 1;
                        } else if (c === '(') {
                            scope = '()';
                            depth = 1;
                        }
                    }
                } else if (!isDigit) {
                    break;
                }
            }
            n++;
        }
        return [type, t.substring(n)];
    }

    const qualifierById = {
        'r': 'const',
        'n': 'in',
        'N': 'inout',
        'o': 'out',
        'O': 'bycopy',
        'R': 'byref',
        'V': 'oneway'
    };

    const converterById = {
        'c': {
            type: 'char',
            fromNative: function (v) {
                return v ? true : false;
            },
            toNative: function (v) {
                return v ? 1 : 0;
            }
        },
        'i': {
            type: 'int'
        },
        'q': {
            type: 'int64'
        },
        'C': {
            type: 'uchar'
        },
        'I': {
            type: 'uint'
        },
        'S': {
            type: 'uint16'
        },
        'Q': {
            type: 'uint64'
        },
        'f': {
            type: 'float'
        },
        'd': {
            type: 'double'
        },
        'v': {
            type: 'void'
        },
        '*': {
            type: 'pointer',
            fromNative: function (h) {
                if (h.isNull()) {
                    return null;
                }
                return Memory.readUtf8String(h);
            }
        },
        '@': {
            type: 'pointer',
            fromNative: function (h, api, registry) {
                if (h.isNull()) {
                    return null;
                } else if (h.toString(16) === this.handle.toString(16)) {
                    return this;
                } else {
                    return new ObjCObject(h, null, api, registry);
                }
            },
            toNative: function (v, api, registry) {
                if (typeof v === 'string') {
                    return registry.NSString.stringWithUTF8String_(Memory.allocUtf8String(v)).handle;
                }
                return v;
            }
        },
        '@?': {
            type: 'pointer'
        },
        '#': {
            type: 'pointer'
        },
        ':': {
            type: 'pointer'
        },
        '^i': {
            type: 'pointer'
        },
        '^q': {
            type: 'pointer'
        },
        '^S': {
            type: 'pointer'
        },
        '^^S': {
            type: 'pointer'
        },
        '^Q': {
            type: 'pointer'
        },
        '^v': {
            type: 'pointer'
        },
        '^*': {
            type: 'pointer'
        },
        '^@': {
            type: 'pointer'
        },
        '^?': {
            type: 'pointer'
        },
        '^{}': {
            type: 'pointer'
        }
    };

    function getApi() {
        if (_api !== null) {
            return _api;
        }

        const temporaryApi = {};
        const pending = [
            {
                module: "libsystem_malloc.dylib",
                functions: {
                    "free": ['void', ['pointer']]
                },
                variables: {
                }
            },
            {
                module: "libobjc.A.dylib",
                functions: {
                    "objc_msgSend": function (address) {
                        this.objc_msgSend = address;
                        this.objc_msgSend_noargs = new NativeFunction(address, 'pointer', ['pointer', 'pointer', '...']);
                    },
                    "objc_getClassList": ['int', ['pointer', 'int']],
                    "objc_lookUpClass": ['pointer', ['pointer']],
                    "class_getName": ['pointer', ['pointer']],
                    "class_copyMethodList": ['pointer', ['pointer', 'pointer']],
                    "class_getClassMethod": ['pointer', ['pointer', 'pointer']],
                    "class_getInstanceMethod": ['pointer', ['pointer', 'pointer']],
                    "class_getSuperclass": ['pointer', ['pointer']],
                    "object_isClass": ['int8', ['pointer']],
                    "object_getClass": ['pointer', ['pointer']],
                    "method_getName": ['pointer', ['pointer']],
                    "method_getTypeEncoding": ['pointer', ['pointer']],
                    "method_getImplementation": ['pointer', ['pointer']],
                    "method_setImplementation": ['pointer', ['pointer', 'pointer']],
                    "sel_getName": ['pointer', ['pointer']],
                    "sel_registerName": ['pointer', ['pointer']]
                },
                variables: {
                }
            },
            {
                module: "libdispatch.dylib",
                functions: {
                    "dispatch_async_f": ['void', ['pointer', 'pointer', 'pointer']]
                },
                variables: {
                    "_dispatch_main_q": function (address) {
                        this._dispatch_main_q = address;
                    }
                }
            }
        ];
        let remaining = 0;
        pending.forEach(function (api) {
            const pendingFunctions = api.functions;
            const pendingVariables = api.variables;
            remaining += Object.keys(pendingFunctions).length + Object.keys(pendingVariables).length;
            Module.enumerateExports(api.module, {
                onMatch: function (exp) {
                    const name = exp.name;
                    if (exp.type === 'function') {
                        const signature = pendingFunctions[name];
                        if (signature) {
                            if (typeof signature === 'function') {
                                signature.call(temporaryApi, exp.address);
                            } else {
                                temporaryApi[name] = new NativeFunction(exp.address, signature[0], signature[1]);
                            }
                            delete pendingFunctions[name];
                            remaining--;
                        }
                    } else if (exp.type === 'variable') {
                        const handler = pendingVariables[name];
                        if (handler) {
                            handler.call(temporaryApi, exp.address);
                            delete pendingVariables[name];
                            remaining--;
                        }
                    }
                    if (remaining === 0) {
                        return 'stop';
                    }
                },
                onComplete: function () {
                }
            });
        });
        if (remaining === 0) {
            _api = temporaryApi;
        }

        return _api;
    }
}).call(this);
