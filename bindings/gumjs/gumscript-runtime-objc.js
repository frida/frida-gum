(function () {
    "use strict";

    let _runtime = null;
    let _api = null;
    let cachedObjCApi = {};

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
        const pointerSize = Process.pointerSize;
        const api = getApi();
        const classRegistry = new ClassRegistry();
        const protocolRegistry = new ProtocolRegistry();
        const scheduledCallbacks = [];
        const bindings = {};
        const msgSendBySignatureId = {};
        const msgSendSuperBySignatureId = {};

        Object.defineProperty(this, 'available', {
            enumerable: true,
            get: function () {
                return api !== null;
            }
        });

        Object.defineProperty(this, 'api', {
            enumerable: true,
            value: cachedObjCApi
        });

        Object.defineProperty(this, 'classes', {
            enumerable: true,
            value: classRegistry
        });

        Object.defineProperty(this, 'protocols', {
            enumerable: true,
            value: protocolRegistry
        });

        Object.defineProperty(this, 'Object', {
            enumerable: true,
            value: ObjCObject
        });

        Object.defineProperty(this, 'Protocol', {
            enumerable: true,
            value: ObjCProtocol
        });

        Object.defineProperty(this, 'mainQueue', {
            enumerable: true,
            get: function () {
                return api._dispatch_main_q;
            }
        });

        Object.defineProperty(this, 'registerProxy', {
            enumerable: true,
            value: registerProxy
        });

        Object.defineProperty(this, 'registerClass', {
            enumerable: true,
            value: registerClass
        });

        Object.defineProperty(this, 'bind', {
            enumerable: true,
            value: bind
        });

        Object.defineProperty(this, 'unbind', {
            enumerable: true,
            value: unbind
        });

        Object.defineProperty(this, 'getBoundData', {
            enumerable: true,
            value: getBoundData
        });

        Object.defineProperty(this, 'choose', {
            enumerable: true,
            value: choose
        });

        Object.defineProperty(this, 'chooseSync', {
            enumerable: true,
            value: function (specifier) {
                const instances = [];
                choose(specifier, {
                    onMatch: function (i) {
                        instances.push(i);
                    },
                    onComplete: function () {
                    }
                });
                return instances;
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

        this.selector = selector;

        this.selectorAsString = selectorAsString;

        function selector(name) {
            return api.sel_registerName(Memory.allocUtf8String(name));
        }

        function selectorAsString(sel) {
            return Memory.readUtf8String(api.sel_getName(sel));
        }

        const registryBuiltins = {
            "hasOwnProperty": true,
            "toJSON": true,
            "toString": true,
            "valueOf": true
        };

        function ClassRegistry() {
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
                        const classHandles = Memory.alloc(numClasses * pointerSize);
                        numClasses = api.objc_getClassList(classHandles, numClasses);
                        for (let i = 0; i !== numClasses; i++) {
                            const handle = Memory.readPointer(classHandles.add(i * pointerSize));
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
                return new ObjCObject(handle, undefined, true);
            }

            function toJSON() {
                return Object.keys(registry).reduce(function (r, name) {
                    r[name] = getClass(name).toJSON();
                    return r;
                }, {});
            }

            function toString() {
                return "ClassRegistry";
            }

            function valueOf() {
                return "ClassRegistry";
            }

            return registry;
        }

        function ProtocolRegistry() {
            let cachedProtocols = {};

            const registry = Proxy.create({
                has(name) {
                    if (registryBuiltins[name] !== undefined)
                        return true;
                    return findProtocol(name) !== null;
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
                            return getProtocol(name);
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
                    const protocolNames = [];
                    cachedProtocols = {};
                    const numProtocolsBuf = Memory.alloc(pointerSize);
                    let protocolHandles = api.objc_copyProtocolList(numProtocolsBuf);
                    try {
                        const numProtocols = Memory.readUInt(numProtocolsBuf);
                        for (let i = 0; i !== numProtocols; i++) {
                            const handle = Memory.readPointer(protocolHandles.add(i * pointerSize));
                            const name = Memory.readUtf8String(api.protocol_getName(handle));
                            protocolNames.push(name);
                            cachedProtocols[name] = handle;
                        }
                    } finally {
                        api.free(protocolHandles);
                    }
                    return protocolNames;
                }
            });

            function getProtocol(name) {
                const cls = findProtocol(name);
                if (cls === null)
                    throw new Error("Unable to find protocol '" + name + "'");
                return cls;
            }

            function findProtocol(name) {
                let handle = cachedProtocols[name];
                if (handle === undefined)
                    handle = api.objc_getProtocol(Memory.allocUtf8String(name));
                if (handle.isNull())
                    return null;
                return new ObjCProtocol(handle);
            }

            function toJSON() {
                return Object.keys(registry).reduce(function (r, name) {
                    r[name] = { handle: cachedProtocols[name] };
                    return r;
                }, {});
            }

            function toString() {
                return "ProtocolRegistry";
            }

            function valueOf() {
                return "ProtocolRegistry";
            }

            return registry;
        }

        const objCObjectBuiltins = {
            "prototype": true,
            "handle": true,
            "hasOwnProperty": true,
            "toJSON": true,
            "toString": true,
            "valueOf": true,
            "equals": true,
            "$kind": true,
            "$super": true,
            "$superClass": true,
            "$class": true,
            "$className": true,
            "$protocols": true,
            "$methods": true
        };

        function ObjCObject(handle, protocol, cachedIsClass, superSpecifier) {
            let cachedClassHandle = null;
            let cachedKind = null;
            let cachedSuper = null;
            let cachedSuperClass = null;
            let cachedClass = null;
            let cachedClassName = null;
            let cachedProtocols = null;
            let cachedMethodNames = null;
            let cachedProtocolMethods = null;
            let respondsToSelector = null;
            const cachedMethods = {};
            const replacedMethods = {};
            let cachedNativeMethodNames = null;
            let weakRef = null;

            handle = getHandle(handle);

            const self = Proxy.create({
                has(name) {
                    if (objCObjectBuiltins[name] !== undefined)
                        return true;
                    if (protocol) {
                        const details = findProtocolMethod(name);
                        return (details !== null && details.implemented);
                    }
                    return findMethod(name) !== null;
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
                        case "valueOf":
                            const description = target.description();
                            return description.UTF8String.bind(description);
                        case "equals":
                            return equals;
                        case "$kind":
                            if (cachedKind === null) {
                                if (isClass())
                                    cachedKind = api.class_isMetaClass(handle) ? 'meta-class' : 'class';
                                else
                                    cachedKind = 'instance';
                            }
                            return cachedKind;
                        case "$super":
                            if (cachedSuper === null) {
                                const superHandle = api.class_getSuperclass(classHandle());
                                if (!superHandle.isNull()) {
                                    const specifier = Memory.alloc(2 * pointerSize);
                                    Memory.writePointer(specifier, handle);
                                    Memory.writePointer(specifier.add(pointerSize), superHandle);
                                    cachedSuper = [new ObjCObject(handle, undefined, cachedIsClass, specifier)];
                                } else {
                                    cachedSuper = [null];
                                }
                            }
                            return cachedSuper[0];
                        case "$superClass":
                            if (cachedSuperClass === null) {
                                const superClassHandle = api.class_getSuperclass(classHandle());
                                if (!superClassHandle.isNull()) {
                                    cachedSuperClass = [new ObjCObject(superClassHandle)];
                                } else {
                                    cachedSuperClass = [null];
                                }
                            }
                            return cachedSuperClass[0];
                        case "$class":
                            if (cachedClass === null)
                                cachedClass = new ObjCObject(api.object_getClass(handle), undefined, true);
                            return cachedClass;
                        case "$className":
                            if (cachedClassName === null) {
                                if (superSpecifier)
                                    cachedClassName = Memory.readUtf8String(api.class_getName(Memory.readPointer(superSpecifier.add(pointerSize))));
                                else if (isClass())
                                    cachedClassName = Memory.readUtf8String(api.class_getName(handle));
                                else
                                    cachedClassName = Memory.readUtf8String(api.object_getClassName(handle));
                            }
                            return cachedClassName;
                        case "$protocols":
                            if (cachedProtocols === null) {
                                cachedProtocols = {};
                                const numProtocolsBuf = Memory.alloc(pointerSize);
                                const protocolHandles = api.class_copyProtocolList(handle, numProtocolsBuf);
                                if (!protocolHandles.isNull()) {
                                    try {
                                        const numProtocols = Memory.readUInt(numProtocolsBuf);
                                        for (let i = 0; i !== numProtocols; i++) {
                                            const protocolHandle = Memory.readPointer(protocolHandles.add(i * pointerSize));
                                            const p = new ObjCProtocol(protocolHandle);
                                            cachedProtocols[p.name] = p;
                                        }
                                    } finally {
                                        api.free(protocolHandles);
                                    }
                                }
                            }
                            return cachedProtocols;
                        case "$methods":
                            if (cachedNativeMethodNames === null) {
                                cachedNativeMethodNames = [];

                                // Fill cachedMethodNames
                                this.keys();

                                cachedNativeMethodNames = Object.keys(cachedMethods).filter(m => m.match(/^(\+|-)/));
                            }
                            return cachedNativeMethodNames;
                        default:
                            if (protocol) {
                                const details = findProtocolMethod(name);
                                if (details === null || !details.implemented)
                                    throw new Error("Unable to find method '" + name + "'");
                            }
                            const wrapper = findMethodWrapper(name);
                            if (wrapper === null)
                                throw new Error("Unable to find method '" + name + "'");
                            return wrapper;
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
                    if (cachedMethodNames === null) {
                        if (!protocol) {
                            const jsNames = {};
                            const nativeNames = {};

                            let cur = api.object_getClass(handle);
                            do {
                                const numMethodsBuf = Memory.alloc(pointerSize);
                                const methodHandles = api.class_copyMethodList(cur, numMethodsBuf);
                                const fullNamePrefix = isClass() ? "+ " : "- ";
                                try {
                                    const numMethods = Memory.readUInt(numMethodsBuf);
                                    for (let i = 0; i !== numMethods; i++) {
                                        const methodHandle = Memory.readPointer(methodHandles.add(i * pointerSize));
                                        const sel = api.method_getName(methodHandle);
                                        const nativeName = Memory.readUtf8String(api.sel_getName(sel));
                                        if (nativeNames[nativeName] !== undefined)
                                            continue;
                                        nativeNames[nativeName] = nativeName;

                                        const jsName = jsMethodName(nativeName);
                                        let serial = 2;
                                        let name = jsName;
                                        while (jsNames[name] !== undefined) {
                                            serial++;
                                            name = jsName + serial;
                                        }
                                        jsNames[name] = name;

                                        const fullName = fullNamePrefix + nativeName;
                                        if (cachedMethods[fullName] === undefined) {
                                            const details = {
                                                sel: sel,
                                                handle: methodHandle,
                                                wrapper: null
                                            };
                                            cachedMethods[fullName] = details;
                                            cachedMethods[name] = details;
                                        }
                                    }
                                } finally {
                                    api.free(methodHandles);
                                }
                                cur = api.class_getSuperclass(cur);
                            } while (!cur.isNull());

                            cachedMethodNames = Object.keys(jsNames);
                        } else {
                            const methodNames = [];

                            const protocolMethods = allProtocolMethods();
                            Object.keys(protocolMethods).forEach(function (methodName) {
                                if (methodName[0] !== '+' && methodName[0] !== '-') {
                                    const details = protocolMethods[methodName];
                                    if (details.implemented)
                                        methodNames.push(methodName);
                                }
                            });

                            cachedMethodNames = methodNames;
                        }
                    }

                    return Object.keys(objCObjectBuiltins).concat(cachedMethodNames);
                }
            }, Object.getPrototypeOf(this));

            if (protocol) {
                respondsToSelector = !isClass() ? findMethodWrapper("- respondsToSelector:") : null;
            }

            return self;

            function dispose() {
                Object.keys(replacedMethods).forEach(function (key) {
                    const methodHandle = ptr(key);
                    const oldImp = replacedMethods[key];
                    api.method_setImplementation(methodHandle, oldImp);
                });
            }

            function classHandle() {
                if (cachedClassHandle === null)
                    cachedClassHandle = isClass() ? handle : api.object_getClass(handle);
                return cachedClassHandle;
            }

            function isClass() {
                if (cachedIsClass === undefined) {
                    if (api.object_isClass)
                        cachedIsClass = !!api.object_isClass(handle);
                    else
                        cachedIsClass = !!api.class_isMetaClass(api.object_getClass(handle));
                }
                return cachedIsClass;
            }

            function findMethod(rawName) {
                let method = cachedMethods[rawName];
                if (method !== undefined)
                    return method;

                const tokens = parseMethodName(rawName);
                const kind = tokens[0];
                const name = tokens[1];
                const sel = selector(name);
                const fullName = tokens[2];
                const defaultKind = isClass() ? '+' : '-';

                if (protocol) {
                    const details = findProtocolMethod(fullName);
                    if (details !== null) {
                        method = {
                            sel: sel,
                            types: details.types,
                            wrapper: null
                        };
                    }
                }

                if (method === undefined) {
                    const methodHandle = (kind === '+')
                        ? api.class_getClassMethod(classHandle(), sel)
                        : api.class_getInstanceMethod(classHandle(), sel);
                    if (!methodHandle.isNull()) {
                        method = {
                            sel: sel,
                            handle: methodHandle,
                            wrapper: null
                        };
                    } else {
                        if (!isClass() && kind === '-' && name !== "methodSignatureForSelector:" && "- methodSignatureForSelector:" in self) {
                            const s = self.methodSignatureForSelector_(sel);
                            if (s === null)
                                return null;
                            const numArgs = s.numberOfArguments();
                            const frameSize = numArgs * pointerSize;
                            let types = s.methodReturnType() + frameSize;
                            for (let i = 0; i !== numArgs; i++) {
                                const frameOffset = (i * pointerSize);
                                types += s.getArgumentTypeAtIndex_(i) + frameOffset;
                            }
                            method = {
                                sel: sel,
                                types: types,
                                wrapper: null
                            };
                        } else {
                            return null;
                        }
                    }
                }

                cachedMethods[fullName] = method;
                if (kind === defaultKind)
                    cachedMethods[jsMethodName(name)] = method;

                return method;
            }

            function findProtocolMethod(rawName) {
                const protocolMethods = allProtocolMethods();
                const details = protocolMethods[rawName];
                return (details !== undefined) ? details : null;
            }

            function allProtocolMethods() {
                if (cachedProtocolMethods === null) {
                    const methods = {};

                    const protocols = collectProtocols(protocol);
                    const defaultKind = isClass() ? '+' : '-';
                    Object.keys(protocols).forEach(function (name) {
                        const p = protocols[name];
                        const m = p.methods;
                        Object.keys(m).forEach(function (fullMethodName) {
                            const method = m[fullMethodName];
                            const methodName = fullMethodName.substr(2);
                            const kind = fullMethodName[0];

                            let didCheckImplemented = false;
                            let implemented = false;
                            const details = {
                                types: method.types
                            };
                            Object.defineProperty(details, 'implemented', {
                                get: function () {
                                    if (!didCheckImplemented) {
                                        if (method.required) {
                                            implemented = true;
                                        } else {
                                            implemented = (respondsToSelector !== null && respondsToSelector.call(self, selector(methodName)));
                                        }
                                        didCheckImplemented = true;
                                    }
                                    return implemented;
                                }
                            });

                            methods[fullMethodName] = details;
                            if (kind === defaultKind)
                                methods[jsMethodName(methodName)] = details;
                        });
                    });

                    cachedProtocolMethods = methods;
                }

                return cachedProtocolMethods;
            }

            function findMethodWrapper(name) {
                const method = findMethod(name);
                if (method === null)
                    return null;
                let wrapper = method.wrapper;
                if (wrapper === null) {
                    wrapper = makeMethodInvocationWrapper(method, self, superSpecifier, replaceMethodImplementation);
                    method.wrapper = wrapper;
                }
                return wrapper;
            }

            function replaceMethodImplementation(methodHandle, imp, oldImp) {
                api.method_setImplementation(methodHandle, imp);

                if (!imp.equals(oldImp))
                    replacedMethods[methodHandle.toString()] = oldImp;
                else
                    delete replacedMethods[methodHandle.toString()];

                if (weakRef === null)
                    weakRef = WeakRef.bind(self, dispose);
            }

            function parseMethodName(rawName) {
                const match = /([+-])\s(\S+)/.exec(rawName);
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

            function equals(ptr) {
                return handle.equals(getHandle(ptr));
            }
        }

        function ObjCProtocol(handle) {
            let cachedName = null;
            let cachedProtocols = null;
            let cachedProperties = null;
            let cachedMethods = null;

            Object.defineProperty(this, 'handle', {
                value: handle,
                enumerable: true
            });

            Object.defineProperty(this, 'name', {
                get: function () {
                    if (cachedName === null)
                        cachedName = Memory.readUtf8String(api.protocol_getName(handle));
                    return cachedName;
                },
                enumerable: true
            });

            Object.defineProperty(this, 'protocols', {
                get: function () {
                    if (cachedProtocols === null) {
                        cachedProtocols = {};
                        const numProtocolsBuf = Memory.alloc(pointerSize);
                        const protocolHandles = api.protocol_copyProtocolList(handle, numProtocolsBuf);
                        if (!protocolHandles.isNull()) {
                            try {
                                const numProtocols = Memory.readUInt(numProtocolsBuf);
                                for (let i = 0; i !== numProtocols; i++) {
                                    const protocolHandle = Memory.readPointer(protocolHandles.add(i * pointerSize));
                                    const protocol = new ObjCProtocol(protocolHandle);
                                    cachedProtocols[protocol.name] = protocol;
                                }
                            } finally {
                                api.free(protocolHandles);
                            }
                        }
                    }
                    return cachedProtocols;
                },
                enumerable: true
            });

            Object.defineProperty(this, 'properties', {
                get: function () {
                    if (cachedProperties === null) {
                        cachedProperties = {};
                        const numBuf = Memory.alloc(pointerSize);
                        const propertyHandles = api.protocol_copyPropertyList(handle, numBuf);
                        if (!propertyHandles.isNull()) {
                            try {
                                const numProperties = Memory.readUInt(numBuf);
                                for (let i = 0; i !== numProperties; i++) {
                                    const propertyHandle = Memory.readPointer(propertyHandles.add(i * pointerSize));
                                    const name = Memory.readUtf8String(api.property_getName(propertyHandle));
                                    const attributes = {};
                                    const attributeEntries = api.property_copyAttributeList(propertyHandle, numBuf);
                                    if (!attributeEntries.isNull()) {
                                        try {
                                            const numAttributeValues = Memory.readUInt(numBuf);
                                            for (let j = 0; j !== numAttributeValues; j++) {
                                                const attributeEntry = attributeEntries.add(j * (2 * pointerSize));
                                                const name = Memory.readUtf8String(Memory.readPointer(attributeEntry));
                                                const value = Memory.readUtf8String(Memory.readPointer(attributeEntry.add(pointerSize)));
                                                attributes[name] = value;
                                            }
                                        } finally {
                                            api.free(attributeEntries);
                                        }
                                    }
                                    cachedProperties[name] = attributes;
                                }
                            } finally {
                                api.free(propertyHandles);
                            }
                        }
                    }
                    return cachedProperties;
                },
                enumerable: true
            });

            Object.defineProperty(this, 'methods', {
                get: function () {
                    if (cachedMethods === null) {
                        cachedMethods = {};
                        const numBuf = Memory.alloc(pointerSize);
                        collectMethods(cachedMethods, numBuf, { required: true, instance: false });
                        collectMethods(cachedMethods, numBuf, { required: false, instance: false });
                        collectMethods(cachedMethods, numBuf, { required: true, instance: true });
                        collectMethods(cachedMethods, numBuf, { required: false, instance: true });
                    }
                    return cachedMethods;
                },
                enumerable: true
            });

            function collectMethods(methods, numBuf, spec) {
                const methodDescValues = api.protocol_copyMethodDescriptionList(handle, spec.required ? 1 : 0, spec.instance ? 1 : 0, numBuf);
                if (methodDescValues.isNull())
                    return;
                try {
                    const numMethodDescValues = Memory.readUInt(numBuf);
                    for (let i = 0; i !== numMethodDescValues; i++) {
                        const methodDesc = methodDescValues.add(i * (2 * pointerSize));
                        const name = (spec.instance ? '- ' : '+ ') + selectorAsString(Memory.readPointer(methodDesc));
                        const types = Memory.readUtf8String(Memory.readPointer(methodDesc.add(pointerSize)));
                        methods[name] = {
                            required: spec.required,
                            types: types
                        };
                    }
                } finally {
                    api.free(methodDescValues);
                }
            }
        }

        function collectProtocols(p, acc) {
            acc = acc || {};

            acc[p.name] = p;

            const parentProtocols = p.protocols;
            Object.keys(parentProtocols).forEach(function (name) {
                collectProtocols(parentProtocols[name], acc);
            });

            return acc;
        }

        function registerProxy(properties) {
            const protocols = properties.protocols || [];
            const methods = properties.methods || {};
            const events = properties.events || {};

            const proxyMethods = {
                '- dealloc': function () {
                    this.data.target.release();
                    unbind(this.self);
                    this.super.dealloc();
                },
                '- respondsToSelector:': function (sel) {
                    return this.data.target.respondsToSelector_(sel);
                },
                '- forwardingTargetForSelector:': function (sel) {
                    const callback = this.data.events.forward;
                    if (callback !== undefined)
                        callback.call(this, selectorAsString(sel));
                    return this.data.target;
                },
                '- methodSignatureForSelector:': function (sel) {
                    return this.data.target.methodSignatureForSelector_(sel);
                },
                '- forwardInvocation:': function (invocation) {
                    invocation.invokeWithTarget_(this.data.target);
                }
            };
            for (var key in methods) {
                if (methods.hasOwnProperty(key)) {
                    if (proxyMethods.hasOwnProperty(key))
                        throw new Error("The '" + key + "' method is reserved");
                    proxyMethods[key] = methods[key];
                }
            }

            const ProxyClass = registerClass({
                super: classRegistry.NSProxy,
                protocols: protocols,
                methods: proxyMethods
            });

            return function (target, data) {
                target = (target instanceof NativePointer) ? new ObjCObject(target) : target;
                data = data || {};

                const instance = ProxyClass.alloc().autorelease();

                const boundData = getBoundData(instance);
                boundData.target = target.retain();
                boundData.events = events;
                for (var key in data) {
                    if (data.hasOwnProperty(key)) {
                        if (boundData.hasOwnProperty(key))
                            throw new Error("The '" + key + "' property is reserved");
                        boundData[key] = data[key];
                    }
                }

                this.handle = instance.handle;
            };
        }

        function registerClass(properties) {
            let name = properties.name;
            if (name) {
                if (name in classRegistry)
                    throw new Error("Unable to register already registered class '" + name + "'");
            } else {
                name = makeClassName();
            }
            const superClass = (properties.super !== undefined) ? properties.super : classRegistry.NSObject;
            const protocols = properties.protocols || [];
            const methods = properties.methods || {};

            const classHandle = api.objc_allocateClassPair(superClass !== null ? superClass.handle : NULL, Memory.allocUtf8String(name), ptr("0"));
            const metaClassHandle = api.object_getClass(classHandle);
            try {
                protocols.forEach(function (protocol) {
                    api.class_addProtocol(classHandle, protocol.handle);
                });

                Object.keys(methods).forEach(function (rawMethodName) {
                    const match = /([+-])\s(\S+)/.exec(rawMethodName);
                    if (match === null)
                        throw new Error("Invalid method name");
                    const kind = match[1];
                    const name = match[2];

                    let method;
                    const value = methods[rawMethodName];
                    if (typeof value === 'function') {
                        let types;
                        if (rawMethodName in superClass) {
                            types = superClass[rawMethodName].types;
                        } else {
                            const protocol = protocols.find(function (protocol) {
                                return rawMethodName in protocol.methods;
                            });
                            types = (protocol !== undefined) ? protocol.methods[rawMethodName].types : null;
                        }
                        if (types === null)
                            throw new Error("Unable to find '" + rawMethodName + "' in super-class or any of its protocols");
                        method = {
                            types: types,
                            implementation: value
                        };
                    } else {
                        method = value;
                    }

                    const target = (kind === '+') ? metaClassHandle : classHandle;
                    let types = method.types;
                    if (types === undefined) {
                        types = unparseSignature(method.retType, [(kind === '+') ? 'class' : 'object', 'selector'].concat(method.argTypes));
                    }
                    const signature = parseSignature(types);
                    const implementation = new NativeCallback(
                        makeMethodImplementationWrapper(signature, method.implementation),
                        signature.retType.type,
                        signature.argTypes.map(function (arg) { return arg.type; }));
                    api.class_addMethod(target, selector(name), implementation, Memory.allocUtf8String(types));
                });
            } catch (e) {
                api.objc_disposeClassPair(classHandle);
                throw e;
            }
            api.objc_registerClassPair(classHandle);

            return new ObjCObject(classHandle);
        }

        function getHandle(obj) {
            if (obj instanceof NativePointer)
                return obj;
            else if (typeof obj === 'object' && obj.hasOwnProperty('handle'))
                return obj.handle;
            else
                throw new Error("Expected NativePointer or ObjC.Object instance");
        }

        function bind(obj, data) {
            const handle = getHandle(obj);
            const self = (obj instanceof ObjCObject) ? obj : new ObjCObject(handle);
            bindings[handle.toString()] = {
                self: self,
                super: self.$super,
                data: data
            };
        }

        function unbind(obj) {
            const handle = getHandle(obj);
            delete bindings[handle.toString()];
        }

        function getBoundData(obj) {
            return getBinding(obj).data;
        }

        function getBinding(obj) {
            const handle = getHandle(obj);
            const key = handle.toString();
            let binding = bindings[key];
            if (binding === undefined) {
                const self = (obj instanceof ObjCObject) ? obj : new ObjCObject(handle);
                binding = {
                    self: self,
                    super: self.$super,
                    data: {}
                };
                bindings[key] = binding;
            }
            return binding;
        }

        function choose(specifier, callbacks) {
            let cls = specifier;
            let subclasses = true;
            if (!(specifier instanceof ObjCObject) && typeof specifier === 'object') {
                cls = specifier.class;
                if (specifier.hasOwnProperty('subclasses'))
                    subclasses = specifier.subclasses;
            }
            if (!(cls instanceof ObjCObject && (cls.$kind === 'class' || cls.$kind === 'meta-class')))
                throw new Error("Expected an ObjC.Object for a class or meta-class");
            const ptr = cls.handle;

            const classHandles = subclasses ? getRecursiveSubclasses(ptr) : [ptr];

            const classes = new Set(classHandles.map(h => h.toString()));

            Process.enumerateMallocRanges({
                onMatch: function (range) {
                    const ptr = range.base;
                    const cls = Memory.readPointer(ptr);
                    if (classes.has(cls.toString()) && range.size >= api.class_getInstanceSize(cls)) {
                        return callbacks.onMatch(new ObjCObject(ptr));
                    }
                },
                onComplete: callbacks.onComplete
            });
        }

        function getRecursiveSubclasses(ptr) {
            const subclasses = [];
            for (let name in classRegistry) {
                const cls = classRegistry[name].handle;
                let c = cls;
                do {
                    if (c.equals(ptr)) {
                        subclasses.push(cls);
                        break;
                    }
                    c = api.class_getSuperclass(c);
                } while (!c.isNull());
            }
            return subclasses;
        }

        function makeMethodInvocationWrapper(method, owner, superSpecifier, replaceImplementation) {
            const sel = method.sel;
            let handle = method.handle;
            let types;
            if (handle === undefined) {
                handle = null;
                types = method.types;
            } else {
                types = Memory.readUtf8String(api.method_getTypeEncoding(handle));
            }

            const signature = parseSignature(types);
            const retType = signature.retType;
            const argTypes = signature.argTypes.slice(2);
            const objc_msgSend = superSpecifier ? getMsgSendSuperImpl(signature) : getMsgSendImpl(signature);

            const argVariableNames = argTypes.map(function (t, i) {
                return "a" + (i + 1);
            });
            const callArgs = [
                superSpecifier ? "superSpecifier" : "this",
                "sel"
            ].concat(argTypes.map(function (t, i) {
                if (t.toNative) {
                    return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
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
                returnCaptureRight = ")";
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

            let oldImp = null;
            Object.defineProperty(m, 'implementation', {
                enumerable: true,
                get: function () {
                    const h = getMethodHandle();

                    return new NativeFunction(api.method_getImplementation(h), m.returnType, m.argumentTypes);
                },
                set: function (imp) {
                    const h = getMethodHandle();

                    if (oldImp === null)
                        oldImp = api.method_getImplementation(h);

                    replaceImplementation(h, imp, oldImp);
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

            Object.defineProperty(m, 'types', {
                enumerable: true,
                value: types
            });

            function getMethodHandle() {
                if (handle === null) {
                    if (owner.$kind === 'instance') {
                        let cur = owner;
                        do {
                            if ("- forwardingTargetForSelector:" in cur) {
                                const target = cur.forwardingTargetForSelector_(sel);
                                if (target === null)
                                    break;
                                if (target.$kind !== 'instance')
                                    break;
                                const h = api.class_getInstanceMethod(target.$class.handle, sel);
                                if (!h.isNull())
                                    handle = h;
                                else
                                    cur = target;
                            } else {
                                break;
                            }
                        } while (handle === null);
                    }

                    if (handle === null)
                        throw new Error("Unable to find method handle of proxied function");
                }

                return handle;
            }

            return m;
        }

        function makeMethodImplementationWrapper(signature, implementation) {
            const retType = signature.retType;
            const argTypes = signature.argTypes;

            const argVariableNames = argTypes.map(function (t, i) {
                if (i === 0)
                    return "handle";
                else if (i === 1)
                    return "sel";
                else
                    return "a" + (i - 1);
            });
            const callArgs = argTypes.slice(2).map(function (t, i) {
                const argVariableName = argVariableNames[2 + i];
                if (t.fromNative) {
                    return "argTypes[" + (2 + i) + "].fromNative.call(self, " + argVariableName + ")";
                }
                return argVariableName;
            });
            let returnCaptureLeft;
            let returnCaptureRight;
            if (retType.type === 'void') {
                returnCaptureLeft = "";
                returnCaptureRight = "";
            } else if (retType.toNative) {
                returnCaptureLeft = "return retType.toNative.call(self, ";
                returnCaptureRight = ")";
            } else {
                returnCaptureLeft = "return ";
                returnCaptureRight = "";
            }

            const m = eval("const m = function (" + argVariableNames.join(", ") + ") { " +
                "const binding = getBinding(handle);" +
                "const self = binding.self;" +
                returnCaptureLeft + "implementation.call(binding" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
            " }; m;");

            return m;
        }

        function rawFridaType(t) {
            return (t === 'object') ? 'pointer' : t;
        }

        function makeClassName() {
            for (let i = 1; true; i++) {
                const name = "FridaAnonymousClass" + i;
                if (!(name in classRegistry)) {
                    return name;
                }
            }
        }

        function objcMethodName(name) {
            return name.replace(/_/g, ":");
        }

        function jsMethodName(name) {
            let result = name.replace(/:/g, "_");
            if (objCObjectBuiltins[result] !== undefined)
                result += "2";
            return result;
        }

        function getMsgSendImpl(signature) {
            let impl = msgSendBySignatureId[signature.id];
            if (!impl) {
                const argTypes = signature.argTypes.map(function (t) { return t.type; });
                impl = new NativeFunction(api.objc_msgSend, signature.retType.type, argTypes);
                msgSendBySignatureId[signature.id] = impl;
            }

            return impl;
        }

        function getMsgSendSuperImpl(signature) {
            let impl = msgSendSuperBySignatureId[signature.id];
            if (!impl) {
                const argTypes = signature.argTypes.map(function (t) { return t.type; });
                impl = new NativeFunction(api.objc_msgSendSuper, signature.retType.type, argTypes);
                msgSendSuperBySignatureId[signature.id] = impl;
            }

            return impl;
        }

        function unparseSignature(retType, argTypes) {
            const frameSize = argTypes.length * pointerSize;
            return typeIdFromAlias(retType) + frameSize + argTypes.map(function (argType, i) {
                const frameOffset = (i * pointerSize);
                return typeIdFromAlias(argType) + frameOffset;
            }).join("");
        }

        function parseSignature(sig) {
            const cursor = [sig, 0];

            parseQualifiers(cursor);
            const retType = readType(cursor);
            readNumber(cursor);

            const argTypes = [];

            let id = retType.type;

            while (dataAvailable(cursor)) {
                parseQualifiers(cursor);
                const argType = readType(cursor);
                readNumber(cursor);
                argTypes.push(argType);

                id += argType.type;
            }

            return {
                id: id,
                retType: retType,
                argTypes: argTypes
            };
        }

        function readType(cursor) {
            while (true) {
                const c = readChar(cursor);

                const type = singularTypeById[c];
                if (type !== undefined) {
                    return type;
                } else if (c === '[') {
                    const length = readNumber(cursor);
                    const elementType = readType(cursor);
                    skipChar(cursor); // ']'
                    return arrayType(length, elementType);
                } else if (c === '{') {
                    readUntil('=', cursor);
                    const fields = [];
                    do {
                        fields.push(readType(cursor));
                    } while (peekChar(cursor) !== '}');
                    skipChar(cursor); // '}'
                    return structType(fields);
                } else if (c === '(') {
                    readUntil('=', cursor);
                    const fields = [];
                    do {
                        fields.push(readType(cursor));
                    } while (peekChar(cursor) !== '}');
                    skipChar(cursor); // ')'
                    return unionType(fields);
                } else if (c === 'b') {
                    readNumber(cursor);
                    return singularTypeById['i'];
                } else if (c === '^') {
                    readType(cursor);
                    return singularTypeById['?'];
                } else {
                    throw new Error("Unable to handle type " + id);
                }
            }
        }

        function readNumber(cursor) {
            let result = "";
            while (dataAvailable(cursor)) {
                const c = peekChar(cursor);
                const v = c.charCodeAt(0);
                const isDigit = v >= 0x30 && v <= 0x39;
                if (isDigit) {
                    result += c;
                    skipChar(cursor);
                } else {
                    break;
                }
            }
            return parseInt(result);
        }

        function readUntil(token, cursor) {
            const buffer = cursor[0];
            const offset = cursor[1];
            const index = buffer.indexOf(token, offset);
            if (index === -1)
                throw new Error("Expected token '" + token + "' not found");
            const result = buffer.substring(offset, index);
            cursor[1] = index + 1;
            return result;
        }

        function readChar(cursor) {
            return cursor[0][cursor[1]++];
        }

        function peekChar(cursor) {
            return cursor[0][cursor[1]];
        }

        function skipChar(cursor) {
            cursor[1]++;
        }

        function dataAvailable(cursor) {
            return cursor[1] !== cursor[0].length;
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

        function parseQualifiers(cursor) {
            const qualifiers = [];
            while (true) {
                const q = qualifierById[peekChar(cursor)];
                if (q === undefined)
                    break;
                qualifiers.push(q);
                skipChar(cursor);
            }
            return qualifiers;
        }

        const idByAlias = {
            'char': 'c',
            'int': 'i',
            'int16': 's',
            'int32': 'l',
            'int64': 'q',
            'uchar': 'C',
            'uint': 'I',
            'uint16': 'S',
            'uint32': 'L',
            'uint64': 'Q',
            'float': 'f',
            'double': 'd',
            'bool': 'B',
            'void': 'v',
            'string': '*',
            'object': '@',
            'class': '#',
            'selector': ':'
        };

        function typeIdFromAlias(alias) {
            const id = idByAlias[alias];
            if (id === undefined)
                throw new Error("No known encoding for type " + alias);
            return id;
        }

        const fromNativeId = function (h) {
            if (h.isNull()) {
                return null;
            } else if (h.toString(16) === this.handle.toString(16)) {
                return this;
            } else {
                return new ObjCObject(h);
            }
        };

        const toNativeId = function (v) {
            if (typeof v === 'string') {
                return classRegistry.NSString.stringWithUTF8String_(Memory.allocUtf8String(v));
            }
            return v;
        };

        function arrayType(length, elementType) {
            return {
                type: 'pointer'
            };
        }

        function structType(fieldTypes) {
            return {
                type: fieldTypes.map(function (t) {
                    return t.type;
                }),
                size: fieldTypes.reduce(function (totalSize, t) {
                    return totalSize + t.size;
                }, 0),
                fromNative: function (v) {
                    return v.map(function (v, i) {
                        return fieldTypes[i].fromNative.call(this, v);
                    }, this);
                },
                toNative: function (v) {
                    return v.map(function (v, i) {
                        return fieldTypes[i].toNative.call(this, v);
                    }, this);
                }
            };
        }

        function unionType(fieldTypes) {
            const largestType = fieldTypes.reduce(function (largest, t) {
                if (t.size > largest.size)
                    return t;
                else
                    return largest;
            }, fieldTypes[0]);
            return {
                type: [largestType.type],
                size: largestType.size,
                fromNative: function (v) {
                    return [largestType.fromNative.call(this, v)];
                },
                toNative: function (v) {
                    return [largestType.toNative.call(this, v)];
                }
            };
        }

        const singularTypeById = {
            'c': {
                type: 'char',
                size: 1,
                toNative: function (v) {
                    if (typeof v === 'boolean') {
                        return v ? 1 : 0;
                    }
                    return v;
                }
            },
            'i': {
                type: 'int',
                size: 4
            },
            's': {
                type: 'int16',
                size: 2
            },
            'l': {
                type: 'int32',
                size: 4
            },
            'q': {
                type: 'int64',
                size: 8
            },
            'C': {
                type: 'uchar',
                size: 1
            },
            'I': {
                type: 'uint',
                size: 4
            },
            'S': {
                type: 'uint16',
                size: 2
            },
            'L': {
                type: 'uint32',
                size: 4
            },
            'Q': {
                type: 'uint64',
                size: 8
            },
            'f': {
                type: 'float',
                size: 4
            },
            'd': {
                type: 'double',
                size: 8
            },
            'B': {
                type: 'bool',
                size: 1,
                fromNative: function (v) {
                    return v ? true : false;
                },
                toNative: function (v) {
                    return v ? 1 : 0;
                }
            },
            'v': {
                type: 'void',
                size: 0
            },
            '*': {
                type: 'pointer',
                size: pointerSize,
                fromNative: function (h) {
                    if (h.isNull()) {
                        return null;
                    }
                    return Memory.readUtf8String(h);
                }
            },
            '@': {
                type: 'pointer',
                size: pointerSize,
                fromNative: fromNativeId,
                toNative: toNativeId
            },
            '#': {
                type: 'pointer',
                size: pointerSize,
                fromNative: fromNativeId,
                toNative: toNativeId
            },
            ':': {
                type: 'pointer',
                size: pointerSize
            },
            '?': {
                type: 'pointer',
                size: pointerSize
            }
        };
    }

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
                }
            }, {
                module: "libobjc.A.dylib",
                functions: {
                    "objc_msgSend": function (address) {
                        this.objc_msgSend = address;
                    },
                    "objc_msgSendSuper": function (address) {
                        this.objc_msgSendSuper = address;
                    },
                    "objc_getClassList": ['int', ['pointer', 'int']],
                    "objc_lookUpClass": ['pointer', ['pointer']],
                    "objc_allocateClassPair": ['pointer', ['pointer', 'pointer', 'pointer']],
                    "objc_disposeClassPair": ['void', ['pointer']],
                    "objc_registerClassPair": ['void', ['pointer']],
                    "class_isMetaClass": ['bool', ['pointer']],
                    "class_getName": ['pointer', ['pointer']],
                    "class_copyProtocolList": ['pointer', ['pointer', 'pointer']],
                    "class_copyMethodList": ['pointer', ['pointer', 'pointer']],
                    "class_getClassMethod": ['pointer', ['pointer', 'pointer']],
                    "class_getInstanceMethod": ['pointer', ['pointer', 'pointer']],
                    "class_getSuperclass": ['pointer', ['pointer']],
                    "class_addProtocol": ['bool', ['pointer', 'pointer']],
                    "class_addMethod": ['bool', ['pointer', 'pointer', 'pointer', 'pointer']],
                    "objc_getProtocol": ['pointer', ['pointer']],
                    "objc_copyProtocolList": ['pointer', ['pointer']],
                    "protocol_getName": ['pointer', ['pointer']],
                    "protocol_copyMethodDescriptionList": ['pointer', ['pointer', 'bool', 'bool', 'pointer']],
                    "protocol_copyPropertyList": ['pointer', ['pointer', 'pointer']],
                    "protocol_copyProtocolList": ['pointer', ['pointer', 'pointer']],
                    "object_isClass": ['bool', ['pointer']],
                    "object_getClass": ['pointer', ['pointer']],
                    "object_getClassName": ['pointer', ['pointer']],
                    "method_getName": ['pointer', ['pointer']],
                    "method_getTypeEncoding": ['pointer', ['pointer']],
                    "method_getImplementation": ['pointer', ['pointer']],
                    "method_setImplementation": ['pointer', ['pointer', 'pointer']],
                    "property_getName": ['pointer', ['pointer']],
                    "property_copyAttributeList": ['pointer', ['pointer', 'pointer']],
                    "sel_getName": ['pointer', ['pointer']],
                    "sel_registerName": ['pointer', ['pointer']],
                    "class_getInstanceSize": ['pointer', ['pointer']]
                },
                optionals: {
                    "object_isClass": 'iOS8'
                }
            }, {
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
            const isObjCApi = api.module === 'libobjc.A.dylib';
            const functions = api.functions || {};
            const variables = api.variables || {};
            const optionals = api.optionals || {};

            remaining += Object.keys(functions).length + Object.keys(variables).length;

            const exportByName = Module
            .enumerateExportsSync(api.module)
            .reduce(function (result, exp) {
                result[exp.name] = exp;
                return result;
            }, {});

            Object.keys(functions)
            .forEach(function (name) {
                const exp = exportByName[name];
                if (exp !== undefined && exp.type === 'function') {
                    const signature = functions[name];
                    if (typeof signature === 'function') {
                        signature.call(temporaryApi, exp.address);
                        if (isObjCApi)
                            signature.call(cachedObjCApi, exp.address);
                    } else {
                        temporaryApi[name] = new NativeFunction(exp.address, signature[0], signature[1]);
                        if (isObjCApi)
                            cachedObjCApi[name] = temporaryApi[name];
                    }
                    remaining--;
                } else {
                    const optional = optionals[name];
                    if (optional)
                        remaining--;
                }
            });

            Object.keys(variables)
            .forEach(function (name) {
                const exp = exportByName[name];
                if (exp !== undefined && exp.type === 'variable') {
                    const handler = variables[name];
                    handler.call(temporaryApi, exp.address);
                    remaining--;
                }
            });
        });
        if (remaining === 0) {
            _api = temporaryApi;
        }

        return _api;
    }
}).call(this);
