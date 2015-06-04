(function () {
    "use strict";

    let _runtime = null;
    let _api = null;
    const pointerSize = Process.pointerSize;
    const msgSendBySignatureId = {};
    const msgSendSuperBySignatureId = {};

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
        const classRegistry = new ClassRegistry();
        const protocolRegistry = new ProtocolRegistry();
        const scheduledCallbacks = [];
        const bindings = {};

        Object.defineProperty(this, 'available', {
            enumerable: true,
            get: function () {
                return api !== null;
            }
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
                return new ObjCObject(handle, true);
            }

            function toJSON() {
                return {};
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
                return {};
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
            "$protocols": true
        };

        function ObjCObject(handle, cachedIsClass, superSpecifier) {
            let cachedClassHandle = null;
            let cachedProtocols = null;
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
                        case "valueOf":
                            const description = target.description();
                            return description.UTF8String.bind(description);
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
                                            const protocol = new ObjCProtocol(protocolHandle);
                                            cachedProtocols[protocol.name] = protocol;
                                        }
                                    } finally {
                                        api.free(protocolHandles);
                                    }
                                }
                            }
                            return cachedProtocols;
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
                            const numMethodsBuf = Memory.alloc(pointerSize);
                            const methodHandles = api.class_copyMethodList(cur, numMethodsBuf);
                            try {
                                const numMethods = Memory.readUInt(numMethodsBuf);
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
            }, Object.getPrototypeOf(this));

            function classHandle() {
                if (cachedClassHandle === null)
                    cachedClassHandle = isClass() ? handle : api.object_getClass(handle);
                return cachedClassHandle;
            }

            function isClass() {
                if (cachedIsClass === undefined)
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
                wrapper = makeMethodInvocationWrapper(methodHandle, sel, superSpecifier);

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
                name = makeClassName;
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

        function bind(obj, data) {
            const handle = (obj instanceof NativePointer) ? obj : obj.handle;
            const self = new ObjCObject(handle);
            bindings[handle.toString()] = {
                self: self,
                super: new ObjCObject(handle, undefined, makeSuperSpecifier(self)),
                data: data
            };
        }

        function unbind(obj) {
            const handle = (obj instanceof NativePointer) ? obj : obj.handle;
            delete bindings[handle.toString()];
        }

        function getBoundData(obj) {
            return getBinding(obj).data;
        }

        function getBinding(obj) {
            const handle = (obj instanceof NativePointer) ? obj : obj.handle;
            const key = handle.toString();
            let binding = bindings[key];
            if (binding === undefined) {
                const self = new ObjCObject(handle);
                binding = {
                    self: self,
                    super: new ObjCObject(handle, undefined, makeSuperSpecifier(self)),
                    data: {}
                };
                bindings[key] = binding;
            }
            return binding;
        }

        function makeMethodInvocationWrapper(handle, sel, superSpecifier) {
            const types = Memory.readUtf8String(api.method_getTypeEncoding(handle));
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

            Object.defineProperty(m, 'types', {
                enumerable: true,
                value: types
            });

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

        function makeSuperSpecifier(obj) {
            const specifier = Memory.alloc(2 * pointerSize);
            Memory.writePointer(specifier, obj.handle);
            Memory.writePointer(specifier.add(pointerSize), obj.superclass().handle);
            return specifier;
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
            return name.replace(/:/g, "_");
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
            return unparseType(retType) + frameSize + argTypes.map(function (argType, i) {
                const frameOffset = (i * pointerSize);
                return unparseType(argType) + frameOffset;
            }).join("");
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

        function unparseType(t) {
            const id = idByType[t];
            if (id === undefined)
                throw new Error("No known encoding for type " + t);
            return id;
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
                return registry.NSString.stringWithUTF8String_(Memory.allocUtf8String(v));
            }
            return v;
        };

        const idByType = {
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

        const converterById = {
            'c': {
                type: 'char',
                toNative: function (v) {
                    if (typeof v === 'boolean') {
                        return v ? 1 : 0;
                    }
                    return v;
                }
            },
            'i': {
                type: 'int'
            },
            's': {
                type: 'int16'
            },
            'l': {
                type: 'int32'
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
            'L': {
                type: 'uint32'
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
            'B': {
                type: 'bool',
                fromNative: function (v) {
                    return v ? true : false;
                },
                toNative: function (v) {
                    return v ? 1 : 0;
                }
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
                fromNative: fromNativeId,
                toNative: toNativeId
            },
            '@?': {
                type: 'pointer'
            },
            '#': {
                type: 'pointer',
                fromNative: fromNativeId,
                toNative: toNativeId
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
                },
                variables: {
                }
            },
            {
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
                    "method_getName": ['pointer', ['pointer']],
                    "method_getTypeEncoding": ['pointer', ['pointer']],
                    "method_getImplementation": ['pointer', ['pointer']],
                    "method_setImplementation": ['pointer', ['pointer', 'pointer']],
                    "property_getName": ['pointer', ['pointer']],
                    "property_copyAttributeList": ['pointer', ['pointer', 'pointer']],
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
