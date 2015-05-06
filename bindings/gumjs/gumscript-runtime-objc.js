(function () {
    var _runtime = null;
    var _api = null;
    var pointerSize = Process.pointerSize;
    var scratchBuffer = Memory.alloc(pointerSize);

    Object.defineProperty(this, 'ObjC', {
        enumerable: true,
        get: function () {
            if (_runtime === null) {
                _runtime = new Runtime();
            }
            return _runtime;
        }
    });

    var Runtime = function Runtime() {
        var api = null;
        var classFactory = null;
        var scheduledCallbacks = [];

        var initialize = function initialize() {
            api = getApi();
            if (api !== null) {
                classFactory = new ClassFactory();
            }
        };

        Object.defineProperty(this, 'available', {
            enumerable: true,
            get: function () {
                return api !== null;
            }
        });

        Object.defineProperty(this, 'classes', {
            enumerable: true,
            get: function () {
                return classFactory.classes;
            }
        });

        Object.defineProperty(this, 'mainQueue', {
            enumerable: true,
            get: function () {
                return api._dispatch_main_q;
            }
        });

        this.schedule = function (queue, work) {
            var NSAutoreleasePool = this.use('NSAutoreleasePool');
            var workCallback = new NativeCallback(function () {
                var pool = NSAutoreleasePool.alloc().init();
                var pendingException = null;
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

        this.use = function (className) {
            return classFactory.use(className);
        };

        this.cast = function (handle, klass) {
            return classFactory.cast(handle, klass);
        };

        this.implement = function (method, fn) {
            return new NativeCallback(fn, method.returnType, method.argumentTypes);
        };

        this.refreshClasses = function () {
            classFactory.refresh();
        };

        this.selector = function (name) {
            return api.sel_registerName(Memory.allocUtf8String(name));
        };

        this.selectorAsString = function (sel) {
            return Memory.readUtf8String(api.sel_getName(sel));
        };

        initialize.call(this);
    };

    var ClassFactory = function ClassFactory() {
        var factory = this;
        var classNames = [];
        var templateByName = {};
        var classByHandle = {};
        var msgSendBySignatureId = {};
        var api = null;

        var initialize = function initialize() {
            api = getApi();
            this.refresh();
        };

        Object.defineProperty(this, 'classes', {
            enumerable: true,
            get: function () {
                return classNames;
            }
        });

        this.use = function use(className) {
            var entry = templateByName[className];
            if (!entry)
                throw new Error("Cannot find class '" + className + "'");

            if (entry[1] === null) {
                var klass = ensureClass(entry[0], className);
                entry[1] = new klass(entry[0], null);
            }

            return entry[1];
        };

        this.cast = function cast(handle, template) {
            var ch = template.classHandle;
            var klass = classByHandle[ch];
            return new klass(ch, handle);
        };

        this.refresh = function refresh() {
            var numClasses = api.objc_getClassList(NULL, 0);
            if (numClasses === classNames.length) {
                // It's impossible to unregister classes in ObjC,
                // so if the number of classes hasn't changed,
                // we can assume that the list is up to date
                return;
            }
            var rawClasses = Memory.alloc(numClasses * pointerSize);
            numClasses = api.objc_getClassList(rawClasses, numClasses);
            var iterations = 0;
            for (var i = 0; i !== numClasses; i++) {
                iterations++;
                var handle = Memory.readPointer(rawClasses.add(i * pointerSize));
                var name = Memory.readUtf8String(api.class_getName(handle));
                if (!templateByName.hasOwnProperty(name)) {
                    templateByName[name] = [handle, null];
                    classNames.push(name);
                }
            }
        };

        var ensureClass = function ensureClass(classHandle, cachedName) {
            var handleId = classHandle.toString();
            var klass = classByHandle[handleId];
            if (klass) {
                return klass;
            }

            var name = cachedName !== null ? cachedName : Memory.readUtf8String(api.class_getName(classHandle));
            var superHandle = api.class_getSuperclass(classHandle);
            var superKlass = !superHandle.isNull() ? ensureClass(superHandle, null) : null;

            eval("klass = function " + name + "(ch, handle) {" +
                (superKlass !== null
                    ? "superKlass.call(this, ch || classHandle, handle);"
                    : "this.classHandle = ch || classHandle; this.handle = handle || NULL;") +
                "initialize(ch, handle);" +
            "};");

            var initialize = function initialize(/*classHandle, handle*/) {
            };

            var initializeClass = function initializeClass() {
                klass.prototype.toString = function toString () {
                    return this.description().UTF8String();
                };

                addMethods('+');
                addMethods('-');
            };

            var addMethods = function addMethods(type) {
                var rawMethods = api.class_copyMethodList(type === '+' ? api.object_getClass(classHandle) : classHandle, scratchBuffer);
                var numMethods = Memory.readU32(scratchBuffer);
                for (var i = 0; i !== numMethods; i++) {
                    addMethod(Memory.readPointer(rawMethods.add(i * pointerSize)), type);
                }
                api.free(rawMethods);
            };

            var addMethod = function addMethod(handle, type) {
                var sel = api.method_getName(handle);
                var name = jsMethodName(Memory.readUtf8String(api.sel_getName(sel)));

                var serial = 1;
                var suffix = "";
                while (klass.prototype.hasOwnProperty(name + suffix)) {
                    serial++;
                    suffix = "" + serial;
                }
                name = name + suffix;

                var m = null;
                Object.defineProperty(klass.prototype, name, {
                    get: function () {
                        if (m === null)
                            m = makeMethod(handle, type, sel);
                        return m;
                    }
                });
            };

            var makeMethod = function (handle, type, sel) {
                var signature = parseSignature(Memory.readUtf8String(api.method_getTypeEncoding(handle)));
                var retType = signature.retType;
                var argTypes = signature.argTypes.slice(2);
                var objc_msgSend = getMsgSendImpl(signature);

                var argVariableNames = argTypes.map(function (t, i) {
                    return "a" + (i + 1);
                });
                var callArgs = [
                    type === '+' ? "this.classHandle" : "this.handle",
                    "sel"
                ].concat(argTypes.map(function (t, i) {
                    if (t.toNative) {
                        return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
                    }
                    return argVariableNames[i];
                }));
                var returnCaptureLeft;
                var returnCaptureRight;
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
                eval("var f = function (" + argVariableNames.join(", ") + ") { " +
                    returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
                " }");

                Object.defineProperty(f, 'selector', {
                    enumerable: true,
                    value: sel
                });

                var implementation = null;
                Object.defineProperty(f, 'implementation', {
                    enumerable: true,
                    get: function () {
                        return new NativeFunction(api.method_getImplementation(handle), f.returnType, f.argumentTypes);
                    },
                    set: function (imp) {
                        implementation = imp;

                        api.method_setImplementation(handle, imp);
                    }
                });

                Object.defineProperty(f, 'returnType', {
                    enumerable: true,
                    value: retType.type
                });

                Object.defineProperty(f, 'argumentTypes', {
                    enumerable: true,
                    value: signature.argTypes.map(function (t) {
                        return t.type;
                    })
                });

                return f;
            };

            // TODO: replace with regex once V8 has been upgraded (which should fix crash on iOS)
            var jsMethodName = function jsMethodName(name) {
                var result = "";
                for (var i = 0; i !== name.length; i++) {
                    var c = name.charAt(i);
                    if (c === ':') {
                        result += "_";
                    } else {
                        result += c;
                    }
                }
                return result;
            };

            var parseSignature = function parseSignature(sig) {
                var id = "";

                var t = nextType(sig);
                var retType = parseType(t[0]);
                id += retType.type;

                var argTypes = [];
                while (t[1].length > 0) {
                    t = nextType(t[1]);
                    var argType = parseType(t[0]);
                    id += argType.type;
                    argTypes.push(argType);
                }

                return {
                    id: id,
                    retType: retType,
                    argTypes: argTypes
                };
            };

            var parseType = function parseType(t) {
                var qualifiers = [];
                while (t.length > 0) {
                    var q = qualifierById[t[0]];
                    if (!q) {
                        break;
                    }
                    qualifiers.push(q);
                    t = t.substring(1);
                }
                var converter = converterById[simplifyType(t)];
                if (!converter) {
                    throw new Error("No parser for type " + t);
                }
                return converter;
            };

            var simplifyType = function simplifyType(t) {
                if (t[0] === '^') {
                    switch (t[1]) {
                        case '[':
                        case '{':
                        case '(':
                            return t.substring(0, 2) + t.substring(t.length - 1);
                    }
                }
                return t;
            };

            var nextType = function nextType(t) {
                var type = "";
                var n = 0;
                var scope = null;
                var depth = 0;
                var foundFirstDigit = false;
                while (n < t.length) {
                    var c = t[n];
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
                        var v = t.charCodeAt(n);
                        var isDigit = v >= 0x30 && v <= 0x39;
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
            };

            var qualifierById = {
                'r': 'const',
                'n': 'in',
                'N': 'inout',
                'o': 'out',
                'O': 'bycopy',
                'R': 'byref',
                'V': 'oneway'
            };

            var converterById = {
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
                    fromNative: function (h) {
                        if (h.isNull()) {
                            return null;
                        } else if (h.toString(16) === this.handle.toString(16)) {
                            return this;
                        } else {
                            var kh = api.object_getClass(h);
                            var k = ensureClass(kh, null);
                            return new k(kh, h);
                        }
                    },
                    toNative: function (v) {
                        if (typeof v === 'string') {
                            return factory.use('NSString').stringWithUTF8String_(Memory.allocUtf8String(v)).handle;
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
                },
            };

            if (superKlass !== null) {
                var Surrogate = function () {
                    this.constructor = klass;
                };
                Surrogate.prototype = superKlass.prototype;
                klass.prototype = new Surrogate();

                klass.__name__ = name;
                klass.__super__ = superKlass.prototype;
            }

            initializeClass();

            classByHandle[handleId] = klass;

            return klass;
        };

        var getMsgSendImpl = function getMsgSendImpl(signature) {
            var impl = msgSendBySignatureId[signature.id];
            if (!impl) {
                var argTypes = [];
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
        };

        initialize.call(this);
    };

    var getApi = function () {
        if (_api !== null) {
            return _api;
        }

        var temporaryApi = {};
        var pending = [
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
                    "class_getName": ['pointer', ['pointer']],
                    "class_copyMethodList": ['pointer', ['pointer', 'pointer']],
                    "class_getSuperclass": ['pointer', ['pointer']],
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
        var remaining = 0;
        pending.forEach(function (api) {
            var pendingFunctions = api.functions;
            var pendingVariables = api.variables;
            remaining += Object.keys(pendingFunctions).length + Object.keys(pendingVariables).length;
            Module.enumerateExports(api.module, {
                onMatch: function (exp) {
                    var name = exp.name;
                    if (exp.type === 'function') {
                        var signature = pendingFunctions[name];
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
                        var handler = pendingVariables[name];
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
    };
}).call(this);
