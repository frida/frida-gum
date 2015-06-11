(function () {
    "use strict";

    var _runtime = null;
    var _api = null;
    var pointerSize = Process.pointerSize;
    var JNI_OK = 0;
    var JNI_VERSION_1_6 = 0x00010006;

    var CONSTRUCTOR_METHOD = 1;
    var STATIC_METHOD = 2;
    var INSTANCE_METHOD = 3;

    // TODO: 64-bit
    var JNI_ENV_OFFSET_SELF = 12;

    var CLASS_OBJECT_SIZE = 160;
    var CLASS_OBJECT_OFFSET_VTABLE_COUNT = 112;
    var CLASS_OBJECT_OFFSET_VTABLE = 116;

    var OBJECT_OFFSET_CLAZZ = 0;

    var METHOD_SIZE = 56;
    var METHOD_OFFSET_CLAZZ = 0;
    var METHOD_OFFSET_ACCESS_FLAGS = 4;
    var METHOD_OFFSET_METHOD_INDEX = 8;
    var METHOD_OFFSET_REGISTERS_SIZE = 10;
    var METHOD_OFFSET_OUTS_SIZE = 12;
    var METHOD_OFFSET_INS_SIZE = 14;
    var METHOD_OFFSET_INSNS = 32;
    var METHOD_OFFSET_JNI_ARG_INFO = 36;

    Object.defineProperty(this, 'Dalvik', {
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
        var vm = null;
        var classFactory = null;
        var pending = [];

        var initialize = function () {
            api = getApi();
            if (api !== null) {
                vm = new VM(api);
                classFactory = new ClassFactory(api, vm);
            }
        };

        WeakRef.bind(Runtime, function dispose() {
            if (api !== null) {
                vm.perform(function () {
                    var env = vm.getEnv();
                    classFactory.dispose(env);
                    Env.dispose(env);
                });
            }
        });

        Object.defineProperty(this, 'available', {
            enumerable: true,
            get: function () {
                return api !== null;
            }
        });

        function _enumerateLoadedClasses(callbacks, onlyDescription) {
            if (Dalvik.available) {
                const hash_tombstone = 0xcbcacccd;
                const loadedClassesOffset = 172;
                const hashEntrySize = 8;
                const ptrLoadedClassesHashtable = api.gDvm.add(loadedClassesOffset);
                const hashTable = Memory.readPointer(ptrLoadedClassesHashtable);
                const tableSize = Memory.readS32(hashTable);
                const ptrpEntries = hashTable.add(12);
                const pEntries = Memory.readPointer(ptrpEntries);
                const end = tableSize * hashEntrySize;

                for (let offset = 0; offset < end; offset += hashEntrySize) {
                    let pEntriePtr = pEntries.add(offset);
                    let hashValue = Memory.readS32(pEntriePtr);
                    if (hashValue !== 0) {
                        let dataPtr = Memory.readPointer(pEntriePtr.add(4));
                        if (dataPtr !== hash_tombstone) {
                            let descriptionPtr = Memory.readPointer(dataPtr.add(24));
                            let description = Memory.readCString(descriptionPtr);
                            if (onlyDescription) {
                                callbacks.onMatch(description);
                            } else {
                                let objectSize = Memory.readU32(dataPtr.add(56));
                                let sourceFile = Memory.readCString(Memory.readPointer(dataPtr.add(152)));
                                callbacks.onMatch({
                                    pointer: pEntriePtr,
                                    objectSize: objectSize,
                                    sourceFile: sourceFile,
                                    description: description
                                });
                            }
                        }
                    }
                }
                callbacks.onComplete();
            } else {
                throw new Error("Dalvik API not available");
            }
        }

        Object.defineProperty(this, 'enumerateLoadedClassesSync', {
            enumerable: true,
            value: function () {
                if (api !== null) {
                    let classes = [];
                    Dalvik.enumerateLoadedClasses({
                        onMatch: function (c) {
                            classes.push(c);
                        },
                        onComplete: function () {
                        }
                    });
                    return classes;
                } else {
                    throw new Error("Dalvik API not available");
                }
            }
        });

        Object.defineProperty(this, 'enumerateLoadedClasses', {
            enumerable: true,
            value: function(callbacks) {
                _enumerateLoadedClasses(callbacks, true);
            }
        });

        this.perform = function (fn) {
            if (api === null) {
                throw new Error("Dalvik runtime not available");
            }

            if (classFactory.loader !== null) {
                vm.perform(fn);
            } else {
                pending.push(fn);
                if (pending.length === 1) {
                    vm.perform(function () {
                        var ActivityThread = classFactory.use("android.app.ActivityThread");
                        var Handler = classFactory.use("android.os.Handler");
                        var Looper = classFactory.use("android.os.Looper");

                        var looper = Looper.getMainLooper();
                        var handler = Handler.$new.overload("android.os.Looper").call(Handler, looper);
                        var message = handler.obtainMessage();
                        Handler.dispatchMessage.implementation = function (msg) {
                            var sameHandler = this.$isSameObject(handler);
                            if (sameHandler) {
                                var app = ActivityThread.currentApplication();
                                if (app !== null) {
                                    Handler.dispatchMessage.implementation = null;
                                    var loader = app.getClassLoader();
                                    setTimeout(function () {
                                        classFactory.loader = loader;
                                        pending.forEach(vm.perform, vm);
                                        pending = null;
                                    }, 0);
                                }
                            } else {
                                this.dispatchMessage(msg);
                            }
                        };
                        message.sendToTarget();
                    });
                }
            }
        };

        this.use = function (className) {
            if (classFactory.loader === null) {
                throw new Error("Not allowed outside Dalvik.perform() callback");
            }
            return classFactory.use(className);
        };

        this.cast = function (obj, C) {
            return classFactory.cast(obj, C);
        };

        this.getObjectClassname = function (obj) {
            return classFactory.getObjectClassname(obj);
        };

        initialize.call(this);
    };

    var ClassFactory = function ClassFactory(api, vm) {
        var factory = this;
        var classes = {};
        var patchedClasses = {};
        var loader = null;

        var initialize = function () {
            api = getApi();
        };

        this.dispose = function (env) {
            for (var entryId in patchedClasses) {
                if (patchedClasses.hasOwnProperty(entryId)) {
                    var entry = patchedClasses[entryId];
                    Memory.writePointer(entry.vtablePtr, entry.vtable);
                    Memory.writeS32(entry.vtableCountPtr, entry.vtableCount);

                    for (var methodId in entry.targetMethods) {
                        if (entry.targetMethods.hasOwnProperty(methodId)) {
                            entry.targetMethods[methodId].implementation = null;
                        }
                    }
                }
            }
            patchedClasses = {};

            for (var classId in classes) {
                if (classes.hasOwnProperty(classId)) {
                    var klass = classes[classId];
                    klass.__methods__.forEach(env.deleteGlobalRef, env);
                    env.deleteGlobalRef(klass.__handle__);
                }
            }
            classes = {};
        };

        Object.defineProperty(this, 'loader', {
            enumerable: true,
            get: function () {
                return loader;
            },
            set: function (value) {
                loader = value;
            }
        });

        this.use = function (className) {
            var C = classes[className];
            if (!C) {
                var env = vm.getEnv();
                if (loader !== null) {
                    var klassObj = loader.loadClass(className);
                    C = ensureClass(klassObj.$handle, className);
                } else {
                    var handle = env.findClass(className.replace(/\./g, "/"));
                    try {
                        C = ensureClass(handle, className);
                    } finally {
                        env.deleteLocalRef(handle);
                    }
                }
            }
            return new C(C.__handle__, null);
        };

        this.cast = function (obj, klass) {
            var handle = obj.hasOwnProperty('$handle') ? obj.$handle : obj;
            var C = klass.$classWrapper;
            return new C(C.__handle__, handle);
        };

        this.getObjectClassname = function (obj) {
            let handle = obj.hasOwnProperty('$handle') ? obj.$handle : obj;
            if (handle instanceof NativePointer) {
                let env = vm.getEnv();
                let invokeObjectMethodNoArgs = env.method('pointer', []);

                let jklass = env.getObjectClass(handle);
                let stringObj = invokeObjectMethodNoArgs(env.handle, jklass, env.javaLangClass().getName);
                let clsStr = env.stringFromJni(stringObj);
                
                env.deleteLocalRef(stringObj);
                env.deleteLocalRef(jklass);
                return clsStr;
            } else {
                throw new Error('Not a pointer and also not a class instance.');
            }
        };

        var ensureClass = function (classHandle, cachedName) {
            var env = vm.getEnv();

            var name = cachedName !== null ? cachedName : env.getClassName(classHandle);
            var klass = classes[name];
            if (klass) {
                return klass;
            }

            var superHandle = env.getSuperclass(classHandle);
            var superKlass;
            if (!superHandle.isNull()) {
                superKlass = ensureClass(superHandle, null);
                env.deleteLocalRef(superHandle);
            } else {
                superKlass = null;
            }

            eval("klass = function " + basename(name) + "(classHandle, handle) {" +
                 "var env = vm.getEnv();" +
                 "this.$classWrapper = klass;" +
                 "this.$classHandle = env.newGlobalRef(classHandle);" +
                 "this.$handle = (handle !== null) ? env.newGlobalRef(handle) : null;" +
                 "this.$weakRef = WeakRef.bind(this, makeHandleDestructor(this.$handle, this.$classHandle));" +
            "};");

            classes[name] = klass;

            var initializeClass = function initializeClass() {
                klass.__name__ = name;
                klass.__handle__ = env.newGlobalRef(classHandle);
                klass.__methods__ = [];

                var ctor = null;
                Object.defineProperty(klass.prototype, "$new", {
                    get: function () {
                        if (ctor === null) {
                            vm.perform(function () {
                                ctor = makeConstructor(klass.__handle__, vm.getEnv());
                            });
                        }
                        return ctor;
                    }
                });
                klass.prototype.$dispose = dispose;

                klass.prototype.$isSameObject = function (obj) {
                    var env = vm.getEnv();
                    return env.isSameObject(obj.$handle, this.$handle);
                };

                Object.defineProperty(klass.prototype, 'class', {
                    get: function () {
                        var Clazz = factory.use("java.lang.Class");
                        return factory.cast(this.$classHandle, Clazz);
                    }
                });

                addMethods();
            };

            var dispose = function () {
                WeakRef.unbind(this.$weakRef);
            };

            var makeConstructor = function (classHandle, env) {
                var Constructor = env.javaLangReflectConstructor();
                var invokeObjectMethodNoArgs = env.method('pointer', []);

                var jsMethods = [];
                var jsRetType = objectType(name, false);
                var constructors = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredConstructors);
                var numConstructors = env.getArrayLength(constructors);
                for (var constructorIndex = 0; constructorIndex !== numConstructors; constructorIndex++) {
                    var constructor = env.getObjectArrayElement(constructors, constructorIndex);

                    var methodId = env.fromReflectedMethod(constructor);
                    var jsArgTypes = [];

                    var types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
                    env.deleteLocalRef(constructor);
                    var numTypes = env.getArrayLength(types);
                    try {
                        for (var typeIndex = 0; typeIndex !== numTypes; typeIndex++) {
                            var t = env.getObjectArrayElement(types, typeIndex);
                            try {
                                var argType = typeFromClassName(env.getTypeName(t));
                                jsArgTypes.push(argType);
                            } finally {
                                env.deleteLocalRef(t);
                            }
                        }
                    } catch (e) {
                        continue;
                    } finally {
                        env.deleteLocalRef(types);
                    }

                    jsMethods.push(makeMethod(CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
                }
                env.deleteLocalRef(constructors);

                if (jsMethods.length === 0)
                    throw new Error("no supported overloads");

                return makeMethodDispatcher("<init>", jsMethods);
            };

            var addMethods = function () {
                var invokeObjectMethodNoArgs = env.method('pointer', []);
                var Method_getName = env.javaLangReflectMethod().getName;

                var methodHandles = klass.__methods__;
                var jsMethods = {};

                var methods = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredMethods);
                var numMethods = env.getArrayLength(methods);
                for (var methodIndex = 0; methodIndex !== numMethods; methodIndex++) {
                    var method = env.getObjectArrayElement(methods, methodIndex);
                    var name = invokeObjectMethodNoArgs(env.handle, method, Method_getName);
                    var jsName = env.stringFromJni(name);
                    env.deleteLocalRef(name);
                    var methodHandle = env.newGlobalRef(method);
                    methodHandles.push(methodHandle);
                    env.deleteLocalRef(method);

                    var jsOverloads;
                    if (jsMethods.hasOwnProperty(jsName)) {
                        jsOverloads = jsMethods[jsName];
                    } else {
                        jsOverloads = [];
                        jsMethods[jsName] = jsOverloads;
                    }
                    jsOverloads.push(methodHandle);
                }

                Object.keys(jsMethods).forEach(function (name) {
                    var m = null;
                    Object.defineProperty(klass.prototype, name, {
                        get: function () {
                            if (m === null) {
                                vm.perform(function () {
                                    m = makeMethodFromOverloads(name, jsMethods[name], vm.getEnv());
                                });
                            }
                            return m;
                        }
                    });
                });
            };

            var makeMethodFromOverloads = function (name, overloads, env) {
                var Method = env.javaLangReflectMethod();
                var Modifier = env.javaLangReflectModifier();
                var invokeObjectMethodNoArgs = env.method('pointer', []);
                var invokeIntMethodNoArgs = env.method('int32', []);
                var invokeUInt8MethodNoArgs = env.method('uint8', []);

                var methods = overloads.map(function (handle) {
                    var methodId = env.fromReflectedMethod(handle);
                    var retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
                    var argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericParameterTypes);
                    var modifiers = invokeIntMethodNoArgs(env.handle, handle, Method.getModifiers);
                    var isVarArgs = invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs) ? true : false;

                    var jsType = (modifiers & Modifier.STATIC) !== 0 ? STATIC_METHOD : INSTANCE_METHOD;

                    var jsRetType;
                    var jsArgTypes = [];

                    try {
                        jsRetType = typeFromClassName(env.getTypeName(retType));
                    } catch (e) {
                        env.deleteLocalRef(argTypes);
                        return null;
                    } finally {
                        env.deleteLocalRef(retType);
                    }

                    try {
                        var numArgTypes = env.getArrayLength(argTypes);
                        for (var argTypeIndex = 0; argTypeIndex !== numArgTypes; argTypeIndex++) {
                            var t = env.getObjectArrayElement(argTypes, argTypeIndex);
                            try {
                                var argClassName = (isVarArgs && argTypeIndex === numArgTypes - 1) ? env.getArrayTypeName(t) : env.getTypeName(t);
                                var argType = typeFromClassName(argClassName);
                                jsArgTypes.push(argType);
                            } finally {
                                env.deleteLocalRef(t);
                            }
                        }
                    } catch (e) {
                        return null;
                    } finally {
                        env.deleteLocalRef(argTypes);
                    }

                    return makeMethod(jsType, methodId, jsRetType, jsArgTypes, env);
                }).filter(function (m) {
                    return m !== null;
                });

                if (methods.length === 0)
                    throw new Error("no supported overloads");

                if (name === "valueOf") {
                    var hasDefaultValueOf = methods.some(function implementsDefaultValueOf(m) {
                        return m.type === INSTANCE_METHOD && m.argumentTypes.length === 0;
                    });
                    if (!hasDefaultValueOf) {
                        var defaultValueOf = function defaultValueOf() {
                            return this;
                        };

                        Object.defineProperty(defaultValueOf, 'holder', {
                            enumerable: true,
                            value: klass
                        });

                        Object.defineProperty(defaultValueOf, 'type', {
                            enumerable: true,
                            value: INSTANCE_METHOD
                        });

                        Object.defineProperty(defaultValueOf, 'returnType', {
                            enumerable: true,
                            value: typeFromClassName('int')
                        });

                        Object.defineProperty(defaultValueOf, 'argumentTypes', {
                            enumerable: true,
                            value: []
                        });

                        Object.defineProperty(defaultValueOf, 'canInvokeWith', {
                            enumerable: true,
                            value: function (args) {
                                return args.length === 0;
                            }
                        });

                        methods.push(defaultValueOf);
                    }
                }

                return makeMethodDispatcher(name, methods);
            };

            var makeMethodDispatcher = function (name, methods) {
                var candidates = {};
                methods.forEach(function (m) {
                    var numArgs = m.argumentTypes.length;
                    var group = candidates[numArgs];
                    if (!group) {
                        group = [];
                        candidates[numArgs] = group;
                    }
                    group.push(m);
                });

                var f = function () {
                    var isInstance = this.$handle !== null;
                    if (methods[0].type !== INSTANCE_METHOD && isInstance) {
                        throw new Error(name + ": cannot call static method by way of an instance");
                    } else if (methods[0].type === INSTANCE_METHOD && !isInstance) {
                        if (name === 'toString') {
                            return "<" + this.$classWrapper.__name__ + ">";
                        }
                        throw new Error(name + ": cannot call instance method without an instance");
                    }
                    var group = candidates[arguments.length];
                    if (!group) {
                        throw new Error(name + ": argument count does not match any overload");
                    }
                    for (var i = 0; i !== group.length; i++) {
                        var method = group[i];
                        if (method.canInvokeWith(arguments)) {
                            return method.apply(this, arguments);
                        }
                    }
                    throw new Error(name + ": argument types do not match any overload");
                };

                Object.defineProperty(f, 'overloads', {
                    enumerable: true,
                    value: methods
                });

                Object.defineProperty(f, 'overload', {
                    enumerable: true,
                    value: function () {
                        var group = candidates[arguments.length];
                        if (!group) {
                            throw new Error(name + ": argument count does not match any overload");
                        }

                        var signature = Array.prototype.join.call(arguments, ":");
                        for (var i = 0; i !== group.length; i++) {
                            var method = group[i];
                            var s = method.argumentTypes.map(function (t) { return t.className; }).join(":");
                            if (s === signature) {
                                return method;
                            }
                        }
                        throw new Error(name + ": specified argument types do not match any overload");
                    }
                });

                Object.defineProperty(f, 'holder', {
                    enumerable: true,
                    get: methods[0].holder
                });

                Object.defineProperty(f, 'type', {
                    enumerable: true,
                    value: methods[0].type
                });

                if (methods.length === 1) {
                    Object.defineProperty(f, 'implementation', {
                        enumerable: true,
                        get: function () {
                            return methods[0].implementation;
                        },
                        set: function (imp) {
                            methods[0].implementation = imp;
                        }
                    });

                    Object.defineProperty(f, 'returnType', {
                        enumerable: true,
                        value: methods[0].returnType
                    });

                    Object.defineProperty(f, 'argumentTypes', {
                        enumerable: true,
                        value: methods[0].argumentTypes
                    });

                    Object.defineProperty(f, 'canInvokeWith', {
                        enumerable: true,
                        value: methods[0].canInvokeWith
                    });
                } else {
                    var throwAmbiguousError = function () {
                        throw new Error("Method has more than one overload. Please resolve by for example: `method.overload('int')`");
                    };

                    Object.defineProperty(f, 'implementation', {
                        enumerable: true,
                        get: throwAmbiguousError,
                        set: throwAmbiguousError
                    });

                    Object.defineProperty(f, 'returnType', {
                        enumerable: true,
                        get: throwAmbiguousError
                    });

                    Object.defineProperty(f, 'argumentTypes', {
                        enumerable: true,
                        get: throwAmbiguousError
                    });

                    Object.defineProperty(f, 'canInvokeWith', {
                        enumerable: true,
                        get: throwAmbiguousError
                    });
                }

                return f;
            };

            var makeMethod = function (type, methodId, retType, argTypes, env) {
                var targetMethodId = methodId;
                var originalMethodId = null;

                var rawRetType = retType.type;
                var rawArgTypes = argTypes.map(function (t) { return t.type; });
                var invokeTarget;
                if (type == CONSTRUCTOR_METHOD) {
                    invokeTarget = env.constructor(rawArgTypes);
                } else if (type == STATIC_METHOD) {
                    invokeTarget = env.staticMethod(rawRetType, rawArgTypes);
                } else if (type == INSTANCE_METHOD) {
                    invokeTarget = env.method(rawRetType, rawArgTypes);
                }

                var frameCapacity = 2;
                var argVariableNames = argTypes.map(function (t, i) {
                    return "a" + (i + 1);
                });
                var callArgs = [
                    "env.handle",
                    type === INSTANCE_METHOD ? "this.$handle" : "this.$classHandle",
                    "targetMethodId"
                ].concat(argTypes.map(function (t, i) {
                    if (t.toJni) {
                        frameCapacity++;
                        return "argTypes[" + i + "].toJni.call(this, " + argVariableNames[i] + ", env)";
                    }
                    return argVariableNames[i];
                }));
                var returnCapture, returnStatements;
                if (rawRetType === 'void') {
                    returnCapture = "";
                    returnStatements = "env.popLocalFrame(NULL);";
                } else {
                    if (retType.fromJni) {
                        frameCapacity++;
                        returnCapture = "var rawResult = ";
                        returnStatements = "var result = retType.fromJni.call(this, rawResult, env);" +
                            "env.popLocalFrame(NULL);" +
                            "return result;";
                    } else {
                        returnCapture = "var result = ";
                        returnStatements = "env.popLocalFrame(NULL);" +
                            "return result;";
                    }
                }
                let f;
                eval("f = function (" + argVariableNames.join(", ") + ") {" +
                    "var env = vm.getEnv();" +
                    "if (env.pushLocalFrame(" + frameCapacity + ") !== JNI_OK) {" +
                        "env.exceptionClear();" +
                        "throw new Error(\"Out of memory\");" +
                    "}" +
                    "try {" +
                        "synchronizeVtable.call(this, env, type === INSTANCE_METHOD);" +
                        returnCapture + "invokeTarget(" + callArgs.join(", ") + ");" +
                    "} catch (e) {" +
                        "env.popLocalFrame(NULL);" +
                        "throw e;" +
                    "}" +
                    "var throwable = env.exceptionOccurred();" +
                    "if (!throwable.isNull()) {" +
                        "env.exceptionClear();" +
                        "var description = env.method('pointer', [])(env.handle, throwable, env.javaLangObject().toString);" +
                        "var descriptionStr = env.stringFromJni(description);" +
                        "env.popLocalFrame(NULL);" +
                        "throw new Error(descriptionStr);" +
                    "}" +
                    returnStatements +
                "}");

                Object.defineProperty(f, 'holder', {
                    enumerable: true,
                    value: klass
                });

                Object.defineProperty(f, 'type', {
                    enumerable: true,
                    value: type
                });

                var implementation = null;
                var synchronizeVtable = function (env, instance) {
                    if (originalMethodId === null) {
                        return; // nothing to do – implementation hasn't been replaced
                    }

                    var thread = Memory.readPointer(env.handle.add(JNI_ENV_OFFSET_SELF));
                    var objectPtr = api.dvmDecodeIndirectRef(thread, instance ? this.$handle : this.$classHandle);
                    let classObject;
                    if (instance) {
                        classObject = Memory.readPointer(objectPtr.add(OBJECT_OFFSET_CLAZZ));
                    } else {
                        classObject = objectPtr;
                    }
                    var key = classObject.toString(16);
                    var entry = patchedClasses[key];
                    if (!entry) {
                        var vtablePtr = classObject.add(CLASS_OBJECT_OFFSET_VTABLE);
                        var vtableCountPtr = classObject.add(CLASS_OBJECT_OFFSET_VTABLE_COUNT);
                        var vtable = Memory.readPointer(vtablePtr);
                        var vtableCount = Memory.readS32(vtableCountPtr);

                        var vtableSize = vtableCount * pointerSize;
                        var shadowVtable = Memory.alloc(2 * vtableSize);
                        Memory.copy(shadowVtable, vtable, vtableSize);
                        Memory.writePointer(vtablePtr, shadowVtable);

                        entry = {
                            classObject: classObject,
                            vtablePtr: vtablePtr,
                            vtableCountPtr: vtableCountPtr,
                            vtable: vtable,
                            vtableCount: vtableCount,
                            shadowVtable: shadowVtable,
                            shadowVtableCount: vtableCount,
                            targetMethods: {}
                        };
                        patchedClasses[key] = entry;
                    }

                    key = methodId.toString(16);
                    var method = entry.targetMethods[key];
                    if (!method) {
                        var methodIndex = entry.shadowVtableCount++;
                        Memory.writePointer(entry.shadowVtable.add(methodIndex * pointerSize), targetMethodId);
                        Memory.writeU16(targetMethodId.add(METHOD_OFFSET_METHOD_INDEX), methodIndex);
                        Memory.writeS32(entry.vtableCountPtr, entry.shadowVtableCount);

                        entry.targetMethods[key] = f;
                    }
                };
                Object.defineProperty(f, 'implementation', {
                    enumerable: true,
                    get: function () {
                        return implementation;
                    },
                    set: function (fn) {
                        if (fn === null && originalMethodId === null) {
                            return;
                        }

                        if (originalMethodId === null) {
                            originalMethodId = Memory.dup(methodId, METHOD_SIZE);
                            targetMethodId = Memory.dup(methodId, METHOD_SIZE);
                        }

                        if (fn !== null) {
                            implementation = implement(f, fn);

                            var argsSize = argTypes.reduce(function (acc, t) { return acc + t.size; }, 0);
                            if (type === INSTANCE_METHOD) {
                                argsSize++;
                            }

                            var accessFlags = Memory.readU32(methodId.add(METHOD_OFFSET_ACCESS_FLAGS)) | 0x0100;
                            var registersSize = argsSize;
                            var outsSize = 0;
                            var insSize = argsSize;
                            var jniArgInfo = 0x80000000;

                            Memory.writeU32(methodId.add(METHOD_OFFSET_ACCESS_FLAGS), accessFlags);
                            Memory.writeU16(methodId.add(METHOD_OFFSET_REGISTERS_SIZE), registersSize);
                            Memory.writeU16(methodId.add(METHOD_OFFSET_OUTS_SIZE), outsSize);
                            Memory.writeU16(methodId.add(METHOD_OFFSET_INS_SIZE), insSize);
                            Memory.writeU32(methodId.add(METHOD_OFFSET_JNI_ARG_INFO), jniArgInfo);

                            api.dvmUseJNIBridge(methodId, implementation);
                        } else {
                            Memory.copy(methodId, originalMethodId, METHOD_SIZE);
                        }
                    }
                });

                Object.defineProperty(f, 'returnType', {
                    enumerable: true,
                    value: retType
                });

                Object.defineProperty(f, 'argumentTypes', {
                    enumerable: true,
                    value: argTypes
                });

                Object.defineProperty(f, 'canInvokeWith', {
                    enumerable: true,
                    value: function (args) {
                        if (args.length !== argTypes.length) {
                            return false;
                        }

                        return argTypes.every(function (t, i) {
                            return t.isCompatible(args[i]);
                        });
                    }
                });

                return f;
            };

            if (superKlass !== null) {
                var Surrogate = function () {
                    this.constructor = klass;
                };
                Surrogate.prototype = superKlass.prototype;
                klass.prototype = new Surrogate();

                klass.__super__ = superKlass.prototype;
            } else {
                klass.__super__ = null;
            }

            initializeClass();

            // Guard against use-after-"free"
            classHandle = null;
            env = null;

            return klass;
        };

        var makeHandleDestructor = function () {
            var handles = Array.prototype.slice.call(arguments).filter(function (h) { return h !== null; });
            return function () {
                vm.perform(function () {
                    var env = vm.getEnv();
                    handles.forEach(env.deleteGlobalRef, env);
                });
            };
        };

        var implement = function (method, fn) {
            var env = vm.getEnv();

            if (method.hasOwnProperty('overloads')) {
                if (method.overloads.length > 1) {
                    throw new Error("Method has more than one overload. Please resolve by for example: `method.overload('int')`");
                }
                method = method.overloads[0];
            }

            var C = method.holder;
            var type = method.type;
            var retType = method.returnType;
            var argTypes = method.argumentTypes;
            var rawRetType = retType.type;
            var rawArgTypes = argTypes.map(function (t) { return t.type; });

            var frameCapacity = 2;
            var argVariableNames = argTypes.map(function (t, i) {
                return "a" + (i + 1);
            });
            var callArgs = argTypes.map(function (t, i) {
                if (t.fromJni) {
                    frameCapacity++;
                    return "argTypes[" + i + "].fromJni.call(self, " + argVariableNames[i] + ", env)";
                }
                return argVariableNames[i];
            });
            var returnCapture, returnStatements, returnNothing;
            if (rawRetType === 'void') {
                returnCapture = "";
                returnStatements = "env.popLocalFrame(NULL);";
                returnNothing = "return;";
            } else {
                if (retType.toJni) {
                    frameCapacity++;
                    returnCapture = "var result = ";
                    if (retType.type === 'pointer') {
                        returnStatements = "var rawResult = retType.toJni.call(this, result, env);" +
                            "return env.popLocalFrame(rawResult);";
                        returnNothing = "return NULL;";
                    } else {
                        returnStatements = "var rawResult = retType.toJni.call(this, result, env);" +
                            "env.popLocalFrame(NULL);" +
                            "return rawResult;";
                        returnNothing = "return 0;";
                    }
                } else {
                    returnCapture = "var result = ";
                    returnStatements = "env.popLocalFrame(NULL);" +
                        "return result;";
                    returnNothing = "return 0;";
                }
            }
            let f;
            eval("f = function (" + ["envHandle", "thisHandle"].concat(argVariableNames).join(", ") + ") {" +
                "var env = new Env(envHandle);" +
                "if (env.pushLocalFrame(" + frameCapacity + ") !== JNI_OK) {" +
                    "return;" +
                "}" +
                ((type === INSTANCE_METHOD) ? "var self = new C(C.__handle__, thisHandle);" : "var self = new C(thisHandle, null);") +
                "try {" +
                    returnCapture + "fn.call(" + ["self"].concat(callArgs).join(", ") + ");" +
                "} catch (e) {" +
                    "if (typeof e === 'object' && e.hasOwnProperty('$handle')) {" +
                        "env.throw(e.$handle);" +
                        returnNothing +
                    "} else {" +
                        "throw e;" +
                    "}" +
                "}" +
                returnStatements +
            "}");

            Object.defineProperty(f, 'type', {
                enumerable: true,
                value: type
            });

            Object.defineProperty(f, 'returnType', {
                enumerable: true,
                value: retType
            });

            Object.defineProperty(f, 'argumentTypes', {
                enumerable: true,
                value: argTypes
            });

            Object.defineProperty(f, 'canInvokeWith', {
                enumerable: true,
                value: function (args) {
                    if (args.length !== argTypes.length) {
                        return false;
                    }

                    return argTypes.every(function (t, i) {
                        return t.isCompatible(args[i]);
                    });
                }
            });

            return new NativeCallback(f, rawRetType, ['pointer', 'pointer'].concat(rawArgTypes));
        };

        var typeFromClassName = function (className) {
            var type = types[className];
            if (!type) {
                if (className.indexOf("[") === 0) {
                    type = arrayType(className.substring(1));
                } else {
                    type = objectType(className, true);
                }
            }

            var result = {
                className: className
            };
            for (var key in type) {
                if (type.hasOwnProperty(key)) {
                    result[key] = type[key];
                }
            }
            return result;
        };

        var types = {
            'boolean': {
                type: 'uint8',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'boolean';
                },
                fromJni: function (v) {
                    return v ? true : false;
                },
                toJni: function (v) {
                    return v ? 1 : 0;
                }
            },
            'byte': {
                type: 'int8',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'number';
                }
            },
            'char': {
                type: 'uint16',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'string' && v.length === 1;
                },
                fromJni: function (c) {
                    return String.fromCharCode(c);
                },
                toJni: function (s) {
                    return s.charCodeAt(0);
                }
            },
            'short': {
                type: 'int16',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'number';
                }
            },
            'int': {
                type: 'int32',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'number';
                }
            },
            'long': {
                type: 'int64',
                size: 2,
                isCompatible: function (v) {
                    return typeof v === 'number';
                }
            },
            'float': {
                type: 'float',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'number';
                }
            },
            'double': {
                type: 'double',
                size: 2,
                isCompatible: function (v) {
                    return typeof v === 'number';
                }
            },
            'void': {
                type: 'void',
                size: 0,
                isCompatible: function () {
                    return false;
                }
            },
            '[B': {
                type: 'pointer',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'object' && v.hasOwnProperty('length');
                },
                fromJni: function () {
                    throw new Error("Not yet implemented ([B)");
                },
                toJni: function () {
                    throw new Error("Not yet implemented ([B)");
                }
            },
            '[C': {
                type: 'pointer',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'object' && v.hasOwnProperty('length');
                },
                fromJni: function () {
                    throw new Error("Not yet implemented ([C)");
                },
                toJni: function () {
                    throw new Error("Not yet implemented ([C)");
                }
            },
            '[I': {
                type: 'pointer',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'object' && v.hasOwnProperty('length');
                },
                fromJni: function () {
                    throw new Error("Not yet implemented ([I)");
                },
                toJni: function () {
                    throw new Error("Not yet implemented ([I)");
                }
            },
            '[Ljava.lang.String;': {
                type: 'pointer',
                size: 1,
                isCompatible: function (v) {
                    return typeof v === 'object' && v.hasOwnProperty('length') && (v.length === 0 || typeof v[0] === 'string');
                },
                fromJni: function (h, env) {
                    var result = [];
                    var length = env.getArrayLength(h);
                    for (var i = 0; i !== length; i++) {
                        var s = env.getObjectArrayElement(h, i);
                        result.push(env.stringFromJni(s));
                        env.deleteLocalRef(s);
                    }
                    return result;
                },
                toJni: function (strings, env) {
                    var result = env.newObjectArray(strings.length, env.javaLangString().handle, NULL);
                    for (var i = 0; i !== strings.length; i++) {
                        var s = env.newStringUtf(strings[i]);
                        env.setObjectArrayElement(result, i, s);
                        env.deleteLocalRef(s);
                    }
                    return result;
                }
            }
        };

        var objectType = function (className, unbox) {
            return {
                type: 'pointer',
                size: 1,
                isCompatible: function (v) {
                    if (className === 'java.lang.String' && typeof v === 'string') {
                        return true;
                    }

                    return typeof v === 'object' && v.hasOwnProperty('$handle'); // TODO: improve strictness
                },
                fromJni: function (h, env) {
                    if (h.isNull()) {
                        return null;
                    } else if (className === 'java.lang.String' && unbox) {
                        return env.stringFromJni(h);
                    } else if (this.$handle !== null && env.isSameObject(h, this.$handle)) {
                        return this;
                    } else {
                        return factory.cast(h, factory.use(className));
                    }
                },
                toJni: function (o, env) {
                    if (typeof o === 'string') {
                        return env.newStringUtf(o);
                    }

                    return o.$handle;
                }
            };
        };

        var arrayType = function (rawElementClassName) {
            var elementClassName;
            var isPrimitive;
            if (rawElementClassName[0] === "L" && rawElementClassName[rawElementClassName.length - 1] === ";") {
                elementClassName = rawElementClassName.substring(1, rawElementClassName.length - 1);
                isPrimitive = false;
            } else {
                elementClassName = rawElementClassName;
                isPrimitive = true;
                throw new Error("Primitive arrays not yet supported");
            }
            var elementType = typeFromClassName(elementClassName);
            return {
                type: 'pointer',
                size: 1,
                isCompatible: function (v) {
                    if (typeof v !== 'object' || !v.hasOwnProperty('length')) {
                        return false;
                    }
                    return v.every(function (element) {
                        return elementType.isCompatible(element);
                    });
                },
                fromJni: function (h, env) {
                    var result = [];
                    var length = env.getArrayLength(h);
                    for (var i = 0; i !== length; i++) {
                        var handle = env.getObjectArrayElement(h, i);
                        try {
                            result.push(elementType.fromJni.call(this, handle, env));
                        } finally {
                            env.deleteLocalRef(handle);
                        }
                    }
                    return result;
                },
                toJni: function (elements, env) {
                    var elementClass = factory.use(elementClassName);
                    var result = env.newObjectArray(elements.length, elementClass.$classHandle, NULL);
                    for (var i = 0; i !== elements.length; i++) {
                        var handle = elementType.toJni.call(this, elements[i], env);
                        env.setObjectArrayElement(result, i, handle);
                    }
                    return result;
                }
            };
        };

        initialize.call(this);
    };

    var VM = function VM(api) {
        var handle = null;
        var attachCurrentThread = null;
        var detachCurrentThread = null;
        var getEnv = null;

        var initialize = function () {
            handle = Memory.readPointer(api.gDvmJni.add(8));

            var vtable = Memory.readPointer(handle);
            attachCurrentThread = new NativeFunction(Memory.readPointer(vtable.add(4 * pointerSize)), 'int32', ['pointer', 'pointer', 'pointer']);
            detachCurrentThread = new NativeFunction(Memory.readPointer(vtable.add(5 * pointerSize)), 'int32', ['pointer']);
            getEnv = new NativeFunction(Memory.readPointer(vtable.add(6 * pointerSize)), 'int32', ['pointer', 'pointer', 'int32']);
        };

        this.perform = function (fn) {
            var env = this.tryGetEnv();
            var alreadyAttached = env !== null;
            if (!alreadyAttached) {
                env = this.attachCurrentThread();
            }

            var pendingException = null;
            try {
                fn();
            } catch (e) {
                pendingException = e;
            }

            if (!alreadyAttached) {
                this.detachCurrentThread();
            }

            if (pendingException !== null) {
                throw pendingException;
            }
        };

        this.attachCurrentThread = function () {
            var envBuf = Memory.alloc(pointerSize);
            checkJniResult("VM::AttachCurrentThread", attachCurrentThread(handle, envBuf, NULL));
            return new Env(Memory.readPointer(envBuf));
        };

        this.detachCurrentThread = function () {
            checkJniResult("VM::DetachCurrentThread", detachCurrentThread(handle));
        };

        this.getEnv = function () {
            var envBuf = Memory.alloc(pointerSize);
            checkJniResult("VM::GetEnv", getEnv(handle, envBuf, JNI_VERSION_1_6));
            return new Env(Memory.readPointer(envBuf));
        };

        this.tryGetEnv = function () {
            var envBuf = Memory.alloc(pointerSize);
            var result = getEnv(handle, envBuf, JNI_VERSION_1_6);
            if (result !== JNI_OK) {
                return null;
            }
            return new Env(Memory.readPointer(envBuf));
        };

        initialize.call(this);
    };

    function Env(handle) {
        this.handle = handle;
    }

    (function () {
        var CALL_CONSTRUCTOR_METHOD_OFFSET = 28;

        var CALL_OBJECT_METHOD_OFFSET = 34;
        var CALL_BOOLEAN_METHOD_OFFSET = 37;
        var CALL_BYTE_METHOD_OFFSET = 40;
        var CALL_CHAR_METHOD_OFFSET = 43;
        var CALL_SHORT_METHOD_OFFSET = 46;
        var CALL_INT_METHOD_OFFSET = 49;
        var CALL_LONG_METHOD_OFFSET = 52;
        var CALL_FLOAT_METHOD_OFFSET = 55;
        var CALL_DOUBLE_METHOD_OFFSET = 58;
        var CALL_VOID_METHOD_OFFSET = 61;

        var CALL_STATIC_OBJECT_METHOD_OFFSET = 114;
        var CALL_STATIC_BOOLEAN_METHOD_OFFSET = 117;
        var CALL_STATIC_BYTE_METHOD_OFFSET = 120;
        var CALL_STATIC_CHAR_METHOD_OFFSET = 123;
        var CALL_STATIC_SHORT_METHOD_OFFSET = 126;
        var CALL_STATIC_INT_METHOD_OFFSET = 129;
        var CALL_STATIC_LONG_METHOD_OFFSET = 132;
        var CALL_STATIC_FLOAT_METHOD_OFFSET = 135;
        var CALL_STATIC_DOUBLE_METHOD_OFFSET = 138;
        var CALL_STATIC_VOID_METHOD_OFFSET = 141;

        var callMethodOffset = {
            'pointer': CALL_OBJECT_METHOD_OFFSET,
            'uint8': CALL_BOOLEAN_METHOD_OFFSET,
            'int8': CALL_BYTE_METHOD_OFFSET,
            'uint16': CALL_CHAR_METHOD_OFFSET,
            'int16': CALL_SHORT_METHOD_OFFSET,
            'int32': CALL_INT_METHOD_OFFSET,
            'int64': CALL_LONG_METHOD_OFFSET,
            'float': CALL_FLOAT_METHOD_OFFSET,
            'double': CALL_DOUBLE_METHOD_OFFSET,
            'void': CALL_VOID_METHOD_OFFSET
        };

        var callStaticMethodOffset = {
            'pointer': CALL_STATIC_OBJECT_METHOD_OFFSET,
            'uint8': CALL_STATIC_BOOLEAN_METHOD_OFFSET,
            'int8': CALL_STATIC_BYTE_METHOD_OFFSET,
            'uint16': CALL_STATIC_CHAR_METHOD_OFFSET,
            'int16': CALL_STATIC_SHORT_METHOD_OFFSET,
            'int32': CALL_STATIC_INT_METHOD_OFFSET,
            'int64': CALL_STATIC_LONG_METHOD_OFFSET,
            'float': CALL_STATIC_FLOAT_METHOD_OFFSET,
            'double': CALL_STATIC_DOUBLE_METHOD_OFFSET,
            'void': CALL_STATIC_VOID_METHOD_OFFSET
        };

        var cachedVtable = null;
        var globalRefs = [];
        Env.dispose = function (env) {
            globalRefs.forEach(env.deleteGlobalRef, env);
            globalRefs = [];
        };

        function register(globalRef) {
            globalRefs.push(globalRef);
            return globalRef;
        }

        function vtable() {
            if (cachedVtable === null) {
                cachedVtable = Memory.readPointer(this.handle);
            }
            return cachedVtable;
        }

        function proxy(offset, retType, argTypes, wrapper) {
            var impl = null;
            return function () {
                if (impl === null) {
                    impl = new NativeFunction(Memory.readPointer(vtable.call(this).add(offset * pointerSize)), retType, argTypes);
                }
                var args = [impl];
                args = args.concat.apply(args, arguments);
                return wrapper.apply(this, args);
            };
        }

        Env.prototype.findClass = proxy(6, 'pointer', ['pointer', 'pointer'], function (impl, name) {
            var result = impl(this.handle, Memory.allocUtf8String(name));
            var throwable = this.exceptionOccurred();
            if (!throwable.isNull()) {
                this.exceptionClear();
                var description = this.method('pointer', [])(this.handle, throwable, this.javaLangObject().toString);
                var descriptionStr = this.stringFromJni(description);
                this.deleteLocalRef(description);
                this.deleteLocalRef(throwable);
                throw new Error(descriptionStr);
            }
            return result;
        });

        Env.prototype.fromReflectedMethod = proxy(7, 'pointer', ['pointer', 'pointer'], function (impl, method) {
            return impl(this.handle, method);
        });

        Env.prototype.getSuperclass = proxy(10, 'pointer', ['pointer', 'pointer'], function (impl, klass) {
            return impl(this.handle, klass);
        });

        Env.prototype.throw = proxy(13, 'int32', ['pointer', 'pointer'], function (impl, obj) {
            return impl(this.handle, obj);
        });

        Env.prototype.exceptionOccurred = proxy(15, 'pointer', ['pointer'], function (impl) {
            return impl(this.handle);
        });

        Env.prototype.exceptionDescribe = proxy(16, 'void', ['pointer'], function (impl) {
            impl(this.handle);
        });

        Env.prototype.exceptionClear = proxy(17, 'void', ['pointer'], function (impl) {
            impl(this.handle);
        });

        Env.prototype.pushLocalFrame = proxy(19, 'int32', ['pointer', 'int32'], function (impl, capacity) {
            return impl(this.handle, capacity);
        });

        Env.prototype.popLocalFrame = proxy(20, 'pointer', ['pointer', 'pointer'], function (impl, result) {
            return impl(this.handle, result);
        });

        Env.prototype.newGlobalRef = proxy(21, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
            return impl(this.handle, obj);
        });

        Env.prototype.deleteGlobalRef = proxy(22, 'void', ['pointer', 'pointer'], function (impl, globalRef) {
            impl(this.handle, globalRef);
        });

        Env.prototype.deleteLocalRef = proxy(23, 'void', ['pointer', 'pointer'], function (impl, localRef) {
            impl(this.handle, localRef);
        });

        Env.prototype.isSameObject = proxy(24, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, ref1, ref2) {
            return impl(this.handle, ref1, ref2) ? true : false;
        });

        Env.prototype.getObjectClass = proxy(31, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
            return impl(this.handle, obj);
        });

        Env.prototype.isInstanceOf = proxy(32, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, obj, klass) {
            return impl(this.handle, obj, klass) ? true : false;
        });

        Env.prototype.getMethodId = proxy(33, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
            return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
        });

        Env.prototype.getFieldId = proxy(94, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
            return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
        });

        Env.prototype.getIntField = proxy(100, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, obj, fieldId) {
            return impl(this.handle, obj, fieldId);
        });

        Env.prototype.getStaticMethodId = proxy(113, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
            return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
        });

        Env.prototype.getStaticFieldId = proxy(144, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
            return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
        });

        Env.prototype.getStaticIntField = proxy(150, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, obj, fieldId) {
            return impl(this.handle, obj, fieldId);
        });

        Env.prototype.newStringUtf = proxy(167, 'pointer', ['pointer', 'pointer'], function (impl, str) {
            var utf = Memory.allocUtf8String(str);
            return impl(this.handle, utf);
        });

        Env.prototype.getStringUtfChars = proxy(169, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, str) {
            return impl(this.handle, str, NULL);
        });

        Env.prototype.releaseStringUtfChars = proxy(170, 'void', ['pointer', 'pointer', 'pointer'], function (impl, str, utf) {
            impl(this.handle, str, utf);
        });

        Env.prototype.getArrayLength = proxy(171, 'int32', ['pointer', 'pointer'], function (impl, array) {
            return impl(this.handle, array);
        });

        Env.prototype.newObjectArray = proxy(172, 'pointer', ['pointer', 'int32', 'pointer', 'pointer'], function (impl, length, elementClass, initialElement) {
            return impl(this.handle, length, elementClass, initialElement);
        });

        Env.prototype.getObjectArrayElement = proxy(173, 'pointer', ['pointer', 'pointer', 'int32'], function (impl, array, index) {
            return impl(this.handle, array, index);
        });

        Env.prototype.setObjectArrayElement = proxy(174, 'void', ['pointer', 'pointer', 'int32', 'pointer'], function (impl, array, index, value) {
            impl(this.handle, array, index, value);
        });

        var cachedMethods = {};
        var method = function (offset, retType, argTypes) {
            var key = offset + "|" + retType + "|" + argTypes.join(":");
            var m = cachedMethods[key];
            if (!m) {
                m = new NativeFunction(Memory.readPointer(vtable.call(this).add(offset * pointerSize)), retType, ['pointer', 'pointer', 'pointer', '...'].concat(argTypes));
                cachedMethods[key] = m;
            }
            return m;
        };

        Env.prototype.constructor = function (argTypes) {
            return method(CALL_CONSTRUCTOR_METHOD_OFFSET, 'pointer', argTypes);
        };

        Env.prototype.method = function (retType, argTypes) {
            var offset = callMethodOffset[retType];
            if (offset === undefined)
                throw new Error("Unsupported type: " + retType);
            return method(offset, retType, argTypes);
        };

        Env.prototype.staticMethod = function (retType, argTypes) {
            var offset = callStaticMethodOffset[retType];
            if (offset === undefined)
                throw new Error("Unsupported type: " + retType);
            return method(offset, retType, argTypes);
        };

        var javaLangClass = null;
        Env.prototype.javaLangClass = function () {
            if (javaLangClass === null) {
                var handle = this.findClass("java/lang/Class");
                javaLangClass = {
                    handle: register(this.newGlobalRef(handle)),
                    getName: this.getMethodId(handle, "getName", "()Ljava/lang/String;"),
                    getDeclaredConstructors: this.getMethodId(handle, "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;"),
                    getDeclaredMethods: this.getMethodId(handle, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;")
                };
                this.deleteLocalRef(handle);
            }
            return javaLangClass;
        };

        var javaLangObject = null;
        Env.prototype.javaLangObject = function () {
            if (javaLangObject === null) {
                var handle = this.findClass("java/lang/Object");
                javaLangObject = {
                    toString: this.getMethodId(handle, "toString", "()Ljava/lang/String;")
                };
                this.deleteLocalRef(handle);
            }
            return javaLangObject;
        };

        var javaLangReflectConstructor = null;
        Env.prototype.javaLangReflectConstructor = function () {
            if (javaLangReflectConstructor === null) {
                var handle = this.findClass("java/lang/reflect/Constructor");
                javaLangReflectConstructor = {
                    getGenericParameterTypes: this.getMethodId(handle, "getGenericParameterTypes", "()[Ljava/lang/reflect/Type;")
                };
                this.deleteLocalRef(handle);
            }
            return javaLangReflectConstructor;
        };

        var javaLangReflectMethod = null;
        Env.prototype.javaLangReflectMethod = function () {
            if (javaLangReflectMethod === null) {
                var handle = this.findClass("java/lang/reflect/Method");
                javaLangReflectMethod = {
                    getName: this.getMethodId(handle, "getName", "()Ljava/lang/String;"),
                    getGenericParameterTypes: this.getMethodId(handle, "getGenericParameterTypes", "()[Ljava/lang/reflect/Type;"),
                    getGenericReturnType: this.getMethodId(handle, "getGenericReturnType", "()Ljava/lang/reflect/Type;"),
                    getModifiers: this.getMethodId(handle, "getModifiers", "()I"),
                    isVarArgs: this.getMethodId(handle, "isVarArgs", "()Z")
                };
                this.deleteLocalRef(handle);
            }
            return javaLangReflectMethod;
        };

        var javaLangReflectModifier = null;
        Env.prototype.javaLangReflectModifier = function () {
            if (javaLangReflectModifier === null) {
                var handle = this.findClass("java/lang/reflect/Modifier");
                javaLangReflectModifier = {
                    PUBLIC: this.getStaticIntField(handle, this.getStaticFieldId(handle, "PUBLIC", "I")),
                    PRIVATE: this.getStaticIntField(handle, this.getStaticFieldId(handle, "PRIVATE", "I")),
                    PROTECTED: this.getStaticIntField(handle, this.getStaticFieldId(handle, "PROTECTED", "I")),
                    STATIC: this.getStaticIntField(handle, this.getStaticFieldId(handle, "STATIC", "I"))
                };
                this.deleteLocalRef(handle);
            }
            return javaLangReflectModifier;
        };

        var javaLangReflectGenericArrayType = null;
        Env.prototype.javaLangReflectGenericArrayType = function () {
            if (javaLangReflectGenericArrayType === null) {
                var handle = this.findClass("java/lang/reflect/GenericArrayType");
                javaLangReflectGenericArrayType = {
                    handle: register(this.newGlobalRef(handle)),
                    getGenericComponentType: this.getMethodId(handle, "getGenericComponentType", "()Ljava/lang/reflect/Type;")
                };
                this.deleteLocalRef(handle);
            }
            return javaLangReflectGenericArrayType;
        };

        Env.prototype.getClassName = function (klass) {
            var name = this.method('pointer', [])(this.handle, klass, this.javaLangClass().getName);
            var result = this.stringFromJni(name);
            this.deleteLocalRef(name);
            return result;
        };

        Env.prototype.getTypeName = function (type) {
            if (this.isInstanceOf(type, this.javaLangClass().handle)) {
                return this.getClassName(type);
            // } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
            //     return "L";
            } else {
                return "java.lang.Object";
            }
        };

        Env.prototype.getArrayTypeName = function (type) {
            if (this.isInstanceOf(type, this.javaLangClass().handle)) {
                return "[L" + this.getClassName(type) + ";";
            } else {
                // TODO: handle primitive types
                return "[Ljava.lang.Object;";
            }
        };

        Env.prototype.stringFromJni = function (str) {
            var utf = this.getStringUtfChars(str);
            var result = Memory.readUtf8String(utf);
            this.releaseStringUtfChars(str, utf);
            return result;
        };
    })();

    var getApi = function () {
        if (_api !== null) {
            return _api;
        }

        var temporaryApi = {};
        var pending = [
            {
                module: "libdvm.so",
                functions: {
                    "_Z20dvmDecodeIndirectRefP6ThreadP8_jobject": ["dvmDecodeIndirectRef", 'pointer', ['pointer', 'pointer']],
                    "_Z15dvmUseJNIBridgeP6MethodPv": ["dvmUseJNIBridge", 'void', ['pointer', 'pointer']]
                },
                variables: {
                    "gDvmJni": function (address) {
                        this.gDvmJni = address;
                    },
                    "gDvm": function (address) {
                        this.gDvm = address;
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
                                temporaryApi[signature[0]] = new NativeFunction(exp.address, signature[1], signature[2]);
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

    var checkJniResult = function (name, result) {
        if (result != JNI_OK) {
            throw new Error(name + " failed: " + result);
        }
    };

    var basename = function (className) {
        return className.slice(className.lastIndexOf(".") + 1);
    };
}).call(this);
