/* jshint esnext: true, evil: true */
(function () {
    "use strict";

    const flavor = typeof Process === 'undefined' ? 'kernel' : 'user';
    if (flavor !== 'user')
        return;

    let _runtime = null;
    let _api = null;
    const pointerSize = Process.pointerSize;
    /* no error */
    const JNI_OK = 0;
    /* generic error */
    const JNI_ERR = -1;
    /* thread detached from the VM */
    const JNI_EDETACHED = -2;
    /* JNI version error */
    const JNI_VERSION = -3;
    const JNI_ABORT = 2;

    const JNI_VERSION_1_6 = 0x00010006;

    // methods
    const CONSTRUCTOR_METHOD = 1;
    const STATIC_METHOD = 2;
    const INSTANCE_METHOD = 3;

    // fields
    const STATIC_FIELD = 1;
    const INSTANCE_FIELD = 2;

    // TODO: 64-bit
    const JNI_ENV_OFFSET_SELF = 12;

    const CLASS_OBJECT_SIZE = 160;
    const CLASS_OBJECT_OFFSET_VTABLE_COUNT = 112;
    const CLASS_OBJECT_OFFSET_VTABLE = 116;

    const OBJECT_OFFSET_CLAZZ = 0;

    const METHOD_SIZE = 56;
    const METHOD_OFFSET_CLAZZ = 0;
    const METHOD_OFFSET_ACCESS_FLAGS = 4;
    const METHOD_OFFSET_METHOD_INDEX = 8;
    const METHOD_OFFSET_REGISTERS_SIZE = 10;
    const METHOD_OFFSET_OUTS_SIZE = 12;
    const METHOD_OFFSET_INS_SIZE = 14;
    const METHOD_OFFSET_INSNS = 32;
    const METHOD_OFFSET_JNI_ARG_INFO = 36;

    // jobject reference types
    const JNIInvalidRefType = 0;
    const JNILocalRefType = 1;
    const JNIGlobalRefType = 2;
    const JNIWeakGlobalRefType = 3;

    const NULL_OBJECT = NULL;

    Object.defineProperty(this, 'Dalvik', {
        enumerable: true,
        get: function () {
            if (_runtime === null) {
                _runtime = new Runtime();
            }
            return _runtime;
        }
    });

    function Runtime() {
        let api = null;
        let vm = null;
        let classFactory = null;
        let pending = [];

        function initialize() {
            api = getApi();
            if (api !== null) {
                vm = new VM(api);
                classFactory = new ClassFactory(api, vm);
            }
        }

        WeakRef.bind(Runtime, function dispose() {
            if (api !== null) {
                vm.perform(function () {
                    const env = vm.getEnv();
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
                    const classes = [];
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
                        const ActivityThread = classFactory.use("android.app.ActivityThread");
                        const Handler = classFactory.use("android.os.Handler");
                        const Looper = classFactory.use("android.os.Looper");

                        const looper = Looper.getMainLooper();
                        const handler = Handler.$new.overload("android.os.Looper").call(Handler, looper);
                        const message = handler.obtainMessage();
                        Handler.dispatchMessage.implementation = function (msg) {
                            const sameHandler = this.$isSameObject(handler);
                            if (sameHandler) {
                                const app = ActivityThread.currentApplication();
                                if (app !== null) {
                                    Handler.dispatchMessage.implementation = null;
                                    const loader = app.getClassLoader();
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

        this.choose = function (className, callbacks) {
            if (classFactory.loader === null) {
                throw new Error("Not allowed outside Dalvik.perform() callback");
            }
            return classFactory.choose(className, callbacks);
        };

        this.cast = function (obj, C) {
            return classFactory.cast(obj, C);
        };

        initialize.call(this);
    }

    function ClassFactory(api, vm) {
        const factory = this;
        let classes = {};
        let patchedClasses = {};
        let loader = null;

        function initialize() {
            api = getApi();
        }

        this.dispose = function (env) {
            for (let entryId in patchedClasses) {
                if (patchedClasses.hasOwnProperty(entryId)) {
                    const entry = patchedClasses[entryId];
                    Memory.writePointer(entry.vtablePtr, entry.vtable);
                    Memory.writeS32(entry.vtableCountPtr, entry.vtableCount);

                    for (let methodId in entry.targetMethods) {
                        if (entry.targetMethods.hasOwnProperty(methodId)) {
                            entry.targetMethods[methodId].implementation = null;
                        }
                    }
                }
            }
            patchedClasses = {};

            for (let classId in classes) {
                if (classes.hasOwnProperty(classId)) {
                    const klass = classes[classId];
                    klass.__methods__.forEach(env.deleteGlobalRef, env);
                    klass.__fields__.forEach(env.deleteGlobalRef, env);
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
            let C = classes[className];
            if (!C) {
                const env = vm.getEnv();
                if (loader !== null) {
                    const klassObj = loader.loadClass(className);
                    C = ensureClass(klassObj.$handle, className);
                } else {
                    const handle = env.findClass(className.replace(/\./g, "/"));
                    try {
                        C = ensureClass(handle, className);
                    } finally {
                        env.deleteLocalRef(handle);
                    }
                }
            }
            return new C(C.__handle__, null);
        };

        this.choose = function (className, callbacks) {
            const env = vm.getEnv();
            const klass = this.use(className);

            let enumerateInstances = function (className, callbacks) {
                const thread = Memory.readPointer(env.handle.add(JNI_ENV_OFFSET_SELF));
                const ptrClassObject = api.dvmDecodeIndirectRef(thread, klass.$classHandle);

                const pattern = ptrClassObject.toMatchPattern();
                const heapSourceBase = api.dvmHeapSourceGetBase();
                const heapSourceLimit = api.dvmHeapSourceGetLimit();
                const size = heapSourceLimit.toInt32() - heapSourceBase.toInt32();
                Memory.scan(heapSourceBase, size, pattern, {
                    onMatch: function (address, size) {
                        if (api.dvmIsValidObject(address)) {
                            Dalvik.perform(function () {
                                const env = vm.getEnv();
                                const thread = Memory.readPointer(env.handle.add(JNI_ENV_OFFSET_SELF));
                                const localReference = api.addLocalReferenceFunc(thread, address);
                                let instance;
                                try {
                                    instance = Dalvik.cast(localReference, klass);
                                } finally {
                                    env.deleteLocalRef(localReference);
                                }

                                const stopMaybe = callbacks.onMatch(instance);
                                if (stopMaybe === 'stop') {
                                    return 'stop';
                                }
                            });
                        }
                    },
                    onError: function (reason) {
                    },
                    onComplete: function () {
                        callbacks.onComplete();
                    }
                });
            };

            if (api.addLocalReferenceFunc === null) {
                const libdvm = Process.getModuleByName('libdvm.so');
                Memory.scan(libdvm.base, libdvm.size, '2D E9 F0 41 05 46 15 4E 0C 46 7E 44 11 B3 43 68',
                    {
                        onMatch: function (address, size) {
                            // Note that on 32-bit ARM this address must have its least significant bit set to 0 for ARM functions, and 1 for Thumb functions. => So set it to 1
                            if (Process.arch === 'arm') {
                                address = address.or(1);
                            }
                            api.addLocalReferenceFunc = new NativeFunction(address, 'pointer', ['pointer', 'pointer']);
                            enumerateInstances(className, callbacks);
                            return 'stop';
                        },
                        onError: function (reason) {
                        },
                        onComplete: function () {
                        }
                    });
            } else {
                enumerateInstances(className, callbacks);
            }
        };

        this.cast = function (obj, klass) {
            const env = vm.getEnv();
            const handle = obj.hasOwnProperty('$handle') ? obj.$handle : obj;
            if (env.isInstanceOf(handle, klass.$classHandle)) {
                const C = klass.$classWrapper;
                return new C(C.__handle__, handle);
            } else {
                throw new Error("Cast from '" + env.getObjectClassName(handle) + "' to '" + env.getClassName(klass.$classHandle) + "' isn't possible");
            }
        };

        function ensureClass(classHandle, cachedName) {
            let env = vm.getEnv();

            const name = cachedName !== null ? cachedName : env.getClassName(classHandle);
            let klass = classes[name];
            if (klass) {
                return klass;
            }

            const superHandle = env.getSuperclass(classHandle);
            let superKlass;
            if (!superHandle.isNull()) {
                try {
                    superKlass = ensureClass(superHandle, null);
                } finally {
                    env.deleteLocalRef(superHandle);
                }
            } else {
                superKlass = null;
            }

            eval("klass = function " + basename(name) + "(classHandle, handle) {" +
                 "const env = vm.getEnv();" +
                 "this.$classWrapper = klass;" +
                 "this.$classHandle = env.newGlobalRef(classHandle);" +
                 "this.$handle = (handle !== null) ? env.newGlobalRef(handle) : null;" +
                 "this.$weakRef = WeakRef.bind(this, makeHandleDestructor(this.$handle, this.$classHandle));" +
            "};");

            classes[name] = klass;

            function initializeClass() {
                klass.__name__ = name;
                klass.__handle__ = env.newGlobalRef(classHandle);
                klass.__methods__ = [];
                klass.__fields__ = [];

                let ctor = null;
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
                    const env = vm.getEnv();
                    return env.isSameObject(obj.$handle, this.$handle);
                };

                Object.defineProperty(klass.prototype, 'class', {
                    get: function () {
                        const Clazz = factory.use("java.lang.Class");
                        return factory.cast(this.$classHandle, Clazz);
                    }
                });

                Object.defineProperty(klass.prototype, "$className", {
                    get: function () {
                        const env = vm.getEnv();
                        return this.hasOwnProperty('$handle') ? env.getObjectClassName(this.$handle) : env.getClassName(this.$classHandle);
                    }
                });

                addMethodsAndFields();
            }

            function dispose() {
                WeakRef.unbind(this.$weakRef);
            }

            function makeConstructor(classHandle, env) {
                const Constructor = env.javaLangReflectConstructor();
                const invokeObjectMethodNoArgs = env.method('pointer', []);

                const jsMethods = [];
                const jsRetType = getTypeFromJniTypename(name, false);
                const constructors = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredConstructors);
                try {
                    const numConstructors = env.getArrayLength(constructors);
                    for (let constructorIndex = 0; constructorIndex !== numConstructors; constructorIndex++) {
                        const constructor = env.getObjectArrayElement(constructors, constructorIndex);
                        try {
                            const methodId = env.fromReflectedMethod(constructor);
                            const jsArgTypes = [];

                            const types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
                            try {
                                const numTypes = env.getArrayLength(types);
                                for (let typeIndex = 0; typeIndex !== numTypes; typeIndex++) {
                                    const t = env.getObjectArrayElement(types, typeIndex);
                                    try {
                                        const argType = getTypeFromJniTypename(env.getTypeName(t));
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
                            jsMethods.push(makeMethod(basename(name), CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
                        } finally {
                            env.deleteLocalRef(constructor);
                        }
                    }
                } finally {
                    env.deleteLocalRef(constructors);
                }

                if (jsMethods.length === 0)
                    throw new Error("no supported overloads");

                return makeMethodDispatcher("<init>", jsMethods);
            }

            function makeField(name, handle, env) {
                const Field = env.javaLangReflectField();
                const Modifier = env.javaLangReflectModifier();
                const invokeObjectMethodNoArgs = env.method('pointer', []);
                const invokeIntMethodNoArgs = env.method('int32', []);

                const fieldId = env.fromReflectedField(handle);
                const modifiers = invokeIntMethodNoArgs(env.handle, handle, Field.getModifiers);
                const jsType = (modifiers & Modifier.STATIC) !== 0 ? STATIC_FIELD : INSTANCE_FIELD;
                const fieldType = invokeObjectMethodNoArgs(env.handle, handle, Field.getGenericType);

                let jsFieldType;
                try {
                    jsFieldType = getTypeFromJniTypename(env.getTypeName(fieldType));
                } catch (e) {
                    return null;
                } finally {
                    env.deleteLocalRef(fieldType);
                }

                const field = createField(name, jsType, fieldId, jsFieldType, env);
                if (field === null)
                    throw new Error("No supported field");

                return field;
            }

            function createField(name, type, targetFieldId, fieldType, env) {
                const rawFieldType = fieldType.type;
                let invokeTarget = null;
                if (type === STATIC_FIELD) {
                    invokeTarget = env.getStaticField(rawFieldType);
                } else if (type === INSTANCE_FIELD) {
                    invokeTarget = env.getField(rawFieldType);
                }

                let frameCapacity = 2;
                const callArgs = [
                    "env.handle",
                    type === INSTANCE_FIELD ? "this.$handle" : "this.$classHandle",
                    "targetFieldId"
                ];

                let returnCapture, returnStatements;
                if (fieldType.fromJni) {
                    frameCapacity++;
                    returnCapture = "rawResult = ";
                    returnStatements = "try {" +
                            "result = fieldType.fromJni.call(this, rawResult, env);" +
                        "} finally {" +
                            "env.popLocalFrame(NULL);" +
                        "} " +
                        "return result;";
                } else {
                    returnCapture = "result = ";
                    returnStatements = "env.popLocalFrame(NULL);" +
                        "return result;";
                }

                let getter;
                eval("getter = function get" + name + "() {" +
                    "const isInstance = this.$handle !== null;" +
                    "if (type === INSTANCE_FIELD && !isInstance) { " +
                        "throw new Error('" + name + ": cannot get an instance field without an instance.');" +
                    "}" +
                    "const env = vm.getEnv();" +
                    "if (env.pushLocalFrame(" + frameCapacity + ") !== JNI_OK) {" +
                        "env.exceptionClear();" +
                        "throw new Error(\"Out of memory\");" +
                    "}" +
                    "let result, rawResult;" +
                    "try {" +
                        returnCapture + "invokeTarget(" + callArgs.join(", ") + ");" +
                    "} catch (e) {" +
                        "env.popLocalFrame(NULL);" +
                        "throw e;" +
                    "}" +
                    "try {" +
                        "env.checkForExceptionAndThrowIt();" +
                    "} catch (e) {" +
                        "env.popLocalFrame(NULL); " +
                        "throw e;" +
                    "}" +
                    returnStatements +
                "}");

                let setFunction = null;
                if (type === STATIC_FIELD) {
                    setFunction = env.setStaticField(rawFieldType);
                } else if (type === INSTANCE_FIELD) {
                    setFunction = env.setField(rawFieldType);
                }

                let inputStatement = null;
                if (fieldType.toJni) {
                    inputStatement = "const input = fieldType.toJni.call(this, value, env);";
                } else {
                    inputStatement = "const input = value;";
                }

                let setter;
                eval("setter = function set" + name + "(value) {" +
                    "const isInstance = this.$handle !== null;" +
                    "if (type === INSTANCE_FIELD && !isInstance) { " +
                        "throw new Error('" + name + ": cannot set an instance field without an instance');" +
                    "}" +
                    "if (!fieldType.isCompatible(value)) {" +
                        "throw new Error('Field \"" + name + "\" expected input value compatible with " + fieldType.className + ".');" +
                    "}" +
                    "const env = vm.getEnv();" +
                    "try {" +
                        inputStatement +
                        "setFunction(" + callArgs.join(", ") + ", input);" +
                    "} catch (e) {" +
                        "throw e;" +
                    "}" +
                    "try {" +
                        "env.checkForExceptionAndThrowIt();" +
                    "} catch (e) {" +
                        "env.popLocalFrame(NULL); " +
                        "throw e;" +
                    "}" +
                "}");

                const f = {};
                Object.defineProperty(f, 'value', {
                    enumerable: true,
                    get: function () {
                        return getter.call(this.self);
                    },
                    set: function (value) {
                        setter.call(this.self, value);
                    }
                });

                Object.defineProperty(f, 'holder', {
                    enumerable: true,
                    value: klass
                });

                Object.defineProperty(f, 'fieldType', {
                    enumerable: true,
                    value: type
                });

                Object.defineProperty(f, 'fieldReturnType', {
                    enumerable: true,
                    value: fieldType
                });

                return f;
            }

            function myAssign(target, ...sources) {
                sources.forEach(source => {
                    Object.defineProperties(target, Object.keys(source).reduce((descriptors, key) => {
                        if (key === "holder" && target.hasOwnProperty("holder")) {
                            // there is already holder property
                        } else {
                            descriptors[key] = Object.getOwnPropertyDescriptor(source, key);
                        }
                        return descriptors;
                    }, {}));
                });
                return target;
            }

            function addMethodsAndFields() {
                const invokeObjectMethodNoArgs = env.method('pointer', []);
                const Method_getName = env.javaLangReflectMethod().getName;
                const Field_getName = env.javaLangReflectField().getName;
                const fieldHandles = klass.__fields__;
                const methodHandles = klass.__methods__;
                const jsMethods = {};
                const jsFields = {};

                const methods = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredMethods);
                try {
                    const numMethods = env.getArrayLength(methods);
                    for (let methodIndex = 0; methodIndex !== numMethods; methodIndex++) {
                        const method = env.getObjectArrayElement(methods, methodIndex);
                        try {
                            const methodName = invokeObjectMethodNoArgs(env.handle, method, Method_getName);
                            try {
                                const methodjsName = env.stringFromJni(methodName);
                                const methodHandle = env.newGlobalRef(method);
                                methodHandles.push(methodHandle);
                                let jsOverloads;
                                if (jsMethods.hasOwnProperty(methodjsName)) {
                                    jsOverloads = jsMethods[methodjsName];
                                } else {
                                    jsOverloads = [];
                                    jsMethods[methodjsName] = jsOverloads;
                                }
                                jsOverloads.push(methodHandle);
                            } finally {
                                env.deleteLocalRef(methodName);
                            }
                        } finally {
                            env.deleteLocalRef(method);
                        }
                    }
                } finally {
                    env.deleteLocalRef(methods);
                }

                const fields = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredFields);
                try {
                    const numFields = env.getArrayLength(fields);
                    for (let fieldIndex = 0; fieldIndex < numFields; fieldIndex++) {
                        const field = env.getObjectArrayElement(fields, fieldIndex);
                        try {
                            const fieldName = invokeObjectMethodNoArgs(env.handle, field, Field_getName);
                            try {
                                const fieldjsName = env.stringFromJni(fieldName);
                                const fieldHandle = env.newGlobalRef(field);
                                fieldHandles.push(fieldHandle);
                                jsFields[fieldjsName] = fieldHandle;
                            } finally {
                                env.deleteLocalRef(fieldName);
                            }
                        } finally {
                            env.deleteLocalRef(field);
                        }
                    }
                } finally {
                    env.deleteLocalRef(fields);
                }

                // define access to the fields in the class (klass)
                const values = myAssign({}, jsFields, jsMethods);
                Object.keys(values).forEach(function (name) {
                    let v = null;
                    Object.defineProperty(klass.prototype, name, {
                        get: function () {
                            if (v === null) {
                                vm.perform(function () {
                                    const env = vm.getEnv();
                                    let f = {};
                                    if (jsFields.hasOwnProperty(name)) {
                                        f = makeField(name, jsFields[name], env);
                                    }

                                    let m = {};
                                    if (jsMethods.hasOwnProperty(name)) {
                                        m = makeMethodFromOverloads(name, jsMethods[name], env);
                                    }
                                    v = myAssign(m, f);
                                });
                            }
                            // TODO find a better way
                            v.self = this;

                            return v;
                        }
                    });
                });
            }

            function makeMethodFromOverloads(name, overloads, env) {
                const Method = env.javaLangReflectMethod();
                const Modifier = env.javaLangReflectModifier();
                const invokeObjectMethodNoArgs = env.method('pointer', []);
                const invokeIntMethodNoArgs = env.method('int32', []);
                const invokeUInt8MethodNoArgs = env.method('uint8', []);

                const methods = overloads.map(function (handle) {
                    const methodId = env.fromReflectedMethod(handle);
                    const modifiers = invokeIntMethodNoArgs(env.handle, handle, Method.getModifiers);

                    const jsType = (modifiers & Modifier.STATIC) !== 0 ? STATIC_METHOD : INSTANCE_METHOD;
                    const isVarArgs = invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs) ? true : false;
                    let jsRetType;
                    const jsArgTypes = [];
                    try {
                        const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
                        env.checkForExceptionAndThrowIt();
                        try {
                            jsRetType = getTypeFromJniTypename(env.getTypeName(retType));
                        } finally {
                            env.deleteLocalRef(retType);
                        }
                        const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericParameterTypes);
                        env.checkForExceptionAndThrowIt();
                        try {
                            const numArgTypes = env.getArrayLength(argTypes);
                            for (let argTypeIndex = 0; argTypeIndex !== numArgTypes; argTypeIndex++) {
                                const t = env.getObjectArrayElement(argTypes, argTypeIndex);
                                try {
                                    const argClassName = (isVarArgs && argTypeIndex === numArgTypes - 1) ? env.getArrayTypeName(t) : env.getTypeName(t);
                                    const argType = getTypeFromJniTypename(argClassName);
                                    jsArgTypes.push(argType);
                                } finally {
                                    env.deleteLocalRef(t);
                                }
                            }
                        } finally {
                            env.deleteLocalRef(argTypes);
                        }
                    } catch (e) {
                        return null;
                    }

                    return makeMethod(name, jsType, methodId, jsRetType, jsArgTypes, env);
                }).filter(function (m) {
                    return m !== null;
                });

                if (methods.length === 0)
                    throw new Error("no supported overloads");

                if (name === "valueOf") {
                    const hasDefaultValueOf = methods.some(function implementsDefaultValueOf(m) {
                        return m.type === INSTANCE_METHOD && m.argumentTypes.length === 0;
                    });
                    if (!hasDefaultValueOf) {
                        const defaultValueOf = function defaultValueOf() {
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
                            value: getTypeFromJniTypename('int')
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
            }

            function makeMethodDispatcher(name, methods) {
                const candidates = {};
                methods.forEach(function (m) {
                    const numArgs = m.argumentTypes.length;
                    let group = candidates[numArgs];
                    if (!group) {
                        group = [];
                        candidates[numArgs] = group;
                    }
                    group.push(m);
                });

                function f() {
                    const isInstance = this.$handle !== null;
                    if (methods[0].type === INSTANCE_METHOD && !isInstance) {
                        if (name === 'toString') {
                            return "<" + this.$classWrapper.__name__ + ">";
                        }
                        throw new Error(name + ": cannot call instance method without an instance");
                    }
                    const group = candidates[arguments.length];
                    if (!group) {
                        throw new Error(name + ": argument count does not match any overload");
                    }
                    for (let i = 0; i !== group.length; i++) {
                        const method = group[i];
                        if (method.canInvokeWith(arguments)) {
                            return method.apply(this, arguments);
                        }
                    }
                    throw new Error(name + ": argument types do not match any overload");
                }

                Object.defineProperty(f, 'overloads', {
                    enumerable: true,
                    value: methods
                });

                Object.defineProperty(f, 'overload', {
                    enumerable: true,
                    value: function () {
                        const group = candidates[arguments.length];
                        if (!group) {
                            throw new Error(name + ": argument count does not match any overload");
                        }

                        const signature = Array.prototype.join.call(arguments, ":");
                        for (let i = 0; i !== group.length; i++) {
                            const method = group[i];
                            const s = method.argumentTypes.map(function (t) {
                                return t.className;
                            }).join(":");
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
                    const throwAmbiguousError = function() {
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
            }

            function makeMethod(methodName, type, methodId, retType, argTypes, env) {
                let targetMethodId = methodId;
                let originalMethodId = null;

                const rawRetType = retType.type;
                const rawArgTypes = argTypes.map(function (t) {
                    return t.type;
                });
                let invokeTarget;
                if (type == CONSTRUCTOR_METHOD) {
                    invokeTarget = env.constructor(rawArgTypes);
                } else if (type == STATIC_METHOD) {
                    invokeTarget = env.staticMethod(rawRetType, rawArgTypes);
                } else if (type == INSTANCE_METHOD) {
                    invokeTarget = env.method(rawRetType, rawArgTypes);
                }

                let frameCapacity = 2;
                const argVariableNames = argTypes.map(function (t, i) {
                    return "a" + (i + 1);
                });
                const callArgs = [
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
                let returnCapture, returnStatements;
                if (rawRetType === 'void') {
                    returnCapture = "";
                    returnStatements = "env.popLocalFrame(NULL);";
                } else {
                    if (retType.fromJni) {
                        frameCapacity++;
                        returnCapture = "rawResult = ";
                        returnStatements = "try {" +
                                "result = retType.fromJni.call(this, rawResult, env);" +
                            "} finally {" +
                                "env.popLocalFrame(NULL);" +
                            "}" +
                            "return result;";
                    } else {
                        returnCapture = "result = ";
                        returnStatements = "env.popLocalFrame(NULL);" +
                            "return result;";
                    }
                }
                let f;
                eval("f = function " + methodName + "(" + argVariableNames.join(", ") + ") {" +
                    "const env = vm.getEnv();" +
                    "if (env.pushLocalFrame(" + frameCapacity + ") !== JNI_OK) {" +
                        "env.exceptionClear();" +
                        "throw new Error(\"Out of memory\");" +
                    "}" +
                    "let result, rawResult;" +
                    "try {" +
                        "synchronizeVtable.call(this, env, type === INSTANCE_METHOD);" +
                        returnCapture + "invokeTarget(" + callArgs.join(", ") + ");" +
                    "} catch (e) {" +
                        "env.popLocalFrame(NULL);" +
                        "throw e;" +
                    "}" +
                    "try {" +
                        "env.checkForExceptionAndThrowIt();" +
                    "} catch (e) {" +
                        "env.popLocalFrame(NULL); " +
                        "throw e;" +
                    "}" +
                    returnStatements +
                "};");

                Object.defineProperty(f, 'holder', {
                    enumerable: true,
                    value: klass
                });

                Object.defineProperty(f, 'type', {
                    enumerable: true,
                    value: type
                });

                let implementation = null;
                function synchronizeVtable(env, instance) {
                    if (originalMethodId === null) {
                        return; // nothing to do – implementation hasn't been replaced
                    }

                    const thread = Memory.readPointer(env.handle.add(JNI_ENV_OFFSET_SELF));
                    const objectPtr = api.dvmDecodeIndirectRef(thread, instance ? this.$handle : this.$classHandle);
                    let classObject;
                    if (instance) {
                        classObject = Memory.readPointer(objectPtr.add(OBJECT_OFFSET_CLAZZ));
                    } else {
                        classObject = objectPtr;
                    }
                    let key = classObject.toString(16);
                    let entry = patchedClasses[key];
                    if (!entry) {
                        const vtablePtr = classObject.add(CLASS_OBJECT_OFFSET_VTABLE);
                        const vtableCountPtr = classObject.add(CLASS_OBJECT_OFFSET_VTABLE_COUNT);
                        const vtable = Memory.readPointer(vtablePtr);
                        const vtableCount = Memory.readS32(vtableCountPtr);

                        const vtableSize = vtableCount * pointerSize;
                        const shadowVtable = Memory.alloc(2 * vtableSize);
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
                    const method = entry.targetMethods[key];
                    if (!method) {
                        const methodIndex = entry.shadowVtableCount++;
                        Memory.writePointer(entry.shadowVtable.add(methodIndex * pointerSize), targetMethodId);
                        Memory.writeU16(targetMethodId.add(METHOD_OFFSET_METHOD_INDEX), methodIndex);
                        Memory.writeS32(entry.vtableCountPtr, entry.shadowVtableCount);

                        entry.targetMethods[key] = f;
                    }
                }
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

                            let argsSize = argTypes.reduce(function (acc, t) { return acc + t.size; }, 0);
                            if (type === INSTANCE_METHOD) {
                                argsSize++;
                            }

                            /*
                             * make method native (with 0x0100)
                             * insSize and registersSize are set to arguments size
                             */
                            const accessFlags = Memory.readU32(methodId.add(METHOD_OFFSET_ACCESS_FLAGS)) | 0x0100;
                            const registersSize = argsSize;
                            const outsSize = 0;
                            const insSize = argsSize;
                            // parse method arguments
                            const jniArgInfo = 0x80000000;

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
            }

            if (superKlass !== null) {
                const Surrogate = function () {
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
        }

        function makeHandleDestructor() {
            const handles = Array.prototype.slice.call(arguments).filter(function (h) {
                return h !== null;
            });
            return function () {
                vm.perform(function () {
                    const env = vm.getEnv();
                    handles.forEach(env.deleteGlobalRef, env);
                });
            };
        }

        function implement(method, fn) {
            const env = vm.getEnv();

            if (method.hasOwnProperty('overloads')) {
                if (method.overloads.length > 1) {
                    throw new Error("Method has more than one overload. Please resolve by for example: `method.overload('int')`");
                }
                method = method.overloads[0];
            }

            const C = method.holder;
            const type = method.type;
            const retType = method.returnType;
            const argTypes = method.argumentTypes;
            const methodName = method.name;
            const rawRetType = retType.type;
            const rawArgTypes = argTypes.map(function (t) { return t.type; });

            let frameCapacity = 2;
            const argVariableNames = argTypes.map(function (t, i) {
                return "a" + (i + 1);
            });
            const callArgs = argTypes.map(function (t, i) {
                if (t.fromJni) {
                    frameCapacity++;
                    return "argTypes[" + i + "].fromJni.call(self, " + argVariableNames[i] + ", env)";
                }
                return argVariableNames[i];
            });
            let returnCapture, returnStatements, returnNothing;
            if (rawRetType === 'void') {
                returnCapture = "";
                returnStatements = "env.popLocalFrame(NULL);";
                returnNothing = "return;";
            } else {
                if (retType.toJni) {
                    frameCapacity++;
                    returnCapture = "result = ";
                    returnStatements = "let rawResult;" +
                        "try {" +
                            "if (retType.isCompatible.call(this, result)) {" +
                                "rawResult = retType.toJni.call(this, result, env);" +
                            "} else {" +
                                "throw new Error(\"Implementation for " + methodName + " expected return value compatible with '" + retType.className + "'.\");" +
                            "}";
                    if (retType.type === 'pointer') {
                        returnStatements += "} catch (e) {" +
                                "env.popLocalFrame(NULL);" +
                                "throw e;" +
                            "}" +
                            "return env.popLocalFrame(rawResult);";
                        returnNothing = "return NULL;";
                    } else {
                        returnStatements += "} finally {" +
                                "env.popLocalFrame(NULL);" +
                            "}" +
                            "return rawResult;";
                        returnNothing = "return 0;";
                    }
                } else {
                    returnCapture = "result = ";
                    returnStatements = "env.popLocalFrame(NULL);" +
                        "return result;";
                    returnNothing = "return 0;";
                }
            }
            let f;
            eval("f = function " + methodName + "(" + ["envHandle", "thisHandle"].concat(argVariableNames).join(", ") + ") {" +
                "const env = new Env(envHandle);" +
                "if (env.pushLocalFrame(" + frameCapacity + ") !== JNI_OK) {" +
                    "return;" +
                "}" +
                "const self = " + ((type === INSTANCE_METHOD) ? "new C(C.__handle__, thisHandle);" : "new C(thisHandle, null);") +
                "let result;" +
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
            "};");

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
        }

        /*
         * http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html#wp9502
         * http://www.liaohuqiu.net/posts/android-object-size-dalvik/
         */
        function getTypeFromJniTypename(typename, unbox) {
            function getPrimitiveType(type) {
                switch (type) {
                    case 'boolean':
                        return {
                            type: 'uint8',
                            size: 1,
                            byteSize: 1,
                            isCompatible: function (v) {
                                return typeof v === 'boolean';
                            },
                            fromJni: function (v) {
                                return v ? true : false;
                            },
                            toJni: function (v) {
                                return v ? 1 : 0;
                            },
                            memoryRead: Memory.readU8,
                            memoryWrite: Memory.writeU8
                        };
                    case 'byte':
                        return {
                            type: 'int8',
                            size: 1,
                            byteSize: 1,
                            isCompatible: function (v) {
                                return Number.isInteger(v) && v >= -128 && v <= 127;
                            },
                            memoryRead: Memory.readS8,
                            memoryWrite: Memory.writeS8
                        };
                    case 'char':
                        return {
                            type: 'uint16',
                            size: 1,
                            byteSize: 2,
                            isCompatible: function (v) {
                                if (typeof v === 'string' && v.length === 1) {
                                    const charCode = v.charCodeAt(0);
                                    return charCode >= 0 && charCode <= 65535;
                                } else {
                                    return false;
                                }
                            },
                            fromJni: function (c) {
                                return String.fromCharCode(c);
                            },
                            toJni: function (s) {
                                return s.charCodeAt(0);
                            },
                            memoryRead: Memory.readU16,
                            memoryWrite: Memory.writeU16
                        };
                    case 'short':
                        return {
                            type: 'int16',
                            size: 1,
                            byteSize: 2,
                            isCompatible: function (v) {
                                return Number.isInteger(v) && v >= -32768 && v <= 32767;
                            },
                            memoryRead: Memory.readS16,
                            memoryWrite: Memory.writeS16
                        };
                    case 'int':
                        return {
                            type: 'int32',
                            size: 1,
                            byteSize: 4,
                            isCompatible: function (v) {
                                return Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
                            },
                            memoryRead: Memory.readS32,
                            memoryWrite: Memory.writeS32
                        };
                    case 'long':
                        return {
                            type: 'int64',
                            size: 2,
                            byteSize: 8,
                            isCompatible: function (v) {
                                // JavaScripts safe integer range is to small for it
                                return Number.isInteger(v); // && v >= -9223372036854775808 && v <= 9223372036854775807;
                            },
                            memoryRead: Memory.readS64,
                            memoryWrite: Memory.writeS64
                        };
                    case 'float':
                        return {
                            type: 'float',
                            size: 1,
                            byteSize: 4,
                            isCompatible: function (v) {
                                // TODO
                                return typeof v === 'number';
                            },
                            memoryRead: Memory.readFloat,
                            memoryWrite: Memory.writeFloat
                        };
                    case 'double':
                        return {
                            type: 'double',
                            size: 2,
                            byteSize: 8,
                            isCompatible: function (v) {
                                // TODO
                                return typeof v === 'number';
                            },
                            memoryRead: Memory.readDouble,
                            memoryWrite: Memory.writeDouble
                        };
                    case 'void':
                        return {
                            type: 'void',
                            size: 0,
                            byteSize: 0,
                            isCompatible: function (v) {
                                return v === undefined;
                            }
                        };
                    default:
                        return undefined;
                }
            }

            function getArrayType(typename, unbox) {
                function fromJniObjectArray(arr, env, convertFromJniFunc) {
                    if (arr.isNull()) {
                        return null;
                    }
                    const result = [];
                    const length = env.getArrayLength(arr);
                    for (let i = 0; i < length; i++) {
                        const elemHandle = env.getObjectArrayElement(arr, i);

                        // Maybe ArrayIndexOutOfBoundsException: if 'i' does not specify a valid index in the array - should not be the case
                        env.checkForExceptionAndThrowIt();
                        try {
                            result.push(convertFromJniFunc(this, elemHandle));
                        } finally {
                            env.deleteLocalRef(elemHandle);
                        }
                    }
                    return result;
                }

                function toJniObjectArray(arr, env, classHandle, setObjectArrayFunc) {
                    if (arr === null) {
                        return NULL_OBJECT;
                    }
                    const length = arr.length;
                    const result = env.newObjectArray.call(env, length, classHandle, NULL);

                    // Maybe OutOfMemoryError
                    env.checkForExceptionAndThrowIt();
                    if (result.isNull()) {
                        return NULL_OBJECT;
                    }
                    for (let i = 0; i < length; i++) {
                        setObjectArrayFunc.call(env, i, result);
                        // maybe ArrayIndexOutOfBoundsException or ArrayStoreException
                        env.checkForExceptionAndThrowIt();
                    }
                    return result;
                }

                function fromJniPrimitiveArray(arr, typename, env, getArrayLengthFunc, getArrayElementsFunc, releaseArrayElementsFunc) {
                    if (arr.isNull()) {
                        return null;
                    }
                    const result = [];
                    const type = getTypeFromJniTypename(typename);
                    const length = getArrayLengthFunc.call(env, arr);
                    const cArr = getArrayElementsFunc.call(env, arr);
                    if (cArr.isNull()) {
                        throw new Error("Can't get the array elements.");
                    }
                    try {
                        const offset = type.byteSize;
                        for (let i = 0; i < length; i++) {
                            const value = type.memoryRead(cArr.add(i * offset));
                            if (type.fromJni) {
                                result.push(type.fromJni(value));
                            } else {
                                result.push(value);
                            }
                        }
                    } finally {
                        releaseArrayElementsFunc.call(env, arr, cArr);
                    }

                    return result;
                }

                function toJniPrimitiveArray(arr, typename, env, newArrayFunc, setArrayFunc) {
                    if (arr === null) {
                        return NULL_OBJECT;
                    }
                    const length = arr.length;
                    const type = getTypeFromJniTypename(typename);
                    const result = newArrayFunc.call(env, length);
                    if (result.isNull()) {
                        throw new Error("The array can't be constructed.");
                    }

                    // we have to alloc memory only if there are array items
                    if (length > 0) {
                        const cArray = Memory.alloc(length * type.byteSize);
                        for (let i = 0; i < length; i++) {
                            if (type.toJni) {
                                type.memoryWrite(cArray.add(i * type.byteSize), type.toJni(arr[i]));
                            } else {
                                type.memoryWrite(cArray.add(i * type.byteSize), arr[i]);
                            }
                        }
                        setArrayFunc.call(env, result, 0, length, cArray);
                        // check for ArrayIndexOutOfBoundsException
                        env.checkForExceptionAndThrowIt();
                    }

                    return result;
                }

                function isCompatiblePrimitiveArray(v, typename) {
                    return v === null || typeof v === 'object' && v.hasOwnProperty('length') &&
                        Array.prototype.every.call(v, elem => getTypeFromJniTypename(typename).isCompatible(elem));
                }

                switch (typename) {
                    case '[Z':
                        return {
                            type: 'pointer',
                            size: 1,
                            isCompatible: function (v) {
                                return isCompatiblePrimitiveArray(v, 'boolean');
                            },
                            fromJni: function (h, env) {
                                return fromJniPrimitiveArray(h, 'boolean', env, env.getArrayLength, env.getBooleanArrayElements, env.releaseBooleanArrayElements);
                            },
                            toJni: function (arr, env) {
                                return toJniPrimitiveArray(arr, 'boolean', env, env.newBooleanArray, env.setBooleanArrayRegion);
                            }
                        };
                        break;
                    case '[B':
                        return {
                            type: 'pointer',
                            size: 1,
                            isCompatible: function (v) {
                                return isCompatiblePrimitiveArray(v, 'byte');
                            },
                            fromJni: function (h, env) {
                                return fromJniPrimitiveArray(h, 'byte', env, env.getArrayLength, env.getByteArrayElements, env.releaseByteArrayElements);
                            },
                            toJni: function (arr, env) {
                                return toJniPrimitiveArray(arr, 'byte', env, env.newByteArray, env.setByteArrayRegion);
                            }
                        };
                        break;
                    case '[C':
                        return {
                            type: 'pointer',
                            size: 1,
                            isCompatible: function (v) {
                                return isCompatiblePrimitiveArray(v, 'char');
                            },
                            fromJni: function (h, env) {
                                return fromJniPrimitiveArray(h, 'char', env, env.getArrayLength, env.getCharArrayElements, env.releaseCharArrayElements);
                            },
                            toJni: function (arr, env) {
                                return toJniPrimitiveArray(arr, 'char', env, env.newCharArray, env.setCharArrayRegion);
                            }
                        };
                        break;
                    case '[D':
                        return {
                            type: 'pointer',
                            size: 1,
                            isCompatible: function (v) {
                                return isCompatiblePrimitiveArray(v, 'double');
                            },
                            fromJni: function (h, env) {
                                return fromJniPrimitiveArray(h, 'double', env, env.getArrayLength, env.getDoubleArrayElements, env.releaseDoubleArrayElements);
                            },
                            toJni: function (arr, env) {
                                return toJniPrimitiveArray(arr, 'double', env, env.newDoubleArray, env.setDoubleArrayRegion);
                            }
                        };
                        break;
                    case '[F':
                        return {
                            type: 'pointer',
                            size: 1,
                            isCompatible: function (v) {
                                return isCompatiblePrimitiveArray(v, 'float');
                            },
                            fromJni: function (h, env) {
                                return fromJniPrimitiveArray(h, 'float', env, env.getArrayLength, env.getFloatArrayElements, env.releaseFloatArrayElements);
                            },
                            toJni: function (arr, env) {
                                return toJniPrimitiveArray(arr, 'float', env, env.newFloatArray, env.setFloatArrayRegion);
                            }
                        };
                        break;
                    case '[I':
                        return {
                            type: 'pointer',
                            size: 1,
                            isCompatible: function (v) {
                                return isCompatiblePrimitiveArray(v, 'int');
                            },
                            fromJni: function (h, env) {
                                return fromJniPrimitiveArray(h, 'int', env, env.getArrayLength, env.getIntArrayElements, env.releaseIntArrayElements);
                            },
                            toJni: function (arr, env) {
                                return toJniPrimitiveArray(arr, 'int', env, env.newIntArray, env.setIntArrayRegion);
                            }
                        };
                        break;
                    case '[J':
                        return {
                            type: 'pointer',
                            size: 1,
                            isCompatible: function (v) {
                                return isCompatiblePrimitiveArray(v, 'long');
                            },
                            fromJni: function (h, env) {
                                return fromJniPrimitiveArray(h, 'long', env, env.getArrayLength, env.getLongArrayElements, env.releaseLongArrayElements);
                            },
                            toJni: function (arr, env) {
                                return toJniPrimitiveArray(arr, 'long', env, env.newLongArray, env.setLongArrayRegion);
                            }
                        };
                        break;
                    case '[S':
                        return {
                            type: 'pointer',
                            size: 1,
                            isCompatible: function (v) {
                                return isCompatiblePrimitiveArray(v, 'short');
                            },
                            fromJni: function (h, env) {
                                return fromJniPrimitiveArray(h, 'short', env, env.getArrayLength, env.getShortArrayElements, env.releaseShortArrayElements);
                            },
                            toJni: function (arr, env) {
                                return toJniPrimitiveArray(arr, 'short', env, env.newShortArray, env.setShortArrayRegion);
                            }
                        };
                        break;
                    default:
                        // it has to be an objectArray, but maybe it goes wrong
                        let elementType;
                        if (typename.indexOf('[') === 0) {
                            elementType = getTypeFromJniTypename(typename.substring(1), unbox);
                        } else {
                            throw new Error("Unsupported type here " + typename);
                        }
                        return {
                            type: 'pointer',
                            size: 1,
                            isCompatible: function (v) {
                                if (v === null) {
                                    return true;
                                } else if (typeof v !== 'object' || !v.hasOwnProperty('length')) {
                                    return false;
                                }
                                return v.every(function (element) {
                                    return elementType.isCompatible(element);
                                });
                            },
                            fromJni: function (arr, env) {
                                return fromJniObjectArray.call(this, arr, env, function (self, elem) {
                                    return elementType.fromJni.call(self, elem, env);
                                });
                            },
                            toJni: function (elements, env) {
                                let classHandle, klassObj;
                                if (loader !== null) {
                                    if (typename[0] === "L" && typename[typename.length - 1] === ";") {
                                        typename = typename.substring(1, typename.length - 1);
                                    }
                                    klassObj = loader.loadClass(typename);
                                    classHandle = klassObj.$classHandle;
                                } else {
                                    classHandle = env.findClass(typename.replace(/\./g, "/"));
                                }

                                try {
                                    return toJniObjectArray(elements, env, classHandle,
                                        function (i, result) {
                                            const handle = elementType.toJni.call(this, elements[i], env);
                                            try {
                                                env.setObjectArrayElement(result, i, handle);
                                            } finally {
                                                if (elementType.type === 'pointer' && env.getObjectRefType(handle) === JNILocalRefType) {
                                                    env.deleteLocalRef(handle);
                                                }
                                            }
                                        });
                                } finally {
                                    if (loader !== null) {
                                        classHandle = null;
                                        klassObj = null;
                                    } else {
                                        env.deleteLocalRef(classHandle);
                                    }
                                }
                            }
                        };
                }
            }

            function getObjectType(typename, unbox) {
                return {
                    type: 'pointer',
                    size: 1,
                    isCompatible: function (v) {
                        if (v === null) {
                            return true;
                        } else if ((typename === 'java.lang.CharSequence' || typename === 'java.lang.String') && typeof v === 'string') {
                            return true;
                        }

                        return typeof v === 'object' && v.hasOwnProperty('$handle'); // TODO: improve strictness
                    },
                    fromJni: function (h, env) {
                        if (h.isNull()) {
                            return null;
                        } else if (typename === 'java.lang.String' && unbox) {
                            return env.stringFromJni(h);
                        } else if (this && this.$handle !== null && env.isSameObject(h, this.$handle)) {
                            return this;
                        } else {
                            return factory.cast(h, factory.use(typename));
                        }
                    },
                    toJni: function (o, env) {
                        if (o === null) {
                            return NULL_OBJECT;
                        } else if (typeof o === 'string') {
                            return env.newStringUtf(o);
                        }

                        return o.$handle;
                    }
                };
            }

            if (unbox === undefined) {
                unbox = true;
            }

            // check if it's a primitive type
            let type = getPrimitiveType(typename);
            if (!type) {
                // is it an array?
                if (typename.indexOf("[") === 0) {
                    type = getArrayType(typename, unbox);
                } else {
                    if (typename[0] === "L" && typename[typename.length - 1] === ";") {
                        typename = typename.substring(1, typename.length - 1);
                    }
                    type = getObjectType(typename, unbox);
                }
            }

            const result = {
                className: typename
            };
            for (let key in type) {
                if (type.hasOwnProperty(key)) {
                    result[key] = type[key];
                }
            }
            return result;
        }

        initialize.call(this);
    }

    function VM(api) {
        let handle = null;
        let attachCurrentThread = null;
        let detachCurrentThread = null;
        let getEnv = null;

        function initialize() {
            handle = Memory.readPointer(api.gDvmJni.add(8));

            const vtable = Memory.readPointer(handle);
            attachCurrentThread = new NativeFunction(Memory.readPointer(vtable.add(4 * pointerSize)), 'int32', ['pointer', 'pointer', 'pointer']);
            detachCurrentThread = new NativeFunction(Memory.readPointer(vtable.add(5 * pointerSize)), 'int32', ['pointer']);
            getEnv = new NativeFunction(Memory.readPointer(vtable.add(6 * pointerSize)), 'int32', ['pointer', 'pointer', 'int32']);
        }

        this.perform = function (fn) {
            let env = this.tryGetEnv();
            const alreadyAttached = env !== null;
            if (!alreadyAttached) {
                env = this.attachCurrentThread();
            }

            let pendingException = null;
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
            const envBuf = Memory.alloc(pointerSize);
            checkJniResult("VM::AttachCurrentThread", attachCurrentThread(handle, envBuf, NULL));
            return new Env(Memory.readPointer(envBuf));
        };

        this.detachCurrentThread = function () {
            checkJniResult("VM::DetachCurrentThread", detachCurrentThread(handle));
        };

        this.getEnv = function () {
            const envBuf = Memory.alloc(pointerSize);
            checkJniResult("VM::GetEnv", getEnv(handle, envBuf, JNI_VERSION_1_6));
            return new Env(Memory.readPointer(envBuf));
        };

        this.tryGetEnv = function () {
            const envBuf = Memory.alloc(pointerSize);
            const result = getEnv(handle, envBuf, JNI_VERSION_1_6);
            if (result !== JNI_OK) {
                return null;
            }
            return new Env(Memory.readPointer(envBuf));
        };

        initialize.call(this);
    }

    function Env(handle) {
        this.handle = handle;
    }

    (function () {
        const CALL_CONSTRUCTOR_METHOD_OFFSET = 28;

        const CALL_OBJECT_METHOD_OFFSET = 34;
        const CALL_BOOLEAN_METHOD_OFFSET = 37;
        const CALL_BYTE_METHOD_OFFSET = 40;
        const CALL_CHAR_METHOD_OFFSET = 43;
        const CALL_SHORT_METHOD_OFFSET = 46;
        const CALL_INT_METHOD_OFFSET = 49;
        const CALL_LONG_METHOD_OFFSET = 52;
        const CALL_FLOAT_METHOD_OFFSET = 55;
        const CALL_DOUBLE_METHOD_OFFSET = 58;
        const CALL_VOID_METHOD_OFFSET = 61;

        const CALL_STATIC_OBJECT_METHOD_OFFSET = 114;
        const CALL_STATIC_BOOLEAN_METHOD_OFFSET = 117;
        const CALL_STATIC_BYTE_METHOD_OFFSET = 120;
        const CALL_STATIC_CHAR_METHOD_OFFSET = 123;
        const CALL_STATIC_SHORT_METHOD_OFFSET = 126;
        const CALL_STATIC_INT_METHOD_OFFSET = 129;
        const CALL_STATIC_LONG_METHOD_OFFSET = 132;
        const CALL_STATIC_FLOAT_METHOD_OFFSET = 135;
        const CALL_STATIC_DOUBLE_METHOD_OFFSET = 138;
        const CALL_STATIC_VOID_METHOD_OFFSET = 141;

        const GET_OBJECT_FIELD_OFFSET = 95;
        const GET_BOOLEAN_FIELD_OFFSET = 96;
        const GET_BYTE_FIELD_OFFSET = 97;
        const GET_CHAR_FIELD_OFFSET = 98;
        const GET_SHORT_FIELD_OFFSET = 99;
        const GET_INT_FIELD_OFFSET = 100;
        const GET_LONG_FIELD_OFFSET = 101;
        const GET_FLOAT_FIELD_OFFSET = 102;
        const GET_DOUBLE_FIELD_OFFSET = 103;

        const SET_OBJECT_FIELD_OFFSET = 104;
        const SET_BOOLEAN_FIELD_OFFSET = 105;
        const SET_BYTE_FIELD_OFFSET = 106;
        const SET_CHAR_FIELD_OFFSET = 107;
        const SET_SHORT_FIELD_OFFSET = 108;
        const SET_INT_FIELD_OFFSET = 109;
        const SET_LONG_FIELD_OFFSET = 110;
        const SET_FLOAT_FIELD_OFFSET = 111;
        const SET_DOUBLE_FIELD_OFFSET = 112;

        const GET_STATIC_OBJECT_FIELD_OFFSET = 145;
        const GET_STATIC_BOOLEAN_FIELD_OFFSET = 146;
        const GET_STATIC_BYTE_FIELD_OFFSET = 147;
        const GET_STATIC_CHAR_FIELD_OFFSET = 148;
        const GET_STATIC_SHORT_FIELD_OFFSET = 149;
        const GET_STATIC_INT_FIELD_OFFSET = 150;
        const GET_STATIC_LONG_FIELD_OFFSET = 151;
        const GET_STATIC_FLOAT_FIELD_OFFSET = 152;
        const GET_STATIC_DOUBLE_FIELD_OFFSET = 153;

        const SET_STATIC_OBJECT_FIELD_OFFSET = 154;
        const SET_STATIC_BOOLEAN_FIELD_OFFSET = 155;
        const SET_STATIC_BYTE_FIELD_OFFSET = 156;
        const SET_STATIC_CHAR_FIELD_OFFSET = 157;
        const SET_STATIC_SHORT_FIELD_OFFSET = 158;
        const SET_STATIC_INT_FIELD_OFFSET = 159;
        const SET_STATIC_LONG_FIELD_OFFSET = 160;
        const SET_STATIC_FLOAT_FIELD_OFFSET = 161;
        const SET_STATIC_DOUBLE_FIELD_OFFSET = 162;

        const callMethodOffset = {
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

        const callStaticMethodOffset = {
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

        const getFieldOffset = {
            'pointer': GET_OBJECT_FIELD_OFFSET,
            'uint8': GET_BOOLEAN_FIELD_OFFSET,
            'int8': GET_BYTE_FIELD_OFFSET,
            'uint16': GET_CHAR_FIELD_OFFSET,
            'int16': GET_SHORT_FIELD_OFFSET,
            'int32': GET_INT_FIELD_OFFSET,
            'int64': GET_LONG_FIELD_OFFSET,
            'float': GET_FLOAT_FIELD_OFFSET,
            'double': GET_DOUBLE_FIELD_OFFSET
        };

        const setFieldOffset = {
            'pointer': SET_OBJECT_FIELD_OFFSET,
            'uint8': SET_BOOLEAN_FIELD_OFFSET,
            'int8': SET_BYTE_FIELD_OFFSET,
            'uint16': SET_CHAR_FIELD_OFFSET,
            'int16': SET_SHORT_FIELD_OFFSET,
            'int32': SET_INT_FIELD_OFFSET,
            'int64': SET_LONG_FIELD_OFFSET,
            'float': SET_FLOAT_FIELD_OFFSET,
            'double': SET_DOUBLE_FIELD_OFFSET
        };

        const getStaticFieldOffset = {
            'pointer': GET_STATIC_OBJECT_FIELD_OFFSET,
            'uint8': GET_STATIC_BOOLEAN_FIELD_OFFSET,
            'int8': GET_STATIC_BYTE_FIELD_OFFSET,
            'uint16': GET_STATIC_CHAR_FIELD_OFFSET,
            'int16': GET_STATIC_SHORT_FIELD_OFFSET,
            'int32': GET_STATIC_INT_FIELD_OFFSET,
            'int64': GET_STATIC_LONG_FIELD_OFFSET,
            'float': GET_STATIC_FLOAT_FIELD_OFFSET,
            'double': GET_STATIC_DOUBLE_FIELD_OFFSET
        };

        const setStaticFieldOffset = {
            'pointer': SET_STATIC_OBJECT_FIELD_OFFSET,
            'uint8': SET_STATIC_BOOLEAN_FIELD_OFFSET,
            'int8': SET_STATIC_BYTE_FIELD_OFFSET,
            'uint16': SET_STATIC_CHAR_FIELD_OFFSET,
            'int16': SET_STATIC_SHORT_FIELD_OFFSET,
            'int32': SET_STATIC_INT_FIELD_OFFSET,
            'int64': SET_STATIC_LONG_FIELD_OFFSET,
            'float': SET_STATIC_FLOAT_FIELD_OFFSET,
            'double': SET_STATIC_DOUBLE_FIELD_OFFSET
        };

        let cachedVtable = null;
        let globalRefs = [];
        Env.dispose = function (env) {
            globalRefs.forEach(env.deleteGlobalRef, env);
            globalRefs = [];
        };

        function register(globalRef) {
            globalRefs.push(globalRef);
            return globalRef;
        }

        function vtable(instance) {
            if (cachedVtable === null) {
                cachedVtable = Memory.readPointer(instance.handle);
            }
            return cachedVtable;
        }

        function proxy(offset, retType, argTypes, wrapper) {
            let impl = null;
            return function () {
                if (impl === null) {
                    impl = new NativeFunction(Memory.readPointer(vtable(this).add(offset * pointerSize)), retType, argTypes);
                }
                let args = [impl];
                args = args.concat.apply(args, arguments);
                return wrapper.apply(this, args);
            };
        }

        Env.prototype.findClass = proxy(6, 'pointer', ['pointer', 'pointer'], function (impl, name) {
            const result = impl(this.handle, Memory.allocUtf8String(name));
            this.checkForExceptionAndThrowIt();
            return result;
        });

        Env.prototype.checkForExceptionAndThrowIt = function () {
            const throwable = this.exceptionOccurred();
            if (!throwable.isNull()) {
                try {
                    this.exceptionClear();
                    const description = this.method('pointer', [])(this.handle, throwable, this.javaLangObject().toString);
                    try {
                        const descriptionStr = this.stringFromJni(description);
                        throw new Error(descriptionStr);
                    } finally {
                        this.deleteLocalRef(description);
                    }
                } finally {
                    this.deleteLocalRef(throwable);
                }
            }
        };

        Env.prototype.fromReflectedMethod = proxy(7, 'pointer', ['pointer', 'pointer'], function (impl, method) {
            return impl(this.handle, method);
        });

        Env.prototype.fromReflectedField = proxy(8, 'pointer', ['pointer', 'pointer'], function (impl, method) {
            return impl(this.handle, method);
        });

        Env.prototype.getSuperclass = proxy(10, 'pointer', ['pointer', 'pointer'], function (impl, klass) {
            return impl(this.handle, klass);
        });

        Env.prototype.isAssignableFrom = proxy(11, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, klass1, klass2) {
            return impl(this.handle, klass1, klass2) ? true : false;
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
            const utf = Memory.allocUtf8String(str);
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

        Env.prototype.newBooleanArray = proxy(175, 'pointer', ['pointer', 'int32'], function (impl, length) {
            return impl(this.handle, length);
        });

        Env.prototype.newByteArray = proxy(176, 'pointer', ['pointer', 'int32'], function (impl, length) {
            return impl(this.handle, length);
        });

        Env.prototype.newCharArray = proxy(177, 'pointer', ['pointer', 'int32'], function (impl, length) {
            return impl(this.handle, length);
        });

        Env.prototype.newShortArray = proxy(178, 'pointer', ['pointer', 'int32'], function (impl, length) {
            return impl(this.handle, length);
        });

        Env.prototype.newIntArray = proxy(179, 'pointer', ['pointer', 'int32'], function (impl, length) {
            return impl(this.handle, length);
        });

        Env.prototype.newLongArray = proxy(180, 'pointer', ['pointer', 'int32'], function (impl, length) {
            return impl(this.handle, length);
        });

        Env.prototype.newFloatArray = proxy(181, 'pointer', ['pointer', 'int32'], function (impl, length) {
            return impl(this.handle, length);
        });

        Env.prototype.newDoubleArray = proxy(182, 'pointer', ['pointer', 'int32'], function (impl, length) {
            return impl(this.handle, length);
        });

        Env.prototype.getBooleanArrayElements = proxy(183, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
            return impl(this.handle, array, NULL);
        });

        Env.prototype.getByteArrayElements = proxy(184, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
            return impl(this.handle, array, NULL);
        });

        Env.prototype.getCharArrayElements = proxy(185, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
            return impl(this.handle, array, NULL);
        });

        Env.prototype.getShortArrayElements = proxy(186, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
            return impl(this.handle, array, NULL);
        });

        Env.prototype.getIntArrayElements = proxy(187, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
            return impl(this.handle, array, NULL);
        });

        Env.prototype.getLongArrayElements = proxy(188, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
            return impl(this.handle, array, NULL);
        });

        Env.prototype.getFloatArrayElements = proxy(189, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
            return impl(this.handle, array, NULL);
        });

        Env.prototype.getDoubleArrayElements = proxy(190, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
            return impl(this.handle, array, NULL);
        });

        Env.prototype.releaseBooleanArrayElements = proxy(191, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
            impl(this.handle, array, cArray, JNI_ABORT);
        });

        Env.prototype.releaseByteArrayElements = proxy(192, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
            impl(this.handle, array, cArray, JNI_ABORT);
        });

        Env.prototype.releaseCharArrayElements = proxy(193, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
            impl(this.handle, array, cArray, JNI_ABORT);
        });

        Env.prototype.releaseShortArrayElements = proxy(194, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
            impl(this.handle, array, cArray, JNI_ABORT);
        });

        Env.prototype.releaseIntArrayElements = proxy(195, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
            impl(this.handle, array, cArray, JNI_ABORT);
        });

        Env.prototype.releaseLongArrayElements = proxy(196, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
            impl(this.handle, array, cArray, JNI_ABORT);
        });

        Env.prototype.releaseFloatArrayElements = proxy(197, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
            impl(this.handle, array, cArray, JNI_ABORT);
        });

        Env.prototype.releaseDoubleArrayElements = proxy(198, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
            impl(this.handle, array, cArray, JNI_ABORT);
        });

        Env.prototype.setBooleanArrayRegion = proxy(207, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
            impl(this.handle, array, start, length, cArray);
        });

        Env.prototype.setByteArrayRegion = proxy(208, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
            impl(this.handle, array, start, length, cArray);
        });

        Env.prototype.setCharArrayRegion = proxy(209, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
            impl(this.handle, array, start, length, cArray);
        });

        Env.prototype.setShortArrayRegion = proxy(210, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
            impl(this.handle, array, start, length, cArray);
        });

        Env.prototype.setIntArrayRegion = proxy(211, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
            impl(this.handle, array, start, length, cArray);
        });

        Env.prototype.setLongArrayRegion = proxy(212, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
            impl(this.handle, array, start, length, cArray);
        });

        Env.prototype.setFloatArrayRegion = proxy(213, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
            impl(this.handle, array, start, length, cArray);
        });

        Env.prototype.setDoubleArrayRegion = proxy(214, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
            impl(this.handle, array, start, length, cArray);
        });

        Env.prototype.getObjectRefType = proxy(232, 'int32', ['pointer', 'pointer'], function (impl, ref) {
            return impl(this.handle, ref);
        });

        const cachedMethods = {};
        function method(offset, retType, argTypes) {
            const key = offset + "|" + retType + "|" + argTypes.join(":");
            let m = cachedMethods[key];
            if (!m) {
                m = new NativeFunction(Memory.readPointer(vtable(this).add(offset * pointerSize)), retType, ['pointer', 'pointer', 'pointer', '...'].concat(argTypes));
                cachedMethods[key] = m;
            }
            return m;
        }

        Env.prototype.constructor = function (argTypes) {
            return method(CALL_CONSTRUCTOR_METHOD_OFFSET, 'pointer', argTypes);
        };

        Env.prototype.method = function (retType, argTypes) {
            const offset = callMethodOffset[retType];
            if (offset === undefined)
                throw new Error("Unsupported type: " + retType);
            return method(offset, retType, argTypes);
        };

        Env.prototype.staticMethod = function (retType, argTypes) {
            const offset = callStaticMethodOffset[retType];
            if (offset === undefined)
                throw new Error("Unsupported type: " + retType);
            return method(offset, retType, argTypes);
        };

        Env.prototype.getField = function (fieldType) {
            const offset = getFieldOffset[fieldType];
            if (offset === undefined)
                throw new Error("Unsupported type: " + fieldType);
            return method(offset, fieldType, []);
        };

        Env.prototype.getStaticField = function (fieldType) {
            const offset = getStaticFieldOffset[fieldType];
            if (offset === undefined)
                throw new Error("Unsupported type: " + fieldType);
            return method(offset, fieldType, []);
        };

        Env.prototype.setField = function (fieldType) {
            const offset = setFieldOffset[fieldType];
            if (offset === undefined)
                throw new Error("Unsupported type: " + fieldType);
            return method(offset, 'void', [fieldType]);
        };

        Env.prototype.setStaticField = function (fieldType) {
            const offset = setStaticFieldOffset[fieldType];
            if (offset === undefined)
                throw new Error("Unsupported type: " + fieldType);
            return method(offset, 'void', [fieldType]);
        };

        let javaLangClass = null;
        Env.prototype.javaLangClass = function () {
            if (javaLangClass === null) {
                const handle = this.findClass("java/lang/Class");
                try {
                    javaLangClass = {
                        handle: register(this.newGlobalRef(handle)),
                        getName: this.getMethodId(handle, "getName", "()Ljava/lang/String;"),
                        getSimpleName: this.getMethodId(handle, "getSimpleName", "()Ljava/lang/String;"),
                        getGenericSuperclass: this.getMethodId(handle, "getGenericSuperclass", "()Ljava/lang/reflect/Type;"),
                        getDeclaredConstructors: this.getMethodId(handle, "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;"),
                        getDeclaredMethods: this.getMethodId(handle, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;"),
                        getDeclaredFields: this.getMethodId(handle, "getDeclaredFields", "()[Ljava/lang/reflect/Field;"),
                        isArray: this.getMethodId(handle, "isArray", "()Z"),
                        isPrimitive: this.getMethodId(handle, "isPrimitive", "()Z"),
                        getComponentType: this.getMethodId(handle, "getComponentType", "()Ljava/lang/Class;")
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangClass;
        };

        let javaLangObject = null;
        Env.prototype.javaLangObject = function () {
            if (javaLangObject === null) {
                const handle = this.findClass("java/lang/Object");
                try {
                    javaLangObject = {
                        toString: this.getMethodId(handle, "toString", "()Ljava/lang/String;"),
                        getClass: this.getMethodId(handle, "getClass", "()Ljava/lang/Class;")
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangObject;
        };

        let javaLangReflectConstructor = null;
        Env.prototype.javaLangReflectConstructor = function () {
            if (javaLangReflectConstructor === null) {
                const handle = this.findClass("java/lang/reflect/Constructor");
                try {
                    javaLangReflectConstructor = {
                        getGenericParameterTypes: this.getMethodId(handle, "getGenericParameterTypes", "()[Ljava/lang/reflect/Type;")
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangReflectConstructor;
        };

        let javaLangReflectMethod = null;
        Env.prototype.javaLangReflectMethod = function () {
            if (javaLangReflectMethod === null) {
                const handle = this.findClass("java/lang/reflect/Method");
                try {
                    javaLangReflectMethod = {
                        getName: this.getMethodId(handle, "getName", "()Ljava/lang/String;"),
                        getGenericParameterTypes: this.getMethodId(handle, "getGenericParameterTypes", "()[Ljava/lang/reflect/Type;"),
                        getGenericReturnType: this.getMethodId(handle, "getGenericReturnType", "()Ljava/lang/reflect/Type;"),
                        getModifiers: this.getMethodId(handle, "getModifiers", "()I"),
                        isVarArgs: this.getMethodId(handle, "isVarArgs", "()Z")
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangReflectMethod;
        };

        let javaLangReflectField = null;
        Env.prototype.javaLangReflectField = function () {
            if (javaLangReflectField === null) {
                const handle = this.findClass("java/lang/reflect/Field");
                try {
                    javaLangReflectField = {
                        getName: this.getMethodId(handle, "getName", "()Ljava/lang/String;"),
                        getType: this.getMethodId(handle, "getType", "()Ljava/lang/Class;"),
                        getGenericType: this.getMethodId(handle, "getGenericType", "()Ljava/lang/reflect/Type;"),
                        getModifiers: this.getMethodId(handle, "getModifiers", "()I"),
                        toString: this.getMethodId(handle, "toString", '()Ljava/lang/String;')
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangReflectField;
        };

        let javaLangReflectModifier = null;
        Env.prototype.javaLangReflectModifier = function () {
            if (javaLangReflectModifier === null) {
                const handle = this.findClass("java/lang/reflect/Modifier");
                try {
                    javaLangReflectModifier = {
                        PUBLIC: this.getStaticIntField(handle, this.getStaticFieldId(handle, "PUBLIC", "I")),
                        PRIVATE: this.getStaticIntField(handle, this.getStaticFieldId(handle, "PRIVATE", "I")),
                        PROTECTED: this.getStaticIntField(handle, this.getStaticFieldId(handle, "PROTECTED", "I")),
                        STATIC: this.getStaticIntField(handle, this.getStaticFieldId(handle, "STATIC", "I")),
                        FINAL: this.getStaticIntField(handle, this.getStaticFieldId(handle, "FINAL", "I")),
                        SYNCHRONIZED: this.getStaticIntField(handle, this.getStaticFieldId(handle, "SYNCHRONIZED", "I")),
                        VOLATILE: this.getStaticIntField(handle, this.getStaticFieldId(handle, "VOLATILE", "I")),
                        TRANSIENT: this.getStaticIntField(handle, this.getStaticFieldId(handle, "TRANSIENT", "I")),
                        NATIVE: this.getStaticIntField(handle, this.getStaticFieldId(handle, "NATIVE", "I")),
                        INTERFACE: this.getStaticIntField(handle, this.getStaticFieldId(handle, "INTERFACE", "I")),
                        ABSTRACT: this.getStaticIntField(handle, this.getStaticFieldId(handle, "ABSTRACT", "I")),
                        STRICT: this.getStaticIntField(handle, this.getStaticFieldId(handle, "STRICT", "I"))
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangReflectModifier;
        };

        let javaLangReflectTypeVariable = null;
        Env.prototype.javaLangReflectTypeVariable = function () {
            if (javaLangReflectTypeVariable === null) {
                const handle = this.findClass("java/lang/reflect/TypeVariable");
                try {
                    javaLangReflectTypeVariable = {
                        handle: register(this.newGlobalRef(handle)),
                        getName: this.getMethodId(handle, "getName", "()Ljava/lang/String;"),
                        getBounds: this.getMethodId(handle, "getBounds", "()[Ljava/lang/reflect/Type;"),
                        getGenericDeclaration: this.getMethodId(handle, "getGenericDeclaration", "()Ljava/lang/reflect/GenericDeclaration;")
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangReflectTypeVariable;
        };

        let javaLangReflectWildcardType = null;
        Env.prototype.javaLangReflectWildcardType = function () {
            if (javaLangReflectWildcardType === null) {
                const handle = this.findClass("java/lang/reflect/WildcardType");
                try {
                    javaLangReflectWildcardType = {
                        handle: register(this.newGlobalRef(handle)),
                        getLowerBounds: this.getMethodId(handle, "getLowerBounds", "()[Ljava/lang/reflect/Type;"),
                        getUpperBounds: this.getMethodId(handle, "getUpperBounds", "()[Ljava/lang/reflect/Type;")
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangReflectWildcardType;
        };

        let javaLangReflectGenericArrayType = null;
        Env.prototype.javaLangReflectGenericArrayType = function () {
            if (javaLangReflectGenericArrayType === null) {
                const handle = this.findClass("java/lang/reflect/GenericArrayType");
                try {
                    javaLangReflectGenericArrayType = {
                        handle: register(this.newGlobalRef(handle)),
                        getGenericComponentType: this.getMethodId(handle, "getGenericComponentType", "()Ljava/lang/reflect/Type;")
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangReflectGenericArrayType;
        };

        let javaLangReflectParameterizedType = null;
        Env.prototype.javaLangReflectParameterizedType = function () {
            if (javaLangReflectParameterizedType === null) {
                const handle = this.findClass("java/lang/reflect/ParameterizedType");
                try {
                    javaLangReflectParameterizedType = {
                        handle: register(this.newGlobalRef(handle)),
                        getActualTypeArguments: this.getMethodId(handle, "getActualTypeArguments", "()[Ljava/lang/reflect/Type;"),
                        getRawType: this.getMethodId(handle, "getRawType", "()Ljava/lang/reflect/Type;"),
                        getOwnerType: this.getMethodId(handle, "getOwnerType", "()Ljava/lang/reflect/Type;")
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangReflectParameterizedType;
        };

        let javaLangString = null;
        Env.prototype.javaLangString = function () {
            if (javaLangString === null) {
                const handle = this.findClass("java/lang/String");
                try {
                    javaLangString = {
                        handle: register(this.newGlobalRef(handle))
                    };
                } finally {
                    this.deleteLocalRef(handle);
                }
            }
            return javaLangString;
        };

        Env.prototype.getClassName = function (classHandle) {
            const name = this.method('pointer', [])(this.handle, classHandle, this.javaLangClass().getName);
            try {
                return this.stringFromJni(name);
            } finally {
                this.deleteLocalRef(name);
            }
        };

        Env.prototype.getObjectClassName = function (objHandle) {
            const jklass = this.getObjectClass(objHandle);
            try {
                return this.getClassName(jklass);
            } finally {
                this.deleteLocalRef(jklass);
            }
        };

        Env.prototype.getActualTypeArgument = function (type) {
            const actualTypeArguments = this.method('pointer', [])(this.handle, type, this.javaLangReflectParameterizedType().getActualTypeArguments);
            this.checkForExceptionAndThrowIt();
            if (!actualTypeArguments.isNull()) {
                try {
                    return this.getTypeNameFromFirstTypeElement(actualTypeArguments);
                } finally {
                    this.deleteLocalRef(actualTypeArguments);
                }
            }
        };

        Env.prototype.getTypeNameFromFirstTypeElement = function (typeArray) {
            const length = this.getArrayLength(typeArray);
            if (length > 0) {
                const typeArgument0 = this.getObjectArrayElement(typeArray, 0);
                try {
                    return this.getTypeName(typeArgument0);
                } finally {
                    this.deleteLocalRef(typeArgument0);
                }
            } else {
                // TODO
                return "java.lang.Object";
            }
        };

        Env.prototype.getTypeName = function (type, getGenericsInformation) {
            const invokeObjectMethodNoArgs = this.method('pointer', []);

            if (this.isInstanceOf(type, this.javaLangClass().handle)) {
                return this.getClassName(type);
            } else if (this.isInstanceOf(type, this.javaLangReflectParameterizedType().handle)) {
                const rawType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectParameterizedType().getRawType);
                this.checkForExceptionAndThrowIt();
                let result;
                try {
                    result = this.getTypeName(rawType);
                } finally {
                    this.deleteLocalRef(rawType);
                }

                if (result === "java.lang.Class" && !getGenericsInformation) {
                    return this.getActualTypeArgument(type);
                }

                if (getGenericsInformation) {
                    result += "<" + this.getActualTypeArgument(type) + ">";
                }
                return result;
            } else if (this.isInstanceOf(type, this.javaLangReflectTypeVariable().handle)) {
                // TODO
                return "java.lang.Object";
            } else if (this.isInstanceOf(type, this.javaLangReflectWildcardType().handle)) {
                // TODO
                return "java.lang.Object";
            } else {
                return "java.lang.Object";
            }
        };

        Env.prototype.getArrayTypeName = function (type) {
            const invokeObjectMethodNoArgs = this.method('pointer', []);

            if (this.isInstanceOf(type, this.javaLangClass().handle)) {
                return this.getClassName(type);
            } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
                const componentType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectGenericArrayType().getGenericComponentType);
                // check for TypeNotPresentException and MalformedParameterizedTypeException
                this.checkForExceptionAndThrowIt();
                try {
                    return "[L" + this.getTypeName(componentType) + ";";
                } finally {
                    this.deleteLocalRef(componentType);
                }
            } else {
                return "[Ljava.lang.Object;";
            }
        };

        Env.prototype.stringFromJni = function (str) {
            const utf = this.getStringUtfChars(str);
            if (utf.isNull()) {
                throw new Error("Can't access the string.");
            }
            try {
                return Memory.readUtf8String(utf);
            } finally {
                this.releaseStringUtfChars(str, utf);
            }
        };
    })();

    function getApi() {
        if (_api !== null) {
            return _api;
        }

        const temporaryApi = {
            addLocalReferenceFunc: null
        };
        const pending = [
            {
                module: "libdvm.so",
                functions: {
                    /*
                     * Converts an indirect reference to to an object reference.
                     */
                    "_Z20dvmDecodeIndirectRefP6ThreadP8_jobject": ["dvmDecodeIndirectRef", 'pointer', ['pointer', 'pointer']],

                    "_Z15dvmUseJNIBridgeP6MethodPv": ["dvmUseJNIBridge", 'void', ['pointer', 'pointer']],

                    /*
                     * Returns the base of the HeapSource.
                     */
                    "_Z20dvmHeapSourceGetBasev": ["dvmHeapSourceGetBase", 'pointer', []],

                    /*
                     * Returns the limit of the HeapSource.
                     */
                    "_Z21dvmHeapSourceGetLimitv": ["dvmHeapSourceGetLimit", 'pointer', []],

                    /*
                     *  Returns true if the pointer points to a valid object.
                     */
                    "_Z16dvmIsValidObjectPK6Object": ["dvmIsValidObject", 'uint8', ['pointer']]
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
                                temporaryApi[signature[0]] = new NativeFunction(exp.address, signature[1], signature[2]);
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

    function checkJniResult(name, result) {
        if (result != JNI_OK) {
            throw new Error(name + " failed: " + result);
        }
    }

    function basename(className) {
        return className.slice(className.lastIndexOf(".") + 1);
    }
}).call(this);