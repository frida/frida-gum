/* jshint esnext: true */
(function () {
    "use strict";

    const engine = global;
    const longSize = (Process.pointerSize == 8 && Process.platform !== 'windows') ? 64 : 32;
    let dispatcher;

    function initialize() {
        dispatcher = new MessageDispatcher();

        const proxyClass = global.Proxy;
        if ('create' in proxyClass) {
            const createProxy = proxyClass.create;
            global.Proxy = function (target, handler) {
                return createProxy.call(proxyClass, handler, Object.getPrototypeOf(target));
            };
        }
    }

    Object.defineProperty(engine, 'recv', {
        enumerable: true,
        value: function () {
            let type, callback;
            if (arguments.length === 1) {
                type = '*';
                callback = arguments[0];
            } else {
                type = arguments[0];
                callback = arguments[1];
            }
            return dispatcher.registerCallback(type, callback);
        }
    });

    Object.defineProperty(engine, 'send', {
        enumerable: true,
        value: function (payload, data) {
            const message = {
                type: 'send',
                payload: payload
            };
            engine._send(JSON.stringify(message), data || null);
        }
    });

    Object.defineProperty(engine, 'int64', {
        enumerable: true,
        value: function (value) {
            return new Int64(value);
        }
    });

    Object.defineProperty(engine, 'uint64', {
        enumerable: true,
        value: function (value) {
            return new UInt64(value);
        }
    });

    Object.defineProperty(engine, 'ptr', {
        enumerable: true,
        value: function (str) {
            return new NativePointer(str);
        }
    });

    Object.defineProperty(engine, 'NULL', {
        enumerable: true,
        value: new NativePointer("0")
    });

    NativePointer.prototype.equals = function (ptr) {
        if (!(ptr instanceof NativePointer)) {
            throw new Error("Not a pointer");
        }
        return this.compare(ptr) === 0;
    };

    class Console {
        log() {
            sendLogMessage('info', Array.prototype.join.call(arguments, " "));
        }

        warn() {
            sendLogMessage('warning', Array.prototype.join.call(arguments, " "));
        }

        error() {
            sendLogMessage('error', Array.prototype.join.call(arguments, " "));
        }
    }

    function sendLogMessage(level, text) {
        const message = {
            type: 'log',
            level: level,
            payload: text
        };
        engine._send(JSON.stringify(message), null);
    }

    Object.defineProperty(engine, 'console', {
        enumerable: true,
        value: new Console()
    });

    Object.defineProperty(Memory, 'dup', {
        enumerable: true,
        value: function (mem, size) {
            const result = Memory.alloc(size);
            Memory.copy(result, mem, size);
            return result;
        }
    });

    Object.defineProperty(Memory, 'readShort', {
        enumerable: true,
        value: function (mem) {
            return Memory.readS16(mem);
        }
    });

    Object.defineProperty(Memory, 'writeShort', {
        enumerable: true,
        value: function (mem, value) {
            return Memory.writeS16(mem, value);
        }
    });

    Object.defineProperty(Memory, 'readUShort', {
        enumerable: true,
        value: function (mem) {
            return Memory.readU16(mem);
        }
    });

    Object.defineProperty(Memory, 'writeUShort', {
        enumerable: true,
        value: function (mem, value) {
            return Memory.writeU16(mem, value);
        }
    });

    Object.defineProperty(Memory, 'readInt', {
        enumerable: true,
        value: function (mem) {
            return Memory.readS32(mem);
        }
    });

    Object.defineProperty(Memory, 'writeInt', {
        enumerable: true,
        value: function (mem, value) {
            return Memory.writeS32(mem, value);
        }
    });

    Object.defineProperty(Memory, 'readUInt', {
        enumerable: true,
        value: function (mem) {
            return Memory.readU32(mem);
        }
    });

    Object.defineProperty(Memory, 'writeUInt', {
        enumerable: true,
        value: function (mem, value) {
            return Memory.writeU32(mem, value);
        }
    });

    if (longSize === 64) {
        Object.defineProperty(Memory, 'readLong', {
            enumerable: true,
            value: function (mem) {
                return Memory.readS64(mem);
            }
        });

        Object.defineProperty(Memory, 'writeLong', {
            enumerable: true,
            value: function (mem, value) {
                Memory.writeS64(mem, value);
            }
        });

        Object.defineProperty(Memory, 'readULong', {
            enumerable: true,
            value: function (mem) {
                return Memory.readU64(mem);
            }
        });

        Object.defineProperty(Memory, 'writeULong', {
            enumerable: true,
            value: function (mem, value) {
                Memory.writeU64(mem, value);
            }
        });
    } else {
        Object.defineProperty(Memory, 'readLong', {
            enumerable: true,
            value: function (mem) {
                return new Int64(Memory.readS32(mem));
            }
        });

        Object.defineProperty(Memory, 'writeLong', {
            enumerable: true,
            value: function (mem, value) {
                Memory.writeS32(mem, value);
            }
        });

        Object.defineProperty(Memory, 'readULong', {
            enumerable: true,
            value: function (mem) {
                return new UInt64(Memory.readU32(mem));
            }
        });

        Object.defineProperty(Memory, 'writeULong', {
            enumerable: true,
            value: function (mem, value) {
                Memory.writeU32(mem, value);
            }
        });
    }

    Object.defineProperty(Process, 'findModuleByAddress', {
        enumerable: true,
        value: function (address) {
            let module = null;
            Process.enumerateModules({
                onMatch: function (m) {
                    const base = m.base;
                    if (base.compare(address) < 0 && base.add(m.size).compare(address) > 0) {
                        module = m;
                        return 'stop';
                    }
                },
                onComplete: function () {
                }
            });
            return module;
        }
    });

    Object.defineProperty(Process, 'getModuleByAddress', {
        enumerable: true,
        value: function (address) {
            const module = Process.findModuleByAddress(address);
            if (module === null)
                throw new Error("Unable to find module containing " + address);
            return module;
        }
    });

    Object.defineProperty(Process, 'findModuleByName', {
        enumerable: true,
        value: function (name) {
            let module = null;
            const nameLowercase = name.toLowerCase();
            Process.enumerateModules({
                onMatch: function (m) {
                    if (m.name.toLowerCase() === nameLowercase) {
                        module = m;
                        return 'stop';
                    }
                },
                onComplete: function () {
                }
            });
            return module;
        }
    });

    Object.defineProperty(Process, 'getModuleByName', {
        enumerable: true,
        value: function (name) {
            const module = Process.findModuleByName(name);
            if (module === null)
                throw new Error("Unable to find module '" + name + "'");
            return module;
        }
    });

    Object.defineProperty(Process, 'enumerateModulesSync', {
        enumerable: true,
        value: function () {
            const modules = [];
            Process.enumerateModules({
                onMatch: function (m) {
                    modules.push(m);
                },
                onComplete: function () {
                }
            });
            return modules;
        }
    });

    if (typeof Process.findRangeByAddress === 'undefined') {
        Object.defineProperty(Process, 'findRangeByAddress', {
            enumerable: true,
            value: function (address) {
                let range = null;
                Process.enumerateRanges('---', {
                    onMatch: function (r) {
                        const base = r.base;
                        if (base.compare(address) < 0 && base.add(r.size).compare(address) > 0) {
                            range = r;
                            return 'stop';
                        }
                    },
                    onComplete: function () {
                    }
                });
                return range;
            }
        });
    }

    Object.defineProperty(Process, 'getRangeByAddress', {
        enumerable: true,
        value: function (address) {
            const range = Process.findRangeByAddress(address);
            if (range === null)
                throw new Error("Unable to find range containing " + address);
            return range;
        }
    });

    Object.defineProperty(Process, 'enumerateMallocRangesSync', {
        enumerable: true,
        value: function () {
            const ranges = [];
            Process.enumerateMallocRanges({
                onMatch: function (r) {
                    ranges.push(r);
                },
                onComplete: function () {
                }
            });
            return ranges;
        }
    });

    Object.defineProperty(Module, 'enumerateImportsSync', {
        enumerable: true,
        value: function (name) {
            const imports = [];
            Module.enumerateImports(name, {
                onMatch: function (e) {
                    imports.push(e);
                },
                onComplete: function () {
                }
            });
            return imports;
        }
    });

    Object.defineProperty(Module, 'enumerateExportsSync', {
        enumerable: true,
        value: function (name) {
            const exports = [];
            Module.enumerateExports(name, {
                onMatch: function (e) {
                    exports.push(e);
                },
                onComplete: function () {
                }
            });
            return exports;
        }
    });

    Object.defineProperty(Module, 'enumerateRangesSync', {
        enumerable: true,
        value: function (name, prot) {
            const ranges = [];
            Module.enumerateRanges(name, prot, {
                onMatch: function (r) {
                    ranges.push(r);
                },
                onComplete: function () {
                }
            });
            return ranges;
        }
    });

    Object.defineProperty(Interceptor, 'attach', {
        enumerable: true,
        value: function (target, callbacks) {
            Memory.readU8(target);
            return Interceptor._attach(target, callbacks);
        }
    });

    Object.defineProperty(Interceptor, 'replace', {
        enumerable: true,
        value: function (target, replacement) {
            Memory.readU8(target);
            Interceptor._replace(target, replacement);
        }
    });

    Object.defineProperty(Instruction, 'parse', {
        enumerable: true,
        value: function (target) {
            Memory.readU8(target);
            return Instruction._parse(target);
        }
    });

    makeEnumerateThreads(Kernel);
    makeEnumerateRanges(Kernel);

    makeEnumerateThreads(Process);
    makeEnumerateRanges(Process);

    function makeEnumerateThreads(mod) {
        Object.defineProperty(mod, 'enumerateThreadsSync', {
            enumerable: true,
            value: function () {
                const threads = [];
                mod.enumerateThreads({
                    onMatch: function (t) {
                        threads.push(t);
                    },
                    onComplete: function () {
                    }
                });
                return threads;
            }
        });
    }

    function makeEnumerateRanges(mod) {
        Object.defineProperty(mod, 'enumerateRanges', {
            enumerable: true,
            value: function (specifier, callbacks) {
                let protection;
                let coalesce = false;
                if (typeof specifier === 'string') {
                    protection = specifier;
                } else {
                    protection = specifier.protection;
                    coalesce = specifier.coalesce;
                }

                if (coalesce) {
                    let current = null;
                    const onMatch = callbacks.onMatch;
                    mod._enumerateRanges(protection, {
                        onMatch: function (r) {
                            if (current !== null) {
                                if (r.base.equals(current.base.add(current.size)) && r.protection === current.protection) {
                                    const coalescedRange = {
                                        base: current.base,
                                        size: current.size + r.size,
                                        protection: current.protection
                                    };
                                    if (current.hasOwnProperty('file'))
                                        coalescedRange.file = current.file;
                                    Object.freeze(coalescedRange);
                                    current = coalescedRange;
                                } else {
                                    onMatch(current);
                                    current = r;
                                }
                            } else {
                                current = r;
                            }
                        },
                        onComplete: function () {
                            if (current !== null)
                                onMatch(current);
                            callbacks.onComplete();
                        }
                    });
                } else {
                    mod._enumerateRanges(protection, callbacks);
                }
            }
        });

        Object.defineProperty(mod, 'enumerateRangesSync', {
            enumerable: true,
            value: function (specifier) {
                const ranges = [];
                mod.enumerateRanges(specifier, {
                    onMatch: function (r) {
                        ranges.push(r);
                    },
                    onComplete: function () {
                    }
                });
                return ranges;
            }
        });
    }

    Object.defineProperty(ApiResolver.prototype, 'enumerateMatchesSync', {
        enumerable: true,
        value: function (query) {
            const matches = [];
            this.enumerateMatches(query, {
                onMatch: function (m) {
                    matches.push(m);
                },
                onComplete: function () {
                }
            });
            return matches;
        }
    });

    Object.defineProperty(engine, 'rpc', {
        enumerable: true,
        value: {
            exports: {}
        }
    });

    const MessageDispatcher = function () {
        const messages = [];
        const operations = {};

        function initialize() {
            engine._setIncomingMessageCallback(handleMessage);
        }

        this.registerCallback = function registerCallback(type, callback) {
            const op = new MessageRecvOperation(callback);
            operations[type] = op[1];
            dispatchMessages();
            return op[0];
        };

        function handleMessage(rawMessage) {
            const message = JSON.parse(rawMessage);
            if (message instanceof Array && message[0] === 'frida:rpc') {
                handleRpcMessage(message[1], message[2], message.slice(3));
            } else {
                messages.push(message);
                dispatchMessages();
            }
        }

        function handleRpcMessage(id, operation, params) {
            const exports = rpc.exports;

            if (operation === 'call') {
                const method = params[0];
                const args = params[1];

                if (!exports.hasOwnProperty(method)) {
                    reply(id, 'error', "Unable to find method '" + method + "'");
                    return;
                }

                try {
                    const result = exports[method].apply(exports, args);
                    if (result instanceof Promise) {
                        result
                        .then(value => {
                            reply(id, 'ok', value);
                        })
                        .catch(error => {
                            reply(id, 'error', error.message);
                        });
                    } else {
                        reply(id, 'ok', result);
                    }
                } catch (e) {
                    reply(id, 'error', e.message);
                }
            } else if (operation === 'list') {
                reply(id, 'ok', Object.keys(exports));
            }
        }

        function reply(id, type, result) {
            if (result instanceof ArrayBuffer)
                send(['frida:rpc', id, type, {}], result);
            else
                send(['frida:rpc', id, type, result]);
        }

        function dispatchMessages() {
            messages.splice(0, messages.length).forEach(dispatch);
        }

        function dispatch(message) {
            let handlerType;
            if (operations.hasOwnProperty(message.type)) {
                handlerType = message.type;
            } else if (operations.hasOwnProperty('*')) {
                handlerType = '*';
            } else {
                messages.push(message);
                return;
            }
            const complete = operations[handlerType];
            delete operations[handlerType];
            complete(message);
        }

        initialize();
    };

    function MessageRecvOperation(callback) {
        let completed = false;

        this.wait = function wait() {
            while (!completed)
                engine._waitForEvent();
        };

        function complete(message) {
            callback(message);
            completed = true;
        }

        return [this, complete];
    }

    initialize();
})();
