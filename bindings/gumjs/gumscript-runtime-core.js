/* jshint esnext: true */
(function () {
    "use strict";

    const engine = this;
    let dispatcher;

    var initialize = function initialize() {
        dispatcher = new MessageDispatcher();
    };

    const longSize = (Process.pointerSize == 8 && Process.platform !== 'windows') ? 64 : 32;

    Object.defineProperty(engine, 'recv', {
        enumerable: true,
        value: function recv() {
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
        value: function send(payload, data) {
            const message = {
                type: 'send',
                payload: payload
            };
            engine._send(JSON.stringify(message), data || null);
        }
    });

    Object.defineProperty(engine, 'ptr', {
        enumerable: true,
        value: function ptr(str) {
            return new NativePointer(str);
        }
    });

    Object.defineProperty(engine, 'NULL', {
        enumerable: true,
        value: new NativePointer("0")
    });

    const Console = function () {
        this.log = function () {
            const message = {
                type: 'log',
                payload: Array.prototype.join.call(arguments, " ")
            };
            engine._send(JSON.stringify(message), null);
        };
    };
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

    Object.defineProperty(Memory, 'readLong', {
        enumerable: true,
        value: function (mem) {
            return Memory['readS' + longSize](mem);
        }
    });

    Object.defineProperty(Memory, 'writeLong', {
        enumerable: true,
        value: function (mem, value) {
            return Memory['writeS' + longSize](mem, value);
        }
    });

    Object.defineProperty(Memory, 'readULong', {
        enumerable: true,
        value: function (mem) {
            return Memory['readU' + longSize](mem);
        }
    });

    Object.defineProperty(Memory, 'writeULong', {
        enumerable: true,
        value: function (mem, value) {
            return Memory['writeU' + longSize](mem, value);
        }
    });

    Object.defineProperty(Process, 'enumerateThreadsSync', {
        enumerable: true,
        value: function () {
            const threads = [];
            Process.enumerateThreads({
                onMatch: function (t) {
                    threads.push(t);
                },
                onComplete: function () {
                }
            });
            return threads;
        }
    });

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

    Object.defineProperty(Process, 'getRangeByAddress', {
        enumerable: true,
        value: function (address) {
            const range = Process.findRangeByAddress(address);
            if (range === null)
                throw new Error("Unable to find range containing " + address);
            return range;
        }
    });

    Object.defineProperty(Process, 'enumerateRanges', {
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
                Process._enumerateRanges(protection, {
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
                Process._enumerateRanges(protection, callbacks);
            }
        }
    });

    Object.defineProperty(Process, 'enumerateRangesSync', {
        enumerable: true,
        value: function (specifier) {
            const ranges = [];
            Process.enumerateRanges(specifier, {
                onMatch: function (r) {
                    ranges.push(r);
                },
                onComplete: function () {
                }
            });
            return ranges;
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

    NativePointer.prototype.equals = function (ptr) {
        if (!(ptr instanceof NativePointer)) {
            throw new Error("Not a pointer");
        }
        return this.compare(ptr) === 0;
    };

    const MessageDispatcher = function () {
        const messages = [];
        const operations = {};

        function initialize() {
            engine._setIncomingMessageCallback(handleMessage);
        }

        this.registerCallback = function registerCallback(type, callback) {
            var op = new MessageRecvOperation(callback);
            operations[type] = op[1];
            dispatchMessages();
            return op[0];
        };

        function handleMessage(rawMessage) {
            messages.push(JSON.parse(rawMessage));
            dispatchMessages();
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

        initialize.call(this);
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

    initialize.call(this);
}).call(this);
