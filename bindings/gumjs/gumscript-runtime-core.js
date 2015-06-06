(function () {
    var engine = this;
    var dispatcher;

    var initialize = function initialize() {
        dispatcher = new MessageDispatcher();
    };

    const longSize = (Process.pointerSize == 8 && Process.platform !== 'windows') ? 64 : 32;

    Object.defineProperty(engine, 'recv', {
        enumerable: true,
        value: function recv() {
            var type, callback;
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
            var message = {
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

    var Console = function () {
        this.log = function () {
            var message = {
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
            var result = Memory.alloc(size);
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
            var threads = [];
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

    Object.defineProperty(Process, 'enumerateModulesSync', {
        enumerable: true,
        value: function () {
            var modules = [];
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

    Object.defineProperty(Process, 'enumerateRangesSync', {
        enumerable: true,
        value: function (prot) {
            var ranges = [];
            Process.enumerateRanges(prot, {
                onMatch: function (r) {
                    ranges.push(r);
                },
                onComplete: function () {
                }
            });
            return ranges;
        }
    });

    Object.defineProperty(Process, 'getModuleByName', {
        enumerable: true,
        value: function (name) {
            var module = null;
            Process.enumerateModules({
                onMatch: function (m) {
                    if (m.name === name) {
                        module = m;
                        return 'stop';
                    }
                },
                onComplete: function () {
                    if (!module) {
                        throw new Error('Module ' + name + ' not found');
                    }
                }
            });
            return module;
        }
    });

    Object.defineProperty(Module, 'enumerateExportsSync', {
        enumerable: true,
        value: function (name) {
            var exports = [];
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
            var ranges = [];
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

    var MessageDispatcher = function () {
        var messages = [];
        var operations = {};

        var initialize = function initialize() {
            engine._setIncomingMessageCallback(handleMessage);
        };

        this.registerCallback = function registerCallback(type, callback) {
            var op = new MessageRecvOperation(callback);
            operations[type] = op[1];
            dispatchMessages();
            return op[0];
        };

        var handleMessage = function handleMessage(rawMessage) {
            messages.push(JSON.parse(rawMessage));
            dispatchMessages();
        };

        var dispatchMessages = function dispatchMessages() {
            messages.splice(0, messages.length).forEach(dispatch);
        };

        var dispatch = function dispatch(message) {
            var handlerType;
            if (operations.hasOwnProperty(message.type)) {
                handlerType = message.type;
            } else if (operations.hasOwnProperty('*')) {
                handlerType = '*';
            } else {
                messages.push(message);
                return;
            }
            var complete = operations[handlerType];
            delete operations[handlerType];
            complete(message);
        };

        initialize.call(this);
    };

    var MessageRecvOperation = function (callback) {
        var completed = false;

        this.wait = function wait() {
            while (!completed) {
                engine._waitForEvent();
            }
        };

        var complete = function complete(message) {
            callback(message);
            completed = true;
        };

        return [this, complete];
    };

    initialize.call(this);
}).call(this);
