/* jshint esnext: true */
(function () {
    "use strict";

    const engine = global;
    const timers = {};
    let nextTimerId = 1;
    let immediates = [];
    let immediateTimer = null;
    let dispatcher;
    const longSize = (Process.pointerSize == 8 && Process.platform !== 'windows') ? 64 : 32;

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

    class Console {
        log() {
            sendLogMessage('info', Array.from(arguments));
        }

        warn() {
            sendLogMessage('warning', Array.from(arguments));
        }

        error() {
            sendLogMessage('error', Array.from(arguments));
        }
    }

    Object.defineProperties(engine, {
        rpc: {
            enumerable: true,
            value: {
                exports: {}
            }
        },
        recv: {
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
        },
        send: {
            enumerable: true,
            value: function (payload, data) {
                const message = {
                    type: 'send',
                    payload: payload
                };
                engine._send(JSON.stringify(message), data || null);
            }
        },
        setTimeout: {
            enumerable: true,
            value: function (func, delay = 0, ...args) {
                if (delay === 0)
                    return setImmediate(func, ...args);

                const id = nextTimerId++;

                const nativeId = _setTimeout(function () {
                    func.apply(null, args);
                }, delay);
                timers[id] = nativeId;

                return id;
            }
        },
        clearTimeout: {
            enumerable: true,
            value: function (id) {
                const nativeId = timers[id];
                if (nativeId !== undefined) {
                    delete timers[id];
                    _clearTimeout(nativeId);
                } else {
                    clearImmediate(id);
                }
            }
        },
        setInterval: {
            enumerable: true,
            value: function (func, delay, ...args) {
                return _setInterval(function () {
                    func.apply(null, args);
                }, delay);
            }
        },
        setImmediate: {
            enumerable: true,
            value: function (func, ...args) {
                const id = nextTimerId++;

                immediates.push([id, func, args]);

                if (immediateTimer === null)
                    immediateTimer = _setTimeout(processImmediates, 0);

                return id;
            }
        },
        clearImmediate: {
            enumerable: true,
            value: function (id) {
                immediates = immediates.filter(([immediateId]) => immediateId !== id);
            }
        },
        int64: {
            enumerable: true,
            value: function (value) {
                return new Int64(value);
            }
        },
        uint64: {
            enumerable: true,
            value: function (value) {
                return new UInt64(value);
            }
        },
        ptr: {
            enumerable: true,
            value: function (str) {
                return new NativePointer(str);
            }
        },
        NULL: {
            enumerable: true,
            value: new NativePointer("0")
        },
        console: {
            enumerable: true,
            value: new Console()
        },
        hexdump: {
            enumerable: true,
            value: hexdump
        },
    });

    NativePointer.prototype.equals = function (ptr) {
        if (!(ptr instanceof NativePointer)) {
            throw new Error("Not a pointer");
        }
        return this.compare(ptr) === 0;
    };

    if (Script.runtime === 'DUK') {
        const cpuContextFields = Object.getOwnPropertyNames(CpuContext.prototype);
        CpuContext.prototype.toJSON = function () {
            return cpuContextFields.reduce((result, name) => {
                result[name] = this[name];
                return result;
            }, {});
        };
    }

    makeEnumerateThreads(Kernel);
    makeEnumerateRanges(Kernel);

    makeEnumerateThreads(Process);
    makeEnumerateRanges(Process);

    function MessageDispatcher() {
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

        function handleMessage(rawMessage, data) {
            const message = JSON.parse(rawMessage);
            if (message instanceof Array && message[0] === 'frida:rpc') {
                handleRpcMessage(message[1], message[2], message.slice(3));
            } else {
                messages.push([message, data]);
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
                            reply(id, 'error', error.message, [error.name, error.stack]);
                        });
                    } else {
                        reply(id, 'ok', result);
                    }
                } catch (e) {
                    reply(id, 'error', e.message, [e.name, e.stack]);
                }
            } else if (operation === 'list') {
                reply(id, 'ok', Object.keys(exports));
            }
        }

        function reply(id, type, result, params) {
            params = params || [];

            if (result instanceof ArrayBuffer)
                send(['frida:rpc', id, type, {}].concat(params), result);
            else
                send(['frida:rpc', id, type, result].concat(params));
        }

        function dispatchMessages() {
            messages.splice(0).forEach(dispatch);
        }

        function dispatch(item) {
            const [message, data] = item;

            let handlerType;
            if (operations.hasOwnProperty(message.type)) {
                handlerType = message.type;
            } else if (operations.hasOwnProperty('*')) {
                handlerType = '*';
            } else {
                messages.push(item);
                return;
            }
            const complete = operations[handlerType];
            delete operations[handlerType];
            complete(message, data);
        }

        initialize();
    };

    function MessageRecvOperation(callback) {
        let completed = false;

        this.wait = function wait() {
            while (!completed)
                engine._waitForEvent();
        };

        function complete(message, data) {
            callback(message, data);
            completed = true;
        }

        return [this, complete];
    }

    function processImmediates() {
        while (true) {
            const item = immediates.shift();
            if (item === undefined)
                break;
            const [, func, args] = item;
            try {
                func.apply(null, args);
            } catch (e) {
                _setTimeout(function () { throw e; }, 0);
            }
        }

        immediateTimer = null;
    }

    function sendLogMessage(level, values) {
        const text = values.map(parseLogArgument).join(" ");
        const message = {
            type: 'log',
            level: level,
            payload: text
        };
        engine._send(JSON.stringify(message), null);
    }

    function parseLogArgument(value) {
        if (value instanceof ArrayBuffer)
            return hexdump(value);
        else
            return value;
    }

    function hexdump(target, options) {
        options = options || {};

        const startOffset = options.offset || 0;
        let length = options.length;
        const showHeader = options.hasOwnProperty('header') ? options.header : true;
        const useAnsi = options.hasOwnProperty('ansi') ? options.ansi : false;

        let buffer;
        if (target instanceof ArrayBuffer) {
            if (length === undefined)
                length = target.byteLength;
            buffer = target;
        } else {
            if (length === undefined)
                length = 256;
            buffer = Memory.readByteArray(target, length);
        }

        const bytes = new Uint8Array(buffer);

        const columnPadding = "  ";
        const leftColumnWidth = 8;
        const hexLegend = " 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F";
        const asciiLegend = "0123456789ABCDEF";

        let resetColor, offsetColor, dataColor, newlineColor;
        if (useAnsi) {
            resetColor = "\x1b[0m";
            offsetColor = "\x1b[0;32m";
            dataColor = "\x1b[0;33m";
            newlineColor = resetColor;
        } else {
            resetColor = "";
            offsetColor = "";
            dataColor = "";
            newlineColor = "";
        }

        const result = [];

        if (showHeader) {
            result.push(
                "        ",
                columnPadding,
                hexLegend,
                columnPadding,
                asciiLegend,
                "\n"
            );
        }

        let offset = startOffset;
        for (let bufferOffset = 0; bufferOffset < length; bufferOffset += 16) {
            if (bufferOffset !== 0)
                result.push("\n");

            result.push(
                offsetColor, pad(offset.toString(16), leftColumnWidth, "0"), resetColor,
                columnPadding
            );

            const asciiChars = [];
            const lineSize = Math.min(length - offset, 16);

            for (let lineOffset = 0; lineOffset !== lineSize; lineOffset++) {
                const value = bytes[offset++];

                const isNewline = value === 10;

                const hexPair = pad(value.toString(16), 2, "0");
                if (lineOffset !== 0)
                    result.push(" ");
                result.push(
                    isNewline ? newlineColor : dataColor,
                    hexPair,
                    resetColor
                );

                asciiChars.push(
                    isNewline ? newlineColor : dataColor,
                    (value >= 32 && value <= 126) ? String.fromCharCode(value) : ".",
                    resetColor
                );
            }

            for (let lineOffset = lineSize; lineOffset !== 16; lineOffset++) {
                result.push("   ");
                asciiChars.push(" ");
            }

            result.push(columnPadding);

            Array.prototype.push.apply(result, asciiChars);
        }

        let trailingSpaceCount = 0;
        for (let tailOffset = result.length - 1; tailOffset >= 0 && result[tailOffset] === " "; tailOffset--) {
            trailingSpaceCount++;
        }

        return result.slice(0, result.length - trailingSpaceCount).join("");
    }

    function pad(str, width, fill) {
        const result = [];
        const paddingSize = Math.max(width - str.length, 0);
        for (let index = 0; index !== paddingSize; index++) {
            result.push(fill);
        }
        return result.join("") + str;
    }

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
        Object.defineProperties(mod, {
            enumerateRanges: {
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
            },
            enumerateRangesSync: {
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
            },
        });
    }

    Object.defineProperties(Memory, {
        dup: {
            enumerable: true,
            value: function (mem, size) {
                const result = Memory.alloc(size);
                Memory.copy(result, mem, size);
                return result;
            }
        },
        readShort: {
            enumerable: true,
            value: function (mem) {
                return Memory.readS16(mem);
            }
        },
        writeShort: {
            enumerable: true,
            value: function (mem, value) {
                return Memory.writeS16(mem, value);
            }
        },
        readUShort: {
            enumerable: true,
            value: function (mem) {
                return Memory.readU16(mem);
            }
        },
        writeUShort: {
            enumerable: true,
            value: function (mem, value) {
                return Memory.writeU16(mem, value);
            }
        },
        readInt: {
            enumerable: true,
            value: function (mem) {
                return Memory.readS32(mem);
            }
        },
        writeInt: {
            enumerable: true,
            value: function (mem, value) {
                return Memory.writeS32(mem, value);
            }
        },
        readUInt: {
            enumerable: true,
            value: function (mem) {
                return Memory.readU32(mem);
            }
        },
        writeUInt: {
            enumerable: true,
            value: function (mem, value) {
                return Memory.writeU32(mem, value);
            }
        },
    });

    if (longSize === 64) {
        Object.defineProperties(Memory, {
            readLong: {
                enumerable: true,
                value: function (mem) {
                    return Memory.readS64(mem);
                }
            },
            writeLong: {
                enumerable: true,
                value: function (mem, value) {
                    Memory.writeS64(mem, value);
                }
            },
            readULong: {
                enumerable: true,
                value: function (mem) {
                    return Memory.readU64(mem);
                }
            },
            writeULong: {
                enumerable: true,
                value: function (mem, value) {
                    Memory.writeU64(mem, value);
                }
            },
        });
    } else {
        Object.defineProperties(Memory, {
            readLong: {
                enumerable: true,
                value: function (mem) {
                    return new Int64(Memory.readS32(mem));
                }
            },
            writeLong: {
                enumerable: true,
                value: function (mem, value) {
                    Memory.writeS32(mem, value);
                }
            },
            readULong: {
                enumerable: true,
                value: function (mem) {
                    return new UInt64(Memory.readU32(mem));
                }
            },
            writeULong: {
                enumerable: true,
                value: function (mem, value) {
                    Memory.writeU32(mem, value);
                }
            },
        });
    }

    Object.defineProperties(Process, {
        findModuleByAddress: {
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
        },
        getModuleByAddress: {
            enumerable: true,
            value: function (address) {
                const module = Process.findModuleByAddress(address);
                if (module === null)
                    throw new Error("Unable to find module containing " + address);
                return module;
            }
        },
        findModuleByName: {
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
        },
        getModuleByName: {
            enumerable: true,
            value: function (name) {
                const module = Process.findModuleByName(name);
                if (module === null)
                    throw new Error("Unable to find module '" + name + "'");
                return module;
            }
        },
        enumerateModulesSync: {
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
        },
        getRangeByAddress: {
            enumerable: true,
            value: function (address) {
                const range = Process.findRangeByAddress(address);
                if (range === null)
                    throw new Error("Unable to find range containing " + address);
                return range;
            }
        },
        enumerateMallocRangesSync: {
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
        },
    });

    if (Process.findRangeByAddress === undefined) {
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

    Object.defineProperties(Module, {
        enumerateImportsSync: {
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
        },
        enumerateExportsSync: {
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
        },
        enumerateRangesSync: {
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
        },
    });

    Object.defineProperties(Interceptor, {
        attach: {
            enumerable: true,
            value: function (target, callbacks) {
                Memory.readU8(target);
                return Interceptor._attach(target, callbacks);
            }
        },
        replace: {
            enumerable: true,
            value: function (target, replacement) {
                Memory.readU8(target);
                Interceptor._replace(target, replacement);
            }
        },
    });

    Object.defineProperty(Instruction, 'parse', {
        enumerable: true,
        value: function (target) {
            Memory.readU8(target);
            return Instruction._parse(target);
        }
    });

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

    const _closeIOStream = IOStream.prototype._close;
    IOStream.prototype.close = function () {
        const stream = this;
        return new Promise(function (resolve, reject) {
            _closeIOStream.call(stream, function (error, success) {
                if (error === null)
                    resolve(success);
                else
                    reject(error);
            });
        });
    };

    const _closeInput = InputStream.prototype._close;
    InputStream.prototype.close = function () {
        const stream = this;
        return new Promise(function (resolve, reject) {
            _closeInput.call(stream, function (error, success) {
                if (error === null)
                    resolve(success);
                else
                    reject(error);
            });
        });
    };

    const _read = InputStream.prototype._read;
    InputStream.prototype.read = function (size) {
        const stream = this;
        return new Promise(function (resolve, reject) {
            _read.call(stream, size, function (error, data) {
                if (error === null)
                    resolve(data);
                else
                    reject(error);
            });
        });
    };

    const _readAll = InputStream.prototype._readAll;
    InputStream.prototype.readAll = function (size) {
        const stream = this;
        return new Promise(function (resolve, reject) {
            _readAll.call(stream, size, function (error, data) {
                if (error === null) {
                    resolve(data);
                } else {
                    error.partialData = data;
                    reject(error);
                }
            });
        });
    };

    const _closeOutput = OutputStream.prototype._close;
    OutputStream.prototype.close = function () {
        const stream = this;
        return new Promise(function (resolve, reject) {
            _closeOutput.call(stream, function (error, success) {
                if (error === null)
                    resolve(success);
                else
                    reject(error);
            });
        });
    };

    const _write = OutputStream.prototype._write;
    OutputStream.prototype.write = function (data) {
        const stream = this;
        return new Promise(function (resolve, reject) {
            _write.call(stream, data, function (error, size) {
                if (error === null)
                    resolve(size);
                else
                    reject(error);
            });
        });
    };

    const _writeAll = OutputStream.prototype._writeAll;
    OutputStream.prototype.writeAll = function (data) {
        const stream = this;
        return new Promise(function (resolve, reject) {
            _writeAll.call(stream, data, function (error, size) {
                if (error === null) {
                    resolve(size);
                } else {
                    error.partialSize = size;
                    reject(error);
                }
            });
        });
    };

    const _closeListener = SocketListener.prototype._close;
    SocketListener.prototype.close = function () {
        const listener = this;
        return new Promise(function (resolve) {
            _closeListener.call(listener, resolve);
        });
    };

    const _accept = SocketListener.prototype._accept;
    SocketListener.prototype.accept = function () {
        const listener = this;
        return new Promise(function (resolve, reject) {
            _accept.call(listener, function (error, connection) {
                if (error === null)
                    resolve(connection);
                else
                    reject(error);
            });
        });
    };

    const _setNoDelay = SocketConnection.prototype._setNoDelay;
    SocketConnection.prototype.setNoDelay = function (noDelay = true) {
        const connection = this;
        return new Promise(function (resolve, reject) {
            _setNoDelay.call(connection, noDelay, function (error, success) {
                if (error === null)
                    resolve(success);
                else
                    reject(error);
            });
        });
    };

    Object.defineProperties(Socket, {
        listen: {
            enumerable: true,
            value: function (options = {}) {
                return new Promise(function (resolve, reject) {
                    const {
                        port = 0,
                        backlog = 10,
                    } = options;

                    Socket._listen(port, backlog, function (error, listener) {
                        if (error === null)
                            resolve(listener);
                        else
                            reject(error);
                    });
                });
            },
        },
        connect: {
            enumerable: true,
            value: function (options) {
                return new Promise(function (resolve, reject) {
                    const {
                        family = 4,
                        host = 'localhost',
                        port,
                    } = options;

                    Socket._connect(family, host, port, function (error, connection) {
                        if (error === null)
                            resolve(connection);
                        else
                            reject(error);
                    });
                });
            },
        },
    });

    initialize();
})();
