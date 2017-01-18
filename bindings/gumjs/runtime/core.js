'use strict';

const Console = require('./console');
const hexdump = require('./hexdump');
const MessageDispatcher = require('./message-dispatcher');

const engine = global;
const timers = {};
let nextTimerId = 1;
let immediates = [];
let immediateTimer = null;
let messageDispatcher;

function initialize() {
  messageDispatcher = new MessageDispatcher();

  const proxyClass = global.Proxy;
  if ('create' in proxyClass) {
    const createProxy = proxyClass.create;
    global.Proxy = function (target, handler) {
      return createProxy.call(proxyClass, handler, Object.getPrototypeOf(target));
    };
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
      return messageDispatcher.registerCallback(type, callback);
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
        delete timers[id];
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
    value: new NativePointer('0')
  },
  console: {
    enumerable: true,
    value: new Console()
  },
  hexdump: {
    enumerable: true,
    value: hexdump
  },
  ObjC: {
    enumerable: true,
    configurable: true,
    get: function () {
      Frida._loadObjC();
      const m = Frida._objc;
      Object.defineProperty(engine, 'ObjC', { value: m });
      return m;
    }
  },
  Java: {
    enumerable: true,
    configurable: true,
    get: function () {
      Frida._loadJava();
      const m = Frida._java;
      Object.defineProperty(engine, 'Java', { value: m });
      return m;
    }
  },
});

NativePointer.prototype.equals = function (ptr) {
  if (!(ptr instanceof NativePointer)) {
    throw new Error('Not a pointer');
  }
  return this.compare(ptr) === 0;
};

const _nextTick = Script._nextTick;
Script.nextTick = function (callback, ...args) {
  _nextTick(callback.bind(global, ...args));
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

function processImmediates() {
  immediateTimer = null;

  const length = immediates.length;
  if (length === 0)
    return;
  const [maxId] = immediates[length - 1];

  do {
    const [id] = immediates[0];
    if (id > maxId)
      break;
    const [, func, args] = immediates.shift();
    try {
      func.apply(null, args);
    } catch (e) {
      _setTimeout(function () { throw e; }, 0);
    }
  } while (immediates.length > 0);
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
  patchCode: {
    enumerable: true,
    value: function (address, size, apply) {
      Memory.readU8(address);
      Memory._patchCode(address, size, apply);
    }
  },
});

Object.defineProperties(Process, {
  findModuleByAddress: {
    enumerable: true,
    value: function (address) {
      let module = null;
      Process.enumerateModules({
        onMatch: function (m) {
          const base = m.base;
          if (base.compare(address) <= 0 && base.add(m.size).compare(address) > 0) {
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
        throw new Error('Unable to find module containing ' + address);
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
        throw new Error('Unable to find range containing ' + address);
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
          if (base.compare(address) <= 0 && base.add(r.size).compare(address) > 0) {
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

const stalkerEventType = {
  call: 1,
  ret: 2,
  exec: 4,
};

Object.defineProperties(Stalker, {
  follow: {
    enumerable: true,
    value: function (first, second) {
      let threadId = first;
      let options = second;

      if (typeof first === 'object') {
        threadId = undefined;
        options = first;
      }

      if (threadId === undefined)
        threadId = Process.getCurrentThreadId();
      if (options === undefined)
        options = {};

      if (typeof threadId !== 'number' || (options === null || typeof options !== 'object'))
        throw new Error('invalid argument');

      const {
        events = {},
        onReceive = null,
        onCallSummary = null,
      } = options;

      if (events === null || typeof events !== 'object')
        throw new Error('events must be an object');

      const eventMask = Object.keys(events).reduce((result, name) => {
        const value = stalkerEventType[name];
        if (value === undefined)
          throw new Error(`unknown event type: ${name}`);

        const enabled = events[name];
        if (typeof enabled !== 'boolean')
          throw new Error('desired events must be specified as boolean values');

        return enabled ? (result | value) : result;
      }, 0);

      Stalker._follow(threadId, eventMask, onReceive, onCallSummary);
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
          family = null,

          host = null,
          port = 0,

          type = null,
          path = null,

          backlog = 10,
        } = options;

        Socket._listen(family, host, port, type, path, backlog, function (error, listener) {
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
          family = null,

          host = 'localhost',
          port = 0,

          type = null,
          path = null,
        } = options;

        Socket._connect(family, host, port, type, path, function (error, connection) {
          if (error === null)
            resolve(connection);
          else
            reject(error);
        });
      });
    },
  },
});

SourceMap.prototype.resolve = function (generatedPosition) {
  const generatedColumn = generatedPosition.column;
  const position = (generatedColumn !== undefined)
      ? this._resolve(generatedPosition.line, generatedColumn)
      : this._resolve(generatedPosition.line);
  if (position === null)
    return null;

  const [source, line, column, name] = position;

  return {source, line, column, name};
};

initialize();
