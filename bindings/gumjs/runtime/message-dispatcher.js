'use strict';

const engine = global;

module.exports = MessageDispatcher;

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
        if (typeof result === 'object' && typeof result.then === 'function') {
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

