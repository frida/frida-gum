'use strict';

const hexdump = require('./hexdump');

const engine = global;
const slice = Array.prototype.slice;

class Console {
  log() {
    sendLogMessage('info', slice.call(arguments));
  }

  warn() {
    sendLogMessage('warning', slice.call(arguments));
  }

  error() {
    sendLogMessage('error', slice.call(arguments));
  }
}

module.exports = Console;

function sendLogMessage(level, values) {
  const text = values.map(parseLogArgument).join(' ');
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
