'use strict';

const hexdump = require('./hexdump');

const engine = global;

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
