const hexdump = require('./hexdump');

const engine = global;
const slice = Array.prototype.slice;

class Console {
  #counters;

  constructor() {
    this.#counters = new Map();
  }

  info() {
    sendLogMessage('info', slice.call(arguments));
  }

  log() {
    sendLogMessage('info', slice.call(arguments));
  }

  debug() {
    sendLogMessage('debug', slice.call(arguments));
  }

  warn() {
    sendLogMessage('warning', slice.call(arguments));
  }

  error() {
    sendLogMessage('error', slice.call(arguments));
  }

  count(label = 'default') {
    const newValue = (this.#counters.get(label) ?? 0) + 1;
    this.#counters.set(label, newValue);
    this.log(`${label}: ${newValue}`);
  }

  countReset(label = 'default') {
    if (this.#counters.has(label)) {
      this.#counters.delete(label);
    } else {
      this.warn(`Count for '${label}' does not exist`);
    }
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

  if (value === undefined)
    return 'undefined';

  if (value === null)
    return 'null';

  return value;
}
