'use strict';

global._setUnhandledExceptionCallback(function (error) {
  const message = {
    type: 'error',
    description: '' + error
  };

  if (error instanceof Error) {
    const stack = error.stack;
    if (stack) {
      message.stack = stack;
    }

    const fileName = error.fileName;
    if (fileName) {
      message.fileName = fileName;
    }

    const lineNumber = error.lineNumber;
    if (lineNumber) {
      message.lineNumber = lineNumber;
      message.columnNumber = 1;
    }
  }

  _send(JSON.stringify(message), null);
});

Duktape.errCreate = function (error) {
  let stack = error.stack;
  if (!stack)
    return error;

  let firstSourcePosition = null;
  let frameTypes = [];

  stack = stack
      .replace(/    at (.+) \(((.+):(.+))?\) (internal)?(native)?(.*)/g,
        function (match, scope, sourceLocation, fileName, lineNumber, internal, native, suffix) {
          frameTypes.push(internal || native);

          if (sourceLocation === undefined || internal !== undefined) {
            return '    at ' + scope + ' (' + (sourceLocation || (native || "")) + ')';
          }

          const position = mapSourcePosition({
            source: fileName,
            line: parseInt(lineNumber, 10)
          });

          if (firstSourcePosition === null)
            firstSourcePosition = position;

          const location = position.source + ':' + position.line;

          const funcName = (scope !== 'global' && scope !== '[anon]') ? scope : null;
          if (funcName !== null)
            return '    at ' + funcName + ' (' + location + ')';
          else
            return '    at ' + location;
        });

  if (frameTypes.length >= 3 && frameTypes[0] === 'internal' && frameTypes[1] === 'native') {
    const lines = stack.split('\n');
    stack = lines[0] + '\n' + lines.slice(3).join('\n');
  }

  error.stack = stack;

  if (firstSourcePosition !== null) {
    error.fileName = firstSourcePosition.source;
    error.lineNumber = firstSourcePosition.line;
  }

  return error;
};

/*
 * Based on https://github.com/evanw/node-source-map-support
 */

const sourceMapCache = {};

function mapSourcePosition(position) {
  let item = sourceMapCache[position.source];
  if (!item) {
    item = sourceMapCache[position.source] = {
      map: findSourceMap(position.source)
    };
  }

  if (item.map) {
    const originalPosition = item.map.resolve(position);

    // Only return the original position if a matching line was found. If no
    // matching line is found then we return position instead, which will cause
    // the stack trace to print the path and line for the compiled file. It is
    // better to give a precise location in the compiled file than a vague
    // location in the original file.
    if (originalPosition !== null)
      return originalPosition;
  }

  return position;
}

function findSourceMap(source) {
  if (source === Script.fileName)
    return Script.sourceMap;
  else if (source === 'frida.js')
    return Frida.sourceMap;
  else if (source === 'objc.js')
    return Frida._objcSourceMap;
  else if (source === 'java.js')
    return Frida._javaSourceMap;
  else
    return null;
}
