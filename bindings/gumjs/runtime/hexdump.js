'use strict';

module.exports = hexdump;

function hexdump(target, options) {
  options = options || {};

  const startOffset = options.offset || 0;
  const printGroup = options.group || 1;
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

  const columnPadding = '  ';
  const leftColumnWidth = 8;
  var hexLegend = ' '; // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F';

  for (let index = 0; index <= 15; index += printGroup) {
    for (let groupOffset = printGroup-1; groupOffset >= 0; groupOffset--) {
      const hex = (index+groupOffset).toString(16);
      hexLegend += hex + ' ';
    }
    hexLegend += ' ';
  }

  const asciiLegend = '0123456789ABCDEF';

  let resetColor, offsetColor, dataColor, newlineColor;
  if (useAnsi) {
    resetColor = '\x1b[0m';
    offsetColor = '\x1b[0;32m';
    dataColor = '\x1b[0;33m';
    newlineColor = resetColor;
  } else {
    resetColor = '';
    offsetColor = '';
    dataColor = '';
    newlineColor = '';
  }

  const result = [];

  if (showHeader) {
    result.push(
      '        ',
      columnPadding,
      hexLegend,
      columnPadding,
      asciiLegend,
      '\n'
    );
  }

  let offset = startOffset;
  for (let bufferOffset = 0; bufferOffset < length; bufferOffset += 16) {
    if (bufferOffset !== 0)
      result.push('\n');

    result.push(
      offsetColor, pad(offset.toString(16), leftColumnWidth, '0'), resetColor,
      columnPadding
    );

    const asciiChars = [];
    const lineSize = Math.min(length - offset, 16);

    for (let lineOffset = 0; lineOffset !== lineSize; lineOffset += printGroup) {
      if (lineOffset !== 0)
        result.push(' ');
      for (let groupOffset = printGroup-1; groupOffset >= 0; groupOffset--) {
        if (bytes[offset + groupOffset] !== void 0) {
          const value = bytes[offset + groupOffset];
          const isNewline = value === 10;

          const hexPair = pad(value.toString(16), 2, '0');
          result.push(
            isNewline ? newlineColor : dataColor,
            hexPair,
            resetColor
          );

          asciiChars.push(
            isNewline ? newlineColor : dataColor,
            (value >= 32 && value <= 126) ? String.fromCharCode(value) : '.',
            resetColor
          );
        }
      }
      offset += printGroup;
    }

    for (let lineOffset = lineSize; lineOffset !== 16; lineOffset++) {
      result.push('   ');
      asciiChars.push(' ');
    }

    result.push(columnPadding);

    Array.prototype.push.apply(result, asciiChars);
  }

  let trailingSpaceCount = 0;
  for (let tailOffset = result.length - 1; tailOffset >= 0 && result[tailOffset] === ' '; tailOffset--) {
    trailingSpaceCount++;
  }

  return result.slice(0, result.length - trailingSpaceCount).join('');
}

function pad(str, width, fill) {
  const result = [];
  const paddingSize = Math.max(width - str.length, 0);
  for (let index = 0; index !== paddingSize; index++) {
    result.push(fill);
  }
  return result.join('') + str;
}
