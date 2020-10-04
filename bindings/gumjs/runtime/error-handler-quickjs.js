global._setUnhandledExceptionCallback(error => {
  const message = {
    type: 'error',
    description: '' + error
  };

  if (error instanceof Error) {
    const stack = error.stack;
    if (stack !== undefined) {
      message.stack = stack;
    }

    const fileName = error.fileName;
    if (fileName !== undefined) {
      message.fileName = fileName;
    }

    const lineNumber = error.lineNumber;
    if (lineNumber !== undefined) {
      message.lineNumber = lineNumber;
      message.columnNumber = 1;
    }
  }

  _send(JSON.stringify(message), null);
});
