var handlers = {};

this.process = {
    version: "v0.12.0",
    argv: [
        "node"
    ],
    cwd: function () {
        return "/";
    },
    once: function (event, callback) {
        var callbacks = handlers[event] || [];
        callbacks.push(callback);
        handlers[event] = callbacks;
    },
    emit: function (event) {
        var callbacks = handlers[event] || [];
        delete handlers[event];
        callbacks.forEach(function (callback) {
            callback();
        });
    }
};
