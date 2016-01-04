/*
 * Based on https://github.com/component/symbol
 */
(function () {
    Proxy.create = function(handler) {
        return new Proxy({}, handler);
    };
})();
