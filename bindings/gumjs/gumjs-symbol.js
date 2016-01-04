/*
 * Based on https://github.com/component/symbol
 */
(function () {
    /**
    * Creates a new Symbol object
    */

    function Symbol() {
        // allow usage without `new`
        if (!(this instanceof Symbol)) return new Symbol();

        // create a unique key based on a long uid for this symbol
        var key = this.__key__ = "__symbol__" + Math.random(32);

        // define a property on Object.prototype, so that whenever a property
        // with the key we just generated is set on any object, it's automatically
        // marked as non-enumerable. this is technically global, but shouldn't matter
        // since it's unique and non-enumerable
        Object.defineProperty(Object.prototype, key, {
            enumerable: false,
            get: function() {},
            set: setter(key)
        });
    }

    /**
    * Returns the internal string representation of the Symbol object
    */

    Symbol.prototype.toString = function() {
        return this.__key__;
    };

    /**
    * Disposes the global Object.prototype property associated with this symbol
    */

    Symbol.prototype.dispose = function() {
        delete Object.prototype[this.__key__];
    };

    /**
    * Returns a `set` function. This is so that *only* this closure will be
    * retained in memory. Leaving the actual `Symbol` instance to be eligible
    * for garbage collection.
    */

    function setter (key) {
        return function(value) {
            // Store the received value and mark it as non-enumerable
            Object.defineProperty(this, key, {
            enumerable: false,
            configurable: true,
            writable: true,
            value: value
            });
        };
    }

    global.Symbol = Symbol;
})();
