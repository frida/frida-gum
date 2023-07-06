require('./core');
require('./error-handler-quickjs');

class WeakRef {
  constructor(target) {
    this._id = Script.bindWeak(target, this._onTargetDead);
  }

  deref() {
    if (this._id === null)
      return;
    return Script._derefWeak(this._id);
  }

  _onTargetDead = () => {
    this._id = null;
  };
}

globalThis.WeakRef = WeakRef;
