class REPL {
  //interface CmdFuncInfo = {
  //  min_args_cnt: number,
  //  func: (...args: string[]) => void,
  //}
  #cmdDispatcher;

  constructor() {
    this.#cmdDispatcher = new Map();
  }

  _doQuickCmd(s) {
    const args = JSON.parse(decodeURIComponent(s));
    const cmd = args[0];
    const func_info = this.#cmdDispatcher.get(cmd)
    if (func_info !== undefined) {
      if (args.length - 1 < func_info.min_args_cnt) {
        throw Error(`${cmd} need at least ${func_info.min_args_cnt} args`);
      }
      func_info.func(...args.slice(1));
    } else {
      throw Error(`Unknown command ${cmd}`);
    }
  }

  setQuickCmd(cmd, min_args_cnt, func) {
    this.#cmdDispatcher.set(cmd, { min_args_cnt, func });
  }

  unsetQuickCmd(cmd) {
    this.#cmdDispatcher.delete(cmd);
  }
}

module.exports = REPL;
