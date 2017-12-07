/**
 * Returns a hexdump of the provided ArrayBuffer or NativePointer target.
 *
 * @param target The ArrayBuffer or NativePointer to dump.
 * @param options Options customizing the output.
 */
declare function hexdump(target: ArrayBuffer | NativePointer, options?: HexdumpOptions): string;

declare interface HexdumpOptions {
    /**
     * Specifies byte offset of where to start dumping. Defaults to 0.
     */
    offset?: number;

    /**
     * Limits how many bytes to dump.
     */
    length?: number;

    /**
     * Whether a header should be included. Defaults to true.
     */
    header?: boolean;

    /**
     * Whether ANSI colors should be used. Defaults to false.
     */
    ansi?: boolean;
}

/**
 * Short-hand for `new Int64(value)`.
 */
declare function int64(value: string | number): Int64;

/**
 * Short-hand for `new UInt64(value)`.
 */
declare function uint64(value: string | number): UInt64;

/**
 * Short-hand for `new NativePointer(value)`.
 */
declare function ptr(value: string | number): NativePointer;

/**
 * Short-hand for `ptr("0")`.
 */
declare const NULL: NativePointer;

/**
 * Requests callback to be called on the next message received from your Frida-based application.
 *
 * This will only give you one message, so you need to call `recv()` again to receive the next one.
 */
declare function recv(callback: MessageCallback): MessageRecvOperation;

/**
 * Requests callback to be called when the next message of the given type has been received from your
 * Frida-based application.
 *
 * This will only give you one message, so you need to call `recv()` again to receive the next one.
 */
declare function recv(type: string, callback: MessageCallback): MessageRecvOperation;

declare interface MessageCallback { (message: any, data: ArrayBuffer | null): void }

declare interface MessageRecvOperation {
    /**
     * Blocks until the message has been received and callback has returned.
     */
    wait(): void;
}

/**
 * Sends a JSON-serializable message to your Frida-based application.
 */
declare function send(message: any): void;

/**
 * Sends a JSON-serializable message to your Frida-based application, along with some raw binary data.
 * This is useful if you e.g. dumped some memory using `Memory.readByteArray()`.
 */
declare function send(message: any, data: ArrayBuffer | number[] | null): void;

/**
 * Calls @func when Frida's event loop is idle.
 * Returns an id that can be passed to `clearTimeout()` to cancel it.
 */
declare function setTimeout(func: ScheduledCallback): TimeoutId;

/**
 * Calls @func after delay milliseconds, optionally passing it the provided params.
 * Returns an id that can be passed to `clearTimeout()` to cancel it.
 */
declare function setTimeout(func: ScheduledCallback, delay: number, ...params: any[]): TimeoutId;

/**
 * Cancels a previously scheduled `setTimeout()`.
 */
declare function clearTimeout(id: TimeoutId): void;

/**
 * Opaque ID returned by `setTimeout()`. Pass it to `clearTimeout()` to cancel a pending `setTimeout()`.
 */
declare interface TimeoutId {}

/**
 * Calls @func every @delay milliseconds, optionally passing it the provided params.
 * Returns an id that can be passed to clearInterval() to cancel it.
 */
declare function setInterval(func: ScheduledCallback, delay: number, ...params: any[]): IntervalId;

declare function clearInterval(id: IntervalId): void;
declare interface IntervalId {}

declare function setImmediate(func: ScheduledCallback, ...params: any[]): ImmediateId;
declare function clearImmediate(id: ImmediateId): void;
declare interface ImmediateId {}

declare interface ScheduledCallback { (...params: any[]): void }

declare class ApiResolver {
    constructor();
    enumerateMatches(): any;
    enumerateMatchesSync(query: any): any;
}
declare class DebugSymbolValue {
    constructor();
    toString(): any;
}
declare class File {
    constructor();
    close(): any;
    flush(): any;
    write(): any;
}
declare class IOStream {
    constructor();
    close(): any;
}
declare class InputStream {
    constructor();
    close(): any;
    read(size: any): any;
    readAll(size: any): any;
}
declare class InstructionValue {
    constructor();
    toString(): any;
}
declare class Int64 {
    constructor();
    add(): Int64;
    and(): Int64;
    compare(): number;
    or(): Int64;
    shl(): Int64;
    shr(): Int64;
    sub(): Int64;
    toJSON(): string;
    toNumber(): number;
    toString(): string;
    valueOf(): number;
    xor(): Int64;
}
declare class InvocationListener {
    constructor();
    detach(): any;
}
declare class InvocationReturnValue {
    constructor();
    replace(): any;
}
declare class NativeFunction {
    constructor();
    apply(): any;
    call(): any;
}
declare class NativePointer {
    constructor();
    add(): NativePointer;
    and(): NativePointer;
    compare(): number;
    equals(ptr: any): boolean;
    isNull(): boolean;
    or(): NativePointer;
    shl(): NativePointer;
    shr(): NativePointer;
    sub(): NativePointer;
    toInt32(): number;
    toJSON(): string;
    toMatchPattern(): string;
    toString(): string;
    xor(): NativePointer;
}
declare class OutputStream {
    constructor();
    close(): any;
    write(data: any): any;
    writeAll(data: any): any;
}
declare class SocketConnection {
    constructor();
    setNoDelay(noDelay: any): any;
}
declare class SocketListener {
    constructor();
    accept(): any;
    close(): any;
}
declare class SourceMap {
    constructor();
    resolve(generatedPosition: any): any;
}
declare class UInt64 {
    constructor();
    add(): UInt64;
    and(): UInt64;
    compare(): number;
    or(): UInt64;
    shl(): UInt64;
    shr(): UInt64;
    sub(): UInt64;
    toJSON(): string;
    toNumber(): number;
    toString(): string;
    valueOf(): number;
    xor(): UInt64;
}
declare const Backtracer: {
    ACCURATE: any;
    FUZZY: any;
};
declare const Frida: {
    sourceMap: {
        resolve: any;
    };
    version: string;
};
declare const rpc: {
    exports: {
    };
};
declare function CpuContext(): any;
declare function InvocationArgs(): any;
declare function InvocationContext(): any;
declare function NativeCallback(): any;
declare function SystemFunction(): any;
declare function UnixInputStream(): any;
declare function UnixOutputStream(): any;
declare function gc(): any;
declare namespace DebugSymbol {
    function findFunctionsMatching(): any;
    function findFunctionsNamed(): any;
    function fromAddress(): any;
    function fromName(): any;
    function getFunctionByName(): any;
}
declare namespace Instruction {
    function parse(target: any): any;
}
declare namespace Interceptor {
    function attach(target: any, callbacks: any): any;
    function detachAll(): any;
    function replace(target: any, replacement: any): void;
    function revert(): any;
}
declare namespace Java {
    const androidVersion: string;
    const available: boolean;
    const classFactory: any;
    const vm: any;
    function cast(obj: any, C: any): any;
    function choose(className: any, callbacks: any): any;
    function enumerateLoadedClasses(callbacks: any): void;
    function enumerateLoadedClassesSync(): any;
    function isMainThread(): any;
    function openClassFile(filePath: any): any;
    function perform(fn: any, ...args: any[]): any;
    function performNow(fn: any): void;
    function scheduleOnMainThread(fn: any): void;
    function use(className: any): any;
}
declare namespace Kernel {
    const available: boolean;
    function enumerateRanges(specifier: any, callbacks: any): void;
    function enumerateRangesSync(specifier: any): any;
    function enumerateThreadsSync(): any;
    function readByteArray(): any;
    function writeByteArray(): any;
}
declare namespace Memory {
    function alloc(): any;
    function allocAnsiString(): any;
    function allocUtf16String(): any;
    function allocUtf8String(): any;
    function copy(): any;
    function dup(mem: any, size: any): any;
    function patchCode(address: any, size: any, apply: any): void;
    function protect(): any;
    function readAnsiString(): any;
    function readByteArray(): any;
    function readCString(): any;
    function readDouble(): any;
    function readFloat(): any;
    function readInt(): any;
    function readLong(): any;
    function readPointer(): any;
    function readS16(): any;
    function readS32(): any;
    function readS64(): any;
    function readS8(): any;
    function readShort(): any;
    function readU16(): any;
    function readU32(): any;
    function readU64(): any;
    function readU8(): any;
    function readUInt(): any;
    function readULong(): any;
    function readUShort(): any;
    function readUtf16String(): any;
    function readUtf8String(): any;
    function scan(): any;
    function scanSync(): any;
    function writeAnsiString(): any;
    function writeByteArray(): any;
    function writeDouble(): any;
    function writeFloat(): any;
    function writeInt(): any;
    function writeLong(): any;
    function writePointer(): any;
    function writeS16(): any;
    function writeS32(): any;
    function writeS64(): any;
    function writeS8(): any;
    function writeShort(): any;
    function writeU16(): any;
    function writeU32(): any;
    function writeU64(): any;
    function writeU8(): any;
    function writeUInt(): any;
    function writeULong(): any;
    function writeUShort(): any;
    function writeUtf16String(): any;
    function writeUtf8String(): any;
}
declare namespace MemoryAccessMonitor {
    function disable(): any;
    function enable(): any;
}
declare namespace Module {
    function enumerateExports(): any;
    function enumerateExportsSync(name: any): any;
    function enumerateImports(): any;
    function enumerateImportsSync(name: any): any;
    function enumerateRanges(): any;
    function enumerateRangesSync(name: any, prot: any): any;
    function findBaseAddress(): any;
    function findExportByName(): any;
}
declare namespace ObjC {
    class Block {
        constructor(target: any);
        implementation(): void;
    }
    const api: {
    };
    const available: boolean;
    const classes: any;
    const protocols: any;
    function Object(handle: any, protocol: any, cachedIsClass: any, superSpecifier: any): any;
    function Protocol(handle: any): any;
    function bind(obj: any, data: any): void;
    function choose(specifier: any, callbacks: any): any;
    function chooseSync(specifier: any): any;
    function getBoundData(obj: any): any;
    function implement(method: any, fn: any): any;
    function registerClass(properties: any): any;
    function registerProtocol(properties: any): any;
    function registerProxy(properties: any): any;
    function schedule(queue: any, work: any): void;
    function selector(name: any): any;
    function selectorAsString(sel: any): any;
    function unbind(obj: any): void;
    namespace mainQueue {
        function add(): any;
        function and(): any;
        function compare(): any;
        function equals(ptr: any): any;
        function isNull(): any;
        function or(): any;
        function shl(): any;
        function shr(): any;
        function sub(): any;
        function toInt32(): any;
        function toJSON(): any;
        function toMatchPattern(): any;
        function toString(): any;
        function xor(): any;
    }
}
declare namespace Process {
    const arch: string;
    const pageSize: number;
    const platform: string;
    const pointerSize: number;
    function enumerateMallocRanges(): any;
    function enumerateMallocRangesSync(): any;
    function enumerateModules(): any;
    function enumerateModulesSync(): any;
    function enumerateRanges(specifier: any, callbacks: any): void;
    function enumerateRangesSync(specifier: any): any;
    function enumerateThreads(): any;
    function enumerateThreadsSync(): any;
    function findModuleByAddress(address: any): any;
    function findModuleByName(name: any): any;
    function findRangeByAddress(address: any): any;
    function getCurrentThreadId(): any;
    function getModuleByAddress(address: any): any;
    function getModuleByName(name: any): any;
    function getRangeByAddress(address: any): any;
    function isDebuggerAttached(): any;
    function setExceptionHandler(): any;
}
declare namespace Script {
    const fileName: string;
    const runtime: string;
    function nextTick(callback: any, args: any): void;
    function pin(): any;
    function setGlobalAccessHandler(): any;
    function unpin(): any;
    namespace sourceMap {
        function resolve(generatedPosition: any): any;
    }
}
declare namespace Socket {
    function connect(options: any): any;
    function listen(options: any): any;
    function localAddress(): any;
    function peerAddress(): any;
    function type(): any;
}
declare namespace Stalker {
    const queueCapacity: number;
    const queueDrainInterval: number;
    const trustThreshold: number;
    function addCallProbe(): any;
    function follow(first: any, second: any): any;
    function garbageCollect(): any;
    function removeCallProbe(): any;
    function unfollow(): any;
}
declare namespace Thread {
    function backtrace(): any;
    function sleep(): any;
}
declare namespace WeakRef {
    function bind(): any;
    function unbind(): any;
}
declare namespace console {
    function error(...args: any[]): void;
    function log(...args: any[]): void;
    function warn(...args: any[]): void;
}
