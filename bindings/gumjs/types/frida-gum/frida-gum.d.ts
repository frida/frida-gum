/**
 * Returns a hexdump of the provided ArrayBuffer or NativePointerValue target.
 *
 * @param target The ArrayBuffer or NativePointerValue to dump.
 * @param options Options customizing the output.
 */
declare function hexdump(target: ArrayBuffer | NativePointerValue, options?: HexdumpOptions): string;

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
 * This is useful if you e.g. dumped some memory using `NativePointer#readByteArray()`.
 */
declare function send(message: any, data: ArrayBuffer | number[] | null): void;

/**
 * Calls `func` when Frida's event loop is idle.
 * Returns an id that can be passed to `clearTimeout()` to cancel it.
 */
declare function setTimeout(func: ScheduledCallback): TimeoutId;

/**
 * Calls `func` after delay milliseconds, optionally passing it the provided params.
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
 * Calls `func` every `delay` milliseconds, optionally passing it the provided params.
 * Returns an id that can be passed to clearInterval() to cancel it.
 */
declare function setInterval(func: ScheduledCallback, delay: number, ...params: any[]): IntervalId;

/**
 * Cancels a previously scheduled `setInterval()`.
 */
declare function clearInterval(id: IntervalId): void;

/**
 * Opaque ID returned by `setInterval()`. Pass it to `clearInterval()` to cancel a pending `setInterval()`.
 */
declare interface IntervalId {}

/**
 * Schedules `func` to be called on Frida's JavaScript thread, optionally passing it the provided params.
 * Returns an id that can be passed to clearImmediate() to cancel it.
 */
declare function setImmediate(func: ScheduledCallback, ...params: any[]): ImmediateId;

/**
 * Cancels a previously scheduled `clearImmediate()`.
 */
declare function clearImmediate(id: ImmediateId): void;

/**
 * Opaque ID returned by `setImmediate()`. Pass it to `clearImmediate()` to cancel a pending `setImmediate()`.
 */
declare interface ImmediateId {}

declare type ScheduledCallback = (...params: any[]) => void;

/**
 * Force garbage collection.
 */
declare function gc(): void;

declare namespace rpc {
    /**
     * Empty object that you can either replace or insert into to expose an RPC-style API to your application.
     * The key specifies the method name and the value is your exported function. This function may either return
     * a plain value for returning that to the caller immediately, or a Promise for returning asynchronously.
     */
    let exports: RpcExports;
}

declare interface RpcExports {
    [name: string]: AnyFunction;
}

declare type AnyFunction = (...args: any[]) => any;

declare namespace Frida {
    /**
     * The current Frida version.
     */
    const version: string;

    /**
     * The current size – in bytes – of Frida’s private heap, which is shared by all scripts and Frida’s own runtime.
     * This is useful for keeping an eye on how much memory your instrumentation is using out of the total consumed by
     * the hosting process.
     */
    const heapSize: number;
}

declare namespace Process {
    /**
     * PID of the current process.
     */
    const id: number;

    /**
     * Architecture of the current process.
     */
    const arch: Architecture;

    /**
     * Platform of the current process.
     */
    const platform: Platform;

    /**
     * Size of a virtual memory page in bytes. This is used to make your scripts more portable.
     */
    const pageSize: number;

    /**
     * Size of a pointer in bytes. This is used to make your scripts more portable.
     */
    const pointerSize: number;

    /**
     * Whether Frida will avoid modifying existing code in memory and will not try to run unsigned code.
     * Currently this property will always be set to Optional unless you are using Gadget and have configured
     * it to assume that code-signing is required. This property allows you to determine whether the Interceptor
     * API is off limits, and whether it is safe to modify code or run unsigned code.
     */
    const codeSigningPolicy: CodeSigningPolicy;

    /**
     * Determines whether a debugger is currently attached.
     */
    function isDebuggerAttached(): boolean;

    /**
     * Gets this thread’s OS-specific id.
     */
    function getCurrentThreadId(): ThreadId;

    /**
     * Enumerates all threads.
     */
    function enumerateThreads(): ThreadDetails[];

    /**
     * Looks up a module by address. Returns null if not found.
     */
    function findModuleByAddress(address: any): Module | null;

    /**
     * Looks up a module by address. Throws an exception if not found.
     */
    function getModuleByAddress(address: any): Module;

    /**
     * Looks up a module by name. Returns null if not found.
     */
    function findModuleByName(name: any): Module | null;

    /**
     * Looks up a module by name. Throws an exception if not found.
     */
    function getModuleByName(name: any): Module;

    /**
     * Enumerates modules loaded right now.
     */
    function enumerateModules(): Module[];

    /**
     * Looks up a memory range by address. Returns null if not found.
     */
    function findRangeByAddress(address: any): RangeDetails | null;

    /**
     * Looks up a memory range by address. Throws an exception if not found.
     */
    function getRangeByAddress(address: any): RangeDetails;

    /**
      * Enumerates memory ranges satisfying `specifier`.
      *
      * @param specifier The kind of ranges to include.
      */
    function enumerateRanges(specifier: PageProtection | EnumerateRangesSpecifier): RangeDetails[];

    /**
     * Just like `enumerateRanges()`, but for individual memory allocations known to the system heap.
     */
    function enumerateMallocRanges(): RangeDetails[];

    /**
     * Installs a process-wide exception handler callback that gets a chance to handle native exceptions before the
     * hosting process itself does.
     *
     * It is up to your callback to decide what to do with the exception. It could for example:
     * - Log the issue.
     * - Notify your application through a `send()` followed by a blocking `recv()` for acknowledgement of the sent data
     *   being received.
     * - Modify registers and memory to recover from the exception.
     *
     * You should return true if you did handle the exception, in which case Frida will resume the thread immediately.
     * If you do not return true, Frida will forward the exception to the hosting process’ exception handler, if it has
     * one, or let the OS terminate the process.
     */
    function setExceptionHandler(callback: ExceptionHandlerCallback): void;
}

declare class Module {
    /**
     * Canonical module name.
     */
    name: string;

    /**
     * Base address.
     */
    base: NativePointer;

    /**
     * Size in bytes.
     */
    size: number;

    /**
     * Full filesystem path.
     */
    path: string;

    /**
     * Enumerates imports of module.
     */
    enumerateImports(): ModuleImportDetails[];

    /**
     * Enumerates exports of module.
     */
    enumerateExports(): ModuleExportDetails[];

    /**
     * Enumerates symbols of module.
     */
    enumerateSymbols(): ModuleSymbolDetails[];

    /**
     * Enumerates memory ranges of module with the `name` as seen in `Process#enumerateModules()`.
     *
     * @param protection Minimum protection of ranges to include.
     */
    enumerateRanges(protection: PageProtection): RangeDetails[];

    /**
     * Looks up the absolute address of the export named `exportName`.
     *
     * Returns null if the export doesn't exist.
     *
     * @param exportName Export name to find the address of.
     */
    findExportByName(exportName: string): NativePointer | null;

    /**
     * Looks up the absolute address of the export named `exportName`.
     *
     * Throws an exception if the export doesn't exist.
     *
     * @param exportName Export name to find the address of.
     */
    getExportByName(exportName: string): NativePointer;

    /**
     * Loads the specified module.
     */
    static load(name: string): Module;

    /**
     * Ensures that initializers of the specified module have been run. This is important during early instrumentation,
     * i.e. code run early in the process lifetime, to be able to safely interact with APIs.
     *
     * One such use-case is interacting with ObjC classes provided by a given module.
     */
    static ensureInitialized(name: string): void;

    /**
     * Looks up the base address of the `name` module. Returns null if the module isn’t loaded.
     *
     * @param name Module name or path.
     */
    static findBaseAddress(name: string): NativePointer | null;

    /**
     * Looks up the base address of the `name` module. Throws an exception if the module isn’t loaded.
     *
     * @param name Module name or path.
     */
    static getBaseAddress(name: string): NativePointer;

    /**
     * Looks up the absolute address of the export named `exportName` in `moduleName`. If the module isn’t known you may
     * pass null instead of its name, but this can be a costly search and should be avoided.
     *
     * Returns null if the module or export doesn't exist.
     *
     * @param moduleName Module name or path.
     * @param exportName Export name to find the address of.
     */
    static findExportByName(moduleName: string | null, exportName: string): NativePointer | null;

    /**
     * Looks up the absolute address of the export named `exportName` in `moduleName`. If the module isn’t known you may
     * pass null instead of its name, but this can be a costly search and should be avoided.
     *
     * Throws an exception if the module or export doesn't exist.
     *
     * @param moduleName Module name or path.
     * @param exportName Export name to find the address of.
     */
    static getExportByName(moduleName: string | null, exportName: string): NativePointer;
}

declare class ModuleMap {
    /**
     * Creates a new module map optimized for determining which module a given memory address belongs to, if any.
     * Takes a snapshot of the currently loaded modules when created, which may be refreshed by calling `update()`.
     *
     * The `filter` argument is optional and allows you to pass a function used for filtering the list of modules.
     * This is useful if you e.g. only care about modules owned by the application itself, and allows you to quickly
     * check if an address belongs to one of its modules. The filter function is given the module's details and must
     * return true for each module that should be kept in the map. It is called for each loaded module every time the
     * map is updated.
     *
     * @param filter Filter function to decide which modules are kept in the map.
     */
    constructor(filter?: ModuleMapFilter);

    /**
     * Determines if `address` belongs to any of the contained modules.
     *
     * @param address Address that might belong to a module in the map.
     */
    has(address: NativePointerValue): boolean;

    /**
     * Looks up a module by address. Returns null if not found.
     *
     * @param address Address that might belong to a module in the map.
     */
    find(address: NativePointerValue): Module | null;

    /**
     * Looks up a module by address. Throws an exception if not found.
     *
     * @param address Address that might belong to a module in the map.
     */
    get(address: NativePointerValue): Module;

    /**
     * Just like `find()`, but only returns the `name` field, which means less overhead when you don’t need the
     * other details. Returns null if not found.
     *
     * @param address Address that might belong to a module in the map.
     */
    findName(address: NativePointerValue): string | null;

    /**
     * Just like `get()`, but only returns the `name` field, which means less overhead when you don’t need the
     * other details. Throws an exception if not found.
     *
     * @param address Address that might belong to a module in the map.
     */
    getName(address: NativePointerValue): string;

    /**
     * Just like `find()`, but only returns the `path` field, which means less overhead when you don’t need the
     * other details. Returns null if not found.
     *
     * @param address Address that might belong to a module in the map.
     */
    findPath(address: NativePointerValue): string | null;

    /**
     * Just like `get()`, but only returns the `path` field, which means less overhead when you don’t need the
     * other details. Throws an exception if not found.
     *
     * @param address Address that might belong to a module in the map.
     */
    getPath(address: NativePointerValue): string;

    /**
     * Updates the map.
     *
     * You should call this after a module has been loaded or unloaded to avoid operating on stale data.
     */
    update(): void;

    /**
     * Gets the modules currently in the map. The returned array is a deep copy and will not mutate after a
     * call to `update()`.
     */
    values(): Module[];
}

type ModuleMapFilter = (m: Module) => boolean;

declare namespace Memory {
    /**
     * Scans memory for occurences of `pattern` in the memory range given by `address` and `size`.
     *
     * @param address Starting address to scan from.
     * @param size Number of bytes to scan.
     * @param pattern Match pattern of the form “13 37 ?? ff” to match 0x13 followed by 0x37 followed by any byte
     *                followed by 0xff. For more advanced matching it is also possible to specify an r2-style mask.
     *                The mask is bitwise AND-ed against both the needle and the haystack. To specify the mask append
     *                a `:` character after the needle, followed by the mask using the same syntax.
     *                For example: “13 37 13 37 : 1f ff ff f1”.
     *                For convenience it is also possible to specify nibble-level wildcards, like “?3 37 13 ?7”,
     *                which gets translated into masks behind the scenes.
     * @param callbacks Object with callbacks.
     */
    function scan(address: NativePointerValue, size: number | UInt64, pattern: string, callbacks: MemoryScanCallbacks): void;

    /**
     * Synchronous version of `scan()`.
     *
     * @param address Starting address to scan from.
     * @param size Number of bytes to scan.
     * @param pattern Match pattern, see `Memory.scan()` for details.
     */
    function scanSync(address: NativePointerValue, size: number | UInt64, pattern: string): MemoryScanMatch[];

    /**
     * Allocates `size` bytes of memory on Frida's private heap, or, if `size` is a multiple of Process#pageSize,
     * one or more raw memory pages managed by the OS. The allocated memory will be released when the returned
     * NativePointer value gets garbage collected. This means you need to keep a reference to it while the pointer
     * is being used by code outside the JavaScript runtime.
     *
     * @param size Number of bytes to allocate.
     */
    function alloc(size: number | UInt64): NativePointer;

    /**
     * Allocates, encodes and writes out `str` as a UTF-8 string on Frida's private heap.
     * See Memory#alloc() for details about its lifetime.
     *
     * @param str String to allocate.
     */
    function allocUtf8String(str: string): NativePointer;

    /**
     * Allocates, encodes and writes out `str` as a UTF-16 string on Frida's private heap.
     * See Memory#alloc() for details about its lifetime.
     *
     * @param str String to allocate.
     */
    function allocUtf16String(str: string): NativePointer;

    /**
     * Allocates, encodes and writes out `str` as an ANSI string on Frida's private heap.
     * See Memory#alloc() for details about its lifetime.
     *
     * @param str String to allocate.
     */
    function allocAnsiString(str: string): NativePointer;

    /**
     * Just like memcpy.
     *
     * @param dst Destination address.
     * @param src Sources address.
     * @param n Number of bytes to copy.
     */
    function copy(dst: NativePointerValue, src: NativePointerValue, n: number | UInt64): void;

    /**
     * Short-hand for Memory#alloc() followed by Memory#copy(). See Memory#alloc() for details about lifetime.
     *
     * @param address Address to copy from.
     * @param size Number of bytes to copy.
     */
    function dup(address: NativePointerValue, size: number | UInt64): NativePointer;

    /**
     * Changes the page protection on a region of memory.
     *
     * @param address Starting address.
     * @param size Number of bytes. Must be a multiple of Process#pageSize.
     * @param protection Desired page protection.
     */
    function protect(address: NativePointerValue, size: number | UInt64, protection: PageProtection): boolean;

    /**
     * Safely modifies `size` bytes at `address`. The supplied function `apply` gets called with a writable pointer
     * where you must write the desired modifications before returning. Do not make any assumptions about this being
     * the same location as address, as some systems require modifications to be written to a temporary location before
     * being mapped into memory on top of the original memory page (e.g. on iOS, where directly modifying in-memory
     * code may result in the process losing its CS_VALID status).
     *
     * @param address Starting address to modify.
     * @param size Number of bytes to modify.
     * @param apply Function that applies the desired changes.
     */
    function patchCode(address: NativePointerValue, size: number | UInt64, apply: MemoryPatchApplyCallback): void;
}

declare namespace Thread {
    function backtrace(context: CpuContext, backtracer?: Backtracer): NativePointer[];
    function sleep(duration: number): void;
}

declare class Backtracer {
    static ACCURATE: Backtracer;
    static FUZZY: Backtracer;
}

declare const enum Architecture {
    Ia32 = "ia32",
    X64 = "x64",
    Arm = "arm",
    Arm64 = "arm64",
    Mips = "mips"
}

declare const enum Platform {
    Windows = "windows",
    Darwin = "darwin",
    Linux = "linux",
    Qnx = "qnx"
}

declare const enum CodeSigningPolicy {
    Optional = "optional",
    Required = "required"
}

/**
 * Given as a string of the form: rwx, where rw- means “readable and writable”.
 */
declare type PageProtection = string;

declare type ThreadId = number;

declare const enum ThreadState {
    Running = "running",
    Stopped = "stopped",
    Waiting = "waiting",
    Uninterruptible = "uninterruptible",
    Halted = "halted"
}

declare interface ThreadDetails {
    /**
     * OS-specific ID.
     */
    id: ThreadId;

    /**
     * Snapshot of state.
     */
    state: ThreadState;

    /**
     * Snapshot of CPU registers.
     */
    context: CpuContext;
}

declare interface KernelModuleDetails {
    /**
     * Canonical module name.
     */
    name: string;

    /**
     * Base address.
     */
    base: UInt64;

    /**
     * Size in bytes.
     */
    size: number;
}

declare interface ModuleImportDetails {
    /**
     * The kind of import, if available.
     */
    type?: ModuleImportType;

    /**
     * Imported symbol name.
     */
    name: string;

    /**
     * Module name, if available.
     */
    module?: string;

    /**
     * Absolute address, if available.
     */
    address?: NativePointer;

    /**
     * Memory location where the import is stored, if available.
     */
    slot?: NativePointer;
}

declare interface ModuleExportDetails {
    /**
     * The kind of export.
     */
    type: ModuleExportType;

    /**
     * Exported symbol name.
     */
    name: string;

    /**
     * Absolute address.
     */
    address: NativePointer;
}

declare interface ModuleSymbolDetails {
    /**
     * Whether symbol is globally visible.
     */
    isGlobal: boolean;

    /**
     * The kind of symbol.
     */
    type: ModuleSymbolType;

    /**
     * Which section this symbol resides in, if available.
     */
    section?: ModuleSymbolSectionDetails;

    /**
     * Symbol name.
     */
    name: string;

    /**
     * Absolute address.
     */
    address: NativePointer;
}

declare const enum ModuleImportType {
    Function = "function",
    Variable = "variable"
}

declare const enum ModuleExportType {
    Function = "function",
    Variable = "variable"
}

declare const enum ModuleSymbolType {
    // Common
    Unknown = "unknown",
    Section = "section",

    // Mach-O
    Undefined = "undefined",
    Absolute = "absolute",
    PreboundUndefined = "prebound-undefined",
    Indirect = "indirect",

    // ELF
    Object = "object",
    Function = "function",
    File = "file",
    Common = "common",
    Tls = "tls"
}

declare interface ModuleSymbolSectionDetails {
    /**
     * Section index, segment name (if applicable) and section name – same format as r2’s section IDs.
     */
    id: string;

    /**
     * Section's memory protection.
     */
    protection: PageProtection;
}

declare interface RangeDetails {
    /**
     * Base address.
     */
    base: NativePointer;

    /**
     * Size in bytes.
     */
    size: number;

    /**
     * Protection.
     */
    protection: PageProtection;

    /**
     * File mapping details, if available.
     */
    file?: FileMapping;
}

declare interface KernelRangeDetails {
    /**
     * Base address.
     */
    base: UInt64;

    /**
     * Size in bytes.
     */
    size: number;

    /**
     * Protection.
     */
    protection: PageProtection;
}

declare interface KernelModuleRangeDetails {
    /**
     * Name.
     */
    name: string;

    /**
     * Base address.
     */
    base: UInt64;

    /**
     * Size in bytes.
     */
    size: number;

    /**
     * Protection.
     */
    protection: PageProtection;
}

declare interface FileMapping {
    /**
     * Full filesystem path.
     */
    path: string;

    /**
     * Offset in the mapped file on disk, in bytes.
     */
    offset: number;

    /**
     * Size in the mapped file on disk, in bytes.
     */
    size: number;
}

declare interface EnumerateRangesSpecifier {
    /**
     * Minimum protection required to be included in the result.
     */
    protection: PageProtection;

    /**
     * Whether neighboring ranges with the same protection should be coalesced. The default is false.
     */
    coalesce: boolean;
}

declare type ExceptionHandlerCallback = (exception: ExceptionDetails) => boolean | void;

declare interface ExceptionDetails {
    /**
     * The kind of exception that occurred.
     */
    type: ExceptionType;

    /**
     * Address where the exception occurred.
     */
    address: NativePointer;

    /**
     * Memory operation details, if relevant.
     */
    memory?: ExceptionMemoryDetails;

    /**
     * CPU registers. You may also update register values by assigning to these keys.
     */
    context: CpuContext;

    /**
     * Address of the OS and architecture-specific CPU context struct.
     *
     * This is only exposed as a last resort for edge-cases where `context` isn’t providing enough details.
     * We would however discourage using this and rather submit a pull-request to add the missing bits needed
     * for your use-case.
     */
    nativeContext: NativePointer;
}

declare const enum ExceptionType {
    Abort = "abort",
    AccessViolation = "access-violation",
    GuardPage = "guard-page",
    IllegalInstruction = "illegal-instruction",
    StackOverflow = "stack-overflow",
    Arithmetic = "arithmetic",
    Breakpoint = "breakpoint",
    SingleStep = "single-step",
    System = "system"
}

declare interface ExceptionMemoryDetails {
    /**
     * The kind of operation that triggered the exception.
     */
    operation: ExceptionMemoryOperation;

    /**
     * Address that was accessed when the exception occurred.
     */
    address: NativePointer;
}

declare const enum ExceptionMemoryOperation {
    read = "read",
    write = "write",
    execute = "execute"
}

declare interface EnumerateCallbacks<T> {
    onMatch: (item: T) => void | EnumerateAction;
    onComplete: () => void;
}

declare const enum EnumerateAction {
    Stop = "stop"
}

declare interface MemoryScanCallbacks {
    /**
     * Called with each occurence that was found.
     *
     * @param address Memory address where a match was found.
     * @param size Size of this match.
     */
    onMatch: (address: NativePointer, size: number) => void | EnumerateAction;

    /**
     * Called when there was a memory access error while scanning.
     *
     * @param reason Why the memory access failed.
     */
    onError?: (reason: string) => void;

    /**
     * Called when the memory range has been fully scanned.
     */
    onComplete: () => void;
}

declare interface MemoryScanMatch {
    /**
     * Memory address where a match was found.
     */
    address: NativePointer;

    /**
     * Size of this match.
     */
    size: number;
}

declare interface KernelMemoryScanCallbacks {
    /**
     * Called with each occurence that was found.
     *
     * @param address Memory address where a match was found.
     * @param size Size of this match.
     */
    onMatch: (address: UInt64, size: number) => void | EnumerateAction;

    /**
     * Called when there was a memory access error while scanning.
     *
     * @param reason Why the memory access failed.
     */
    onError?: (reason: string) => void;

    /**
     * Called when the memory range has been fully scanned.
     */
    onComplete: () => void;
}

declare interface KernelMemoryScanMatch {
    /**
     * Memory address where a match was found.
     */
    address: UInt64;

    /**
     * Size of this match.
     */
    size: number;
}

declare type MemoryPatchApplyCallback = (code: NativePointer) => void;

/**
 * Represents a signed 64-bit value.
 */
declare class Int64 {
    /**
     * Creates a new Int64 from `v`, which is either a string containing the value in decimal, or hexadecimal
     * if prefixed with “0x”, or a number. You may use the int64(v) short-hand for brevity.
     */
    constructor(v: string | number | Int64);

    /**
     * Makes a new Int64 whose value is `this` + `v`.
     */
    add(v: Int64 | number | string): Int64;

    /**
     * Makes a new Int64 whose value is `this` - `v`.
     */
    sub(v: Int64 | number | string): Int64;

    /**
     * Makes a new Int64 whose value is `this` & `v`.
     */
    and(v: Int64 | number | string): Int64;

    /**
     * Makes a new Int64 whose value is `this` | `v`.
     */
    or(v: Int64 | number | string): Int64;

    /**
     * Makes a new Int64 whose value is `this` ^ `v`.
     */
    xor(v: Int64 | number | string): Int64;

    /**
     * Makes a new Int64 whose value is `this` << `v`.
     */
    shr(v: Int64 | number | string): Int64;

    /**
     * Makes a new Int64 whose value is `this` >> `v`.
     */
    shl(v: Int64 | number | string): Int64;

    /**
     * Makes a new Int64 whose value is ~`this`.
     */
    not(): Int64;

    /**
     * Returns an integer comparison result just like String#localeCompare().
     */
    compare(v: Int64 | number | string): number;

    /**
     * Returns a boolean indicating whether `v` is equal to `this`.
     */
    equals(v: Int64 | number | string): boolean;

    /**
     * Converts to a number.
     */
    toNumber(): number;

    /**
     * Converts to a string.
     */
    toString(): string;

    /**
     * Converts to a string with `radix`.
     */
    toString(radix: number): string;

    /**
     * Converts to a JSON-serializable value. Same as `toString()`.
     */
    toJSON(): string;

    /**
     * Converts to a number. Same as `toNumber()`.
     */
    valueOf(): number;
}

/**
 * Represents an unsigned 64-bit value.
 */
declare class UInt64 {
    /**
     * Creates a new UInt64 from `v`, which is either a string containing the value in decimal, or hexadecimal
     * if prefixed with “0x”, or a number. You may use the uint64(v) short-hand for brevity.
     */
    constructor(v: string | number | UInt64);

    /**
     * Makes a new UInt64 whose value is `this` + `v`.
     */
    add(v: UInt64 | number | string): UInt64;

    /**
     * Makes a new UInt64 whose value is `this` - `v`.
     */
    sub(v: UInt64 | number | string): UInt64;

    /**
     * Makes a new UInt64 whose value is `this` & `v`.
     */
    and(v: UInt64 | number | string): UInt64;

    /**
     * Makes a new UInt64 whose value is `this` | `v`.
     */
    or(v: UInt64 | number | string): UInt64;

    /**
     * Makes a new UInt64 whose value is `this` ^ `v`.
     */
    xor(v: UInt64 | number | string): UInt64;

    /**
     * Makes a new UInt64 whose value is `this` << `v`.
     */
    shr(v: UInt64 | number | string): UInt64;

    /**
     * Makes a new UInt64 whose value is `this` >> `v`.
     */
    shl(v: UInt64 | number | string): UInt64;

    /**
     * Makes a new UInt64 whose value is ~`this`.
     */
    not(): UInt64;

    /**
     * Returns an integer comparison result just like String#localeCompare().
     */
    compare(v: UInt64 | number | string): number;

    /**
     * Returns a boolean indicating whether `v` is equal to `this`.
     */
    equals(v: UInt64 | number | string): boolean;

    /**
     * Converts to a number.
     */
    toNumber(): number;

    /**
     * Converts to a string.
     */
    toString(): string;

    /**
     * Converts to a string with `radix`.
     */
    toString(radix: number): string;

    /**
     * Converts to a JSON-serializable value. Same as `toString()`.
     */
    toJSON(): string;

    /**
     * Converts to a number. Same as `toNumber()`.
     */
    valueOf(): number;
}

/**
 * Represents a native pointer value whose size depends on Process#pointerSize.
 */
declare class NativePointer {
    /**
     * Creates a new NativePointer from `v`, which is either a string containing the memory address in decimal,
     * or hexadecimal if prefixed with “0x”, or a number. You may use the ptr(v) short-hand for brevity.
     */
    constructor(v: string | number | UInt64 | Int64 | NativePointerValue);

    /**
     * Returns a boolean allowing you to conveniently check if a pointer is `NULL`.
     */
    isNull(): boolean;

    /**
     * Makes a new NativePointer whose value is `this` + `v`.
     */
    add(v: NativePointerValue | UInt64 | Int64 | number | string): NativePointer;

    /**
     * Makes a new NativePointer whose value is `this` - `v`.
     */
    sub(v: NativePointerValue | UInt64 | Int64 | number | string): NativePointer;

    /**
     * Makes a new NativePointer whose value is `this` & `v`.
     */
    and(v: NativePointerValue | UInt64 | Int64 | number | string): NativePointer;

    /**
     * Makes a new NativePointer whose value is `this` | `v`.
     */
    or(v: NativePointerValue | UInt64 | Int64 | number | string): NativePointer;

    /**
     * Makes a new NativePointer whose value is `this` ^ `v`.
     */
    xor(v: NativePointerValue | UInt64 | Int64 | number | string): NativePointer;

    /**
     * Makes a new NativePointer whose value is `this` << `v`.
     */
    shr(v: NativePointerValue | UInt64 | Int64 | number | string): NativePointer;

    /**
     * Makes a new NativePointer whose value is `this` >> `v`.
     */
    shl(v: NativePointerValue | UInt64 | Int64 | number | string): NativePointer;

    /**
     * Returns a boolean indicating whether `v` is equal to `this`; i.e. it contains the same memory address.
     */
    equals(v: NativePointerValue | UInt64 | Int64 | number | string): boolean;

    /**
     * Returns an integer comparison result just like String#localeCompare().
     */
    compare(v: NativePointerValue | UInt64 | Int64 | number | string): number;

    /**
     * Converts to a signed 32-bit integer.
     */
    toInt32(): number;

    /**
     * Converts to a “0x”-prefixed hexadecimal string.
     */
    toString(): string;

    /**
     * Converts to a string with `radix`.
     */
    toString(radix: number): string;

    /**
     * Converts to a JSON-serializable value. Same as `toString()`.
     */
    toJSON(): string;

    /**
     * Returns a string containing a `Memory#scan()`-compatible match pattern for this pointer’s raw value.
     */
    toMatchPattern(): string;

    readPointer(): NativePointer;
    readS8(): number;
    readU8(): number;
    readS16(): number;
    readU16(): number;
    readS32(): number;
    readU32(): number;
    readS64(): Int64;
    readU64(): UInt64;
    readShort(): number;
    readUShort(): number;
    readInt(): number;
    readUInt(): number;
    readLong(): number | Int64;
    readULong(): number | UInt64;
    readFloat(): number;
    readDouble(): number;
    readByteArray(length: number): ArrayBuffer | null;
    readCString(size?: number): string | null;
    readUtf8String(size?: number): string | null;
    readUtf16String(length?: number): string | null;
    readAnsiString(size?: number): string | null;

    writePointer(value: NativePointerValue): NativePointer;
    writeS8(value: number | Int64): NativePointer;
    writeU8(value: number | UInt64): NativePointer;
    writeS16(value: number | Int64): NativePointer;
    writeU16(value: number | UInt64): NativePointer;
    writeS32(value: number | Int64): NativePointer;
    writeU32(value: number | UInt64): NativePointer;
    writeS64(value: number | Int64): NativePointer;
    writeU64(value: number | UInt64): NativePointer;
    writeShort(value: number | Int64): NativePointer;
    writeUShort(value: number | UInt64): NativePointer;
    writeInt(value: number | Int64): NativePointer;
    writeUInt(value: number | UInt64): NativePointer;
    writeLong(value: number | Int64): NativePointer;
    writeULong(value: number | UInt64): NativePointer;
    writeFloat(value: number): NativePointer;
    writeDouble(value: number): NativePointer;
    writeByteArray(value: ArrayBuffer | number[]): NativePointer;
    writeUtf8String(value: string): NativePointer;
    writeUtf16String(value: string): NativePointer;
    writeAnsiString(value: string): NativePointer;
}

declare interface ObjectWrapper {
    handle: NativePointer;
}

declare type NativePointerValue = NativePointer | ObjectWrapper;

declare class NativeFunction extends NativePointer {
    constructor(address: NativePointerValue, retType: NativeType, argTypes: NativeType[], abi?: NativeABI);
    constructor(address: NativePointerValue, retType: NativeType, argTypes: NativeType[], options?: NativeFunctionOptions);
    apply(thisArg: NativePointerValue | null | undefined, args: NativeArgumentValue[]): NativeReturnValue;
    call(): NativeReturnValue;
    call(thisArg: NativePointerValue | null | undefined, ...args: NativeArgumentValue[]): NativeReturnValue;
}

declare class SystemFunction extends NativePointer {
    constructor(address: NativePointerValue, retType: NativeType, argTypes: NativeType[], abi?: NativeABI);
    constructor(address: NativePointerValue, retType: NativeType, argTypes: NativeType[], options?: NativeFunctionOptions);
    apply(thisArg: NativePointerValue | null | undefined, args: NativeArgumentValue[]): SystemFunctionResult;
    call(): SystemFunctionResult;
    call(thisArg: NativePointerValue | null | undefined, ...args: NativeArgumentValue[]): SystemFunctionResult;
}

declare type SystemFunctionResult = WindowsSystemFunctionResult | UnixSystemFunctionResult;

declare interface WindowsSystemFunctionResult {
    value: NativeReturnValue;
    lastError: number;
}

declare interface UnixSystemFunctionResult {
    value: NativeReturnValue;
    errno: number;
}

declare class NativeCallback extends NativePointer {
    constructor(func: any, retType: NativeType, argTypes: NativeType[]);
}

declare type NativeArgumentValue = NativePointerValue | UInt64 | Int64 | number | boolean | any[];

declare type NativeReturnValue = NativePointer | UInt64 | Int64 | number | boolean | any[];

declare type NativeType = string | any[];

declare const enum NativeABI {
    Default = "default",
    SysV = "sysv",
    StdCall = "stdcall",
    ThisCall = "thiscall",
    FastCall = "fastcall",
    MSCDecl = "mscdecl",
    Win64 = "win64",
    Unix64 = "unix64",
    VFP = "vfp"
}

declare interface NativeFunctionOptions {
    abi?: NativeABI;
    scheduling?: SchedulingBehavior;
    exceptions?: ExceptionsBehavior;
}

declare const enum SchedulingBehavior {
    Cooperative = "cooperative",
    Exclusive = "exclusive"
}

declare const enum ExceptionsBehavior {
    Steal = "steal",
    Propagate = "propagate"
}

declare type CpuContext = PortableCpuContext | IA32CpuContext | X64CpuContext | ArmCpuContext | Arm64CpuContext | MipsCpuContext;

declare interface PortableCpuContext {
    pc: NativePointer;
    sp: NativePointer;
}

declare interface IA32CpuContext extends PortableCpuContext {
    eax: NativePointer;
    ecx: NativePointer;
    edx: NativePointer;
    ebx: NativePointer;
    esp: NativePointer;
    ebp: NativePointer;
    esi: NativePointer;
    edi: NativePointer;

    eip: NativePointer;
}

declare interface X64CpuContext extends PortableCpuContext {
    rax: NativePointer;
    rcx: NativePointer;
    rdx: NativePointer;
    rbx: NativePointer;
    rsp: NativePointer;
    rbp: NativePointer;
    rsi: NativePointer;
    rdi: NativePointer;

    r8: NativePointer;
    r9: NativePointer;
    r10: NativePointer;
    r11: NativePointer;
    r12: NativePointer;
    r13: NativePointer;
    r14: NativePointer;
    r15: NativePointer;

    rip: NativePointer;
}

declare interface ArmCpuContext extends PortableCpuContext {
    r0: NativePointer;
    r1: NativePointer;
    r2: NativePointer;
    r3: NativePointer;
    r4: NativePointer;
    r5: NativePointer;
    r6: NativePointer;
    r7: NativePointer;

    r8: NativePointer;
    r9: NativePointer;
    r10: NativePointer;
    r11: NativePointer;
    r12: NativePointer;

    lr: NativePointer;
}

declare interface Arm64CpuContext extends PortableCpuContext {
    x0: NativePointer;
    x1: NativePointer;
    x2: NativePointer;
    x3: NativePointer;
    x4: NativePointer;
    x5: NativePointer;
    x6: NativePointer;
    x7: NativePointer;
    x8: NativePointer;
    x9: NativePointer;
    x10: NativePointer;
    x11: NativePointer;
    x12: NativePointer;
    x13: NativePointer;
    x14: NativePointer;
    x15: NativePointer;
    x16: NativePointer;
    x17: NativePointer;
    x18: NativePointer;
    x19: NativePointer;
    x20: NativePointer;
    x21: NativePointer;
    x22: NativePointer;
    x23: NativePointer;
    x24: NativePointer;
    x25: NativePointer;
    x26: NativePointer;
    x27: NativePointer;
    x28: NativePointer;

    fp: NativePointer;
    lr: NativePointer;
}

declare interface MipsCpuContext extends PortableCpuContext {
    gp: NativePointer;
    fp: NativePointer;
    ra: NativePointer;

    hi: NativePointer;
    lo: NativePointer;

    at: NativePointer;

    v0: NativePointer;
    v1: NativePointer;

    a0: NativePointer;
    a1: NativePointer;
    a2: NativePointer;
    a3: NativePointer;

    t0: NativePointer;
    t1: NativePointer;
    t2: NativePointer;
    t3: NativePointer;
    t4: NativePointer;
    t5: NativePointer;
    t6: NativePointer;
    t7: NativePointer;
    t8: NativePointer;
    t9: NativePointer;

    s0: NativePointer;
    s1: NativePointer;
    s2: NativePointer;
    s3: NativePointer;
    s4: NativePointer;
    s5: NativePointer;
    s6: NativePointer;
    s7: NativePointer;

    k0: NativePointer;
    k1: NativePointer;
}

/**
 * TCP and UNIX sockets.
 */
declare namespace Socket {
    /**
     * Opens a TCP or UNIX listening socket.
     *
     * Defaults to listening on both IPv4 and IPv6, if supported, and binding on all interfaces on a randomly
     * selected port.
     */
    function listen(options?: SocketListenOptions): Promise<SocketListener>;

    /**
     * Connects to a TCP or UNIX server.
     */
    function connect(options: SocketConnectOptions): Promise<SocketConnection>;

    /**
     * Inspects the OS socket `handle` and returns its type, or `null` if invalid or unknown.
     */
    function type(handle: number): SocketType | null;

    /**
     * Inspects the OS socket `handle` and returns its local address, or `null` if invalid or unknown.
     */
    function localAddress(handle: number): SocketEndpointAddress | null;

    /**
     * Inspects the OS socket `handle` and returns its peer address, or `null` if invalid or unknown.
     */
    function peerAddress(handle: number): SocketEndpointAddress | null;
}

/**
 * Listener created by `Socket.listen()`.
 */
declare type SocketListener = TcpListener | UnixListener;

declare interface BaseListener {
    /**
     * Closes the listener, releasing resources related to it. Once the listener is closed, all other operations
     * will fail. Closing a listener multiple times is allowed and will not result in an error.
     */
    close(): Promise<void>;

    /**
     * Waits for the next client to connect.
     */
    accept(): Promise<SocketConnection>;
}

declare interface TcpListener extends BaseListener {
    /**
     * IP port being listened on.
     */
    port: number;
}

declare interface UnixListener extends BaseListener {
    /**
     * Path being listened on.
     */
    path: string;
}

declare interface SocketConnection extends IOStream {
    /**
     * Disables the Nagle algorithm if `noDelay` is `true`, otherwise enables it. The Nagle algorithm is enabled
     * by default, so it is only necessary to call this method if you wish to optimize for low delay instead of
     * high throughput.
     */
    setNoDelay(noDelay: boolean): Promise<void>;
}

declare interface IOStream {
    /**
     * The `InputStream` to read from.
     */
    input: InputStream;

    /**
     * The `OutputStream` to write to.
     */
    output: OutputStream;

    /**
     * Closes the stream, releasing resources related to it. This will also close the individual input and output
     * streams. Once the stream is closed, all other operations will fail. Closing a stream multiple times is allowed
     * and will not result in an error.
     */
    close(): Promise<void>;
}

declare interface InputStream {
    /**
     * Closes the stream, releasing resources related to it. Once the stream is closed, all other operations will fail.
     * Closing a stream multiple times is allowed and will not result in an error.
     */
    close(): Promise<void>;

    /**
     * Reads up to `size` bytes from the stream. The resulting buffer is up to `size` bytes long. End of stream is
     * signalled through an empty buffer.
     */
    read(size: number): Promise<ArrayBuffer>;

    /**
     * Keeps reading from the stream until exactly `size` bytes have been consumed. The resulting buffer is exactly
     * `size` bytes long. Premature error or end of stream results in an `Error` object with a `partialData` property
     * containing the incomplete data.
     */
    readAll(size: number): Promise<ArrayBuffer>;
}

declare interface OutputStream {
    /**
     * Closes the stream, releasing resources related to it. Once the stream is closed, all other operations will fail.
     * Closing a stream multiple times is allowed and will not result in an error.
     */
    close(): Promise<void>;

    /**
     * Tries to write `data` to the stream. Returns how how many bytes of `data` were written to the stream.
     */
    write(data: ArrayBuffer | number[]): Promise<number>;

    /**
     * Keeps writing to the stream until all of `data` has been written. Premature error or end of stream results in an
     * `Error` object with a `partialSize` property specifying how many bytes of `data` were written to the stream
     * before the error occurred.
     */
    writeAll(data: ArrayBuffer | number[]): Promise<void>;
}

declare const enum AddressFamily {
    Unix = "unix",
    IPv4 = "ipv4",
    IPv6 = "ipv6"
}

declare const enum SocketType {
    Tcp = "tcp",
    Udp = "udp",
    Tcp6 = "tcp6",
    Udp6 = "udp6",
    UnixStream = "unix:stream",
    UnixDatagram = "unix:dgram"
}

declare const enum UnixSocketType {
    Anonymous = "anonymous",
    Path = "path",
    Abstract = "abstract",
    AbstractPadded = "abstract-padded"
}

declare type SocketListenOptions = TcpListenOptions | UnixListenOptions;

declare interface TcpListenOptions extends BaseListenOptions {
    /**
     * Address family. Omit to listen on both ipv4 and ipv6 – if supported by the OS.
     */
    family?: AddressFamily.IPv4 | AddressFamily.IPv6;

    /**
     * Host or IP address to listen on. Omit to listen on all interfaces.
     */
    host?: string;

    /**
     * Port to listen on. Omit to listen on a randomly selected port.
     */
    port?: number;
}

declare interface UnixListenOptions extends BaseListenOptions {
    /**
     * Address family.
     */
    family: AddressFamily.Unix;

    /**
     * Type of UNIX socket to listen on. Defaults to UnixSocketType.Path.
     */
    type?: UnixSocketType;

    /**
     * UNIX socket path to listen on.
     */
    path: string;
}

declare interface BaseListenOptions {
    /**
     * Listen backlog. Defaults to 10.
     */
    backlog?: number;
}

declare type SocketConnectOptions = TcpConnectOptions | UnixConnectOptions;

declare interface TcpConnectOptions {
    /**
     * Address family. Omit to determine based on the host specified.
     */
    family?: AddressFamily.IPv4 | AddressFamily.IPv6;

    /**
     * Host or IP address to connect to. Defaults to `localhost`.
     */
    host?: string;

    /**
     * IP port to connect to.
     */
    port: number;

    /**
     * Whether to create a TLS connection. Defaults to `false`.
     */
    tls?: boolean;
}

declare interface UnixConnectOptions {
    /**
     * Address family.
     */
    family: AddressFamily.Unix;

    /**
     * Type of UNIX socket to connect to. Defaults to UnixSocketType.Path.
     */
    type?: UnixSocketType;

    /**
     * Path to UNIX socket to connect to.
     */
    path: string;

    /**
     * Whether to create a TLS connection. Defaults to `false`.
     */
    tls?: boolean;
}

declare type SocketEndpointAddress = TcpEndpointAddress | UnixEndpointAddress;

declare interface TcpEndpointAddress {
    /**
     * IP address.
     */
    ip: string;

    /**
     * Port.
     */
    port: number;
}

declare interface UnixEndpointAddress {
    /**
     * UNIX socket path.
     */
    path: string;
}

/**
 * Intercepts execution through inline hooking.
 */
declare namespace Interceptor {
    /**
     * Intercepts calls to function at `target`.
     */
    function attach(target: NativePointerValue, callbacks: InvocationListenerCallbacks): InvocationListener;

    /**
     * Intercepts execution of instruction at `target`.
     */
    function attach(target: NativePointerValue, probe: InstructionProbeCallback): InvocationListener;

    /**
     * Detaches all previously attached listeners.
     */
    function detachAll(): void;

    /**
     * Replaces function at `target` with implementation at `replacement`.
     */
    function replace(target: NativePointerValue, replacement: NativePointerValue): void;

    /**
     * Reverts the previously replaced function at `target`.
     */
    function revert(target: NativePointerValue): void;
}

declare class InvocationListener {
    /**
     * Detaches listener previously attached through `Interceptor#attach()`.
     */
    detach(): void;
}

/**
 * Callbacks to invoke synchronously before and after a function call.
 */
declare interface InvocationListenerCallbacks {
    onEnter?: (this: InvocationContext, args: InvocationArguments) => void;
    onLeave?: (this: InvocationContext, retval: InvocationReturnValue) => void;
}

/**
 * Callback to invoke when an instruction is about to be executed.
 */
declare type InstructionProbeCallback = (this: InvocationContext, args: InvocationArguments) => void;

/**
 * Virtual array providing access to the argument list. Agnostic to the number of arguments and their types.
 */
declare type InvocationArguments = NativePointer[];

/**
 * Value that is about to be returned.
 */
declare class InvocationReturnValue extends NativePointer {
    /**
     * Replaces the return value that would otherwise be returned.
     */
    replace(value: NativePointerValue): void;
}

declare type InvocationContext = PortableInvocationContext | WindowsInvocationContext | UnixInvocationContext;

declare interface PortableInvocationContext {
    /**
     * Return address.
     */
    returnAddress: NativePointer;

    /**
     * CPU registers. You may also update register values by assigning to these keys.
     */
    context: CpuContext;

    /**
     * OS thread ID.
     */
    threadId: ThreadId;

    /**
     * Call depth of relative to other invocations.
     */
    depth: number;

    /**
     * User-defined invocation data. Useful if you want to read an argument in `onEnter` and act on it in `onLeave`.
     */
    [x: string]: any;
}

declare interface WindowsInvocationContext extends PortableInvocationContext {
    /**
     * Current OS error value (you may replace it).
     */
    lastError: number;
}

declare interface UnixInvocationContext extends PortableInvocationContext {
    /**
     * Current errno value (you may replace it).
     */
    errno: number;
}

declare class Instruction {
    /**
     * Parses the instruction at the `target` address in memory.
     *
     * Note that on 32-bit ARM this address must have its least significant bit
     * set to 0 for ARM functions, and 1 for Thumb functions. Frida takes care
     * of this detail for you if you get the address from a Frida API, for
     * example `Module.getExportByName()`.
     *
     * @param target Memory location containing instruction to parse.
     */
    static parse(target: NativePointerValue): Instruction | X86Instruction | ArmInstruction | Arm64Instruction | MipsInstruction;

    /**
     * Address (EIP) of this instruction.
     */
    address: NativePointer;

    /**
     * Pointer to the next instruction, so you can `parse()` it.
     */
    next: NativePointer;

    /**
     * Size of this instruction.
     */
    size: number;

    /**
     * Instruction mnemonic.
     */
    mnemonic: string;

    /**
     * String representation of instruction operands.
     */
    opStr: string;

    /**
     * Group names that this instruction belongs to.
     */
    groups: string[];

    /**
     * Converts to a human-readable string.
     */
    toString(): string;
}

declare class X86Instruction extends Instruction {
    /**
     * Array of objects describing each operand.
     */
    operands: X86Operand[];

    /**
     * Registers implicitly read by this instruction.
     */
    regsRead: X86Register[];

    /**
     * Registers implicitly written to by this instruction.
     */
    regsWritten: X86Register[];
}

declare class ArmInstruction extends Instruction {
    /**
     * Array of objects describing each operand.
     */
    operands: ArmOperand[];

    /**
     * Registers implicitly read by this instruction.
     */
    regsRead: ArmRegister[];

    /**
     * Registers implicitly written to by this instruction.
     */
    regsWritten: ArmRegister[];
}

declare class Arm64Instruction extends Instruction {
    /**
     * Array of objects describing each operand.
     */
    operands: Arm64Operand[];

    /**
     * Registers implicitly read by this instruction.
     */
    regsRead: Arm64Register[];

    /**
     * Registers implicitly written to by this instruction.
     */
    regsWritten: Arm64Register[];
}

declare class MipsInstruction extends Instruction {
    /**
     * Array of objects describing each operand.
     */
    operands: MipsOperand[];

    /**
     * Registers implicitly read by this instruction.
     */
    regsRead: MipsRegister[];

    /**
     * Registers implicitly written to by this instruction.
     */
    regsWritten: MipsRegister[];
}

declare type X86Operand = X86RegOperand | X86ImmOperand | X86MemOperand;

declare const enum X86OperandType {
    Reg = "reg",
    Imm = "imm",
    Mem = "mem",
}

declare interface X86BaseOperand {
    size: number;
}

declare interface X86RegOperand extends X86BaseOperand {
    type: X86OperandType.Reg;
    value: X86Register;
}

declare interface X86ImmOperand extends X86BaseOperand {
    type: X86OperandType.Imm;
    value: number | Int64;
}

declare interface X86MemOperand extends X86BaseOperand {
    type: X86OperandType.Mem;
    value: {
        segment?: X86Register;
        base?: X86Register;
        index?: X86Register;
        scale: number;
        disp: number;
    };
}

declare type ArmOperand = ArmRegOperand | ArmImmOperand | ArmMemOperand |
    ArmFpOperand | ArmCimmOperand | ArmPimmOperand | ArmSetendOperand |
    ArmSysregOperand;

declare const enum ArmOperandType {
    Reg = "reg",
    Imm = "imm",
    Mem = "mem",
    Fp = "fp",
    Cimm = "cimm",
    Pimm = "pimm",
    Setend = "setend",
    Sysreg = "sysreg",
}

declare interface ArmBaseOperand {
    shift?: {
        type: ArmShifter;
        value: number;
    };
    vectorIndex?: number;
    subtracted: boolean;
}

declare interface ArmRegOperand extends ArmBaseOperand {
    type: ArmOperandType.Reg;
    value: ArmRegister;
}

declare interface ArmImmOperand extends ArmBaseOperand {
    type: ArmOperandType.Imm;
    value: number;
}

declare interface ArmMemOperand extends ArmBaseOperand {
    type: ArmOperandType.Mem;
    value: {
        base?: ArmRegister;
        index?: ArmRegister;
        scale: number;
        disp: number;
    };
}

declare interface ArmFpOperand extends ArmBaseOperand {
    type: ArmOperandType.Fp;
    value: number;
}

declare interface ArmCimmOperand extends ArmBaseOperand {
    type: ArmOperandType.Cimm;
    value: number;
}

declare interface ArmPimmOperand extends ArmBaseOperand {
    type: ArmOperandType.Pimm;
    value: number;
}

declare interface ArmSetendOperand extends ArmBaseOperand {
    type: ArmOperandType.Setend;
    value: Endian;
}

declare interface ArmSysregOperand extends ArmBaseOperand {
    type: ArmOperandType.Sysreg;
    value: ArmRegister;
}

declare const enum ArmShifter {
    Asr = "asr",
    Lsl = "lsl",
    Lsr = "lsr",
    Ror = "ror",
    Rrx = "rrx",
    AsrReg = "asr-reg",
    LslReg = "lsl-reg",
    LsrReg = "lsr-reg",
    RorReg = "ror-reg",
    RrxReg = "rrx-reg",
}

declare type Arm64Operand = Arm64RegOperand | Arm64ImmOperand | Arm64MemOperand |
    Arm64FpOperand | Arm64CimmOperand | Arm64RegMrsOperand | Arm64RegMsrOperand |
    Arm64PstateOperand | Arm64SysOperand | Arm64PrefetchOperand | Arm64BarrierOperand;

declare const enum Arm64OperandType {
    Reg = "reg",
    Imm = "imm",
    Mem = "mem",
    Fp = "fp",
    Cimm = "cimm",
    RegMrs = "reg-mrs",
    RegMsr = "reg-msr",
    Pstate = "pstate",
    Sys = "sys",
    Prefetch = "prefetch",
    Barrier = "barrier",
}

declare interface Arm64BaseOperand {
    shift?: {
        type: Arm64Shifter;
        value: number;
    };
    ext?: Arm64Extender;
    vas?: Arm64Vas;
    vectorIndex?: number;
}

declare interface Arm64RegOperand extends Arm64BaseOperand {
    type: Arm64OperandType.Reg;
    value: Arm64Register;
}

declare interface Arm64ImmOperand extends Arm64BaseOperand {
    type: Arm64OperandType.Imm;
    value: Int64;
}

declare interface Arm64MemOperand extends Arm64BaseOperand {
    type: Arm64OperandType.Mem;
    value: {
        base?: Arm64Register;
        index?: Arm64Register;
        disp: number;
    };
}

declare interface Arm64FpOperand extends Arm64BaseOperand {
    type: Arm64OperandType.Fp;
    value: number;
}

declare interface Arm64CimmOperand extends Arm64BaseOperand {
    type: Arm64OperandType.Cimm;
    value: Int64;
}

declare interface Arm64RegMrsOperand extends Arm64BaseOperand {
    type: Arm64OperandType.RegMrs;
    value: Arm64Register;
}

declare interface Arm64RegMsrOperand extends Arm64BaseOperand {
    type: Arm64OperandType.RegMsr;
    value: Arm64Register;
}

declare interface Arm64PstateOperand extends Arm64BaseOperand {
    type: Arm64OperandType.Pstate;
    value: number;
}

declare interface Arm64SysOperand extends Arm64BaseOperand {
    type: Arm64OperandType.Sys;
    value: number;
}

declare interface Arm64PrefetchOperand extends Arm64BaseOperand {
    type: Arm64OperandType.Prefetch;
    value: number;
}

declare interface Arm64BarrierOperand extends Arm64BaseOperand {
    type: Arm64OperandType.Barrier;
    value: number;
}

declare const enum Arm64Shifter {
    Lsl = "lsl",
    Msl = "msl",
    Lsr = "lsr",
    Asr = "asr",
    Ror = "ror",
}

declare const enum Arm64Extender {
    Uxtb = "uxtb",
    Uxth = "uxth",
    Uxtw = "uxtw",
    Uxtx = "uxtx",
    Sxtb = "sxtb",
    Sxth = "sxth",
    Sxtw = "sxtw",
    Sxtx = "sxtx",
}

declare const enum Arm64Vas {
    A8b = "8b",
    A16b = "16b",
    A4h = "4h",
    A8h = "8h",
    A2s = "2s",
    A4s = "4s",
    A1d = "1d",
    A2d = "2d",
    A1q = "1q",
}

declare type MipsOperand = MipsRegOperand | MipsImmOperand | MipsMemOperand;

declare const enum MipsOperandType {
    Reg = "reg",
    Imm = "imm",
    Mem = "mem",
}

declare interface MipsRegOperand {
    type: MipsOperandType.Reg;
    value: MipsRegister;
}

declare interface MipsImmOperand {
    type: MipsOperandType.Imm;
    value: number;
}

declare interface MipsMemOperand {
    type: MipsOperandType.Mem;
    value: {
        base?: MipsRegister;
        disp: number;
    };
}

declare const enum Endian {
    Big = "be",
    Little = "le",
}

declare namespace Kernel {
    /**
     * Whether the Kernel API is available.
     */
    const available: boolean;

    /**
     * Base address of the kernel. Can be overridden with any non-zero UInt64.
     */
    let base: UInt64;

    /**
     * Size of kernel page in bytes.
     */
    const pageSize: number;

    /**
     * Enumerates kernel modules loaded right now.
     */
    function enumerateModules(): KernelModuleDetails[];

    /**
      * Enumerates all kernel memory ranges matching `specifier`.
      *
      * @param specifier The kind of ranges to include.
      */
    function enumerateRanges(specifier: PageProtection | EnumerateRangesSpecifier): KernelRangeDetails[];

    /**
     * Enumerates all ranges of a kernel module.
     *
     * @param name Name of the module, or `null` for the module of the kernel itself.
     * @param protection Include ranges with at least this protection.
     */
    function enumerateModuleRanges(name: string | null, protection: PageProtection): KernelModuleRangeDetails[];

    /**
     * Allocates kernel memory.
     *
     * @param size Size of the allocation in bytes (will be rounded up to a multiple of the kernel's page size).
     */
    function alloc(size: number | UInt64): UInt64;

    /**
     * Changes the page protection on a region of kernel memory.
     *
     * @param address Starting address.
     * @param size Number of bytes. Must be a multiple of Process#pageSize.
     * @param protection Desired page protection.
     */
    function protect(address: UInt64, size: number | UInt64, protection: PageProtection): boolean;

    /**
     * Scans kernel memory for occurences of `pattern` in the memory range given by `address` and `size`.
     *
     * @param address Starting address to scan from.
     * @param size Number of bytes to scan.
     * @param pattern Match pattern of the form “13 37 ?? ff” to match 0x13 followed by 0x37 followed by any byte
     *                followed by 0xff. For more advanced matching it is also possible to specify an r2-style mask.
     *                The mask is bitwise AND-ed against both the needle and the haystack. To specify the mask append
     *                a `:` character after the needle, followed by the mask using the same syntax.
     *                For example: “13 37 13 37 : 1f ff ff f1”.
     *                For convenience it is also possible to specify nibble-level wildcards, like “?3 37 13 ?7”,
     *                which gets translated into masks behind the scenes.
     * @param callbacks Object with callbacks.
     */
    function scan(address: UInt64, size: number | UInt64, pattern: string, callbacks: KernelMemoryScanCallbacks): void;

    /**
     * Synchronous version of `scan()`.
     *
     * @param address Starting address to scan from.
     * @param size Number of bytes to scan.
     * @param pattern Match pattern, see `Memory.scan()` for details.
     */
    function scanSync(address: UInt64, size: number | UInt64, pattern: string): KernelMemoryScanMatch[];

    function readS8(address: UInt64): number;
    function readU8(address: UInt64): number;
    function readS16(address: UInt64): number;
    function readU16(address: UInt64): number;
    function readS32(address: UInt64): number;
    function readU32(address: UInt64): number;
    function readS64(address: UInt64): Int64;
    function readU64(address: UInt64): UInt64;
    function readShort(address: UInt64): number;
    function readUShort(address: UInt64): number;
    function readInt(address: UInt64): number;
    function readUInt(address: UInt64): number;
    function readLong(address: UInt64): number | Int64;
    function readULong(address: UInt64): number | UInt64;
    function readFloat(address: UInt64): number;
    function readDouble(address: UInt64): number;
    function readByteArray(address: UInt64, length: number): ArrayBuffer | null;
    function readCString(address: UInt64, size: number): string | null;
    function readUtf8String(address: UInt64, size: number): string | null;
    function readUtf16String(address: UInt64, length: number): string | null;

    function writeS8(address: UInt64, value: number | Int64): void;
    function writeU8(address: UInt64, value: number | UInt64): void;
    function writeS16(address: UInt64, value: number | Int64): void;
    function writeU16(address: UInt64, value: number | UInt64): void;
    function writeS32(address: UInt64, value: number | Int64): void;
    function writeU32(address: UInt64, value: number | UInt64): void;
    function writeS64(address: UInt64, value: number | Int64): void;
    function writeU64(address: UInt64, value: number | UInt64): void;
    function writeShort(address: UInt64, value: number | Int64): void;
    function writeUShort(address: UInt64, value: number | UInt64): void;
    function writeInt(address: UInt64, value: number | Int64): void;
    function writeUInt(address: UInt64, value: number | UInt64): void;
    function writeLong(address: UInt64, value: number | Int64): void;
    function writeULong(address: UInt64, value: number | UInt64): void;
    function writeFloat(address: UInt64, value: number): void;
    function writeDouble(address: UInt64, value: number): void;
    function writeByteArray(address: UInt64, value: ArrayBuffer | number[]): void;
    function writeUtf8String(address: UInt64, value: string): void;
    function writeUtf16String(address: UInt64, value: string): void;
}

declare class ApiResolver {
    constructor(type: string);
    enumerateMatches(query: any): any;
}
declare class DebugSymbolValue {
    constructor();
    toString(): any;
}
declare class File {
    constructor(filePath: string, mode: string);
    close(): void;
    flush(): void;
    write(data: string | ArrayBuffer): void;
}
declare class SourceMap {
    constructor();
    resolve(generatedPosition: any): any;
}
declare function UnixInputStream(): any;
declare function UnixOutputStream(): any;
declare namespace DebugSymbol {
    function findFunctionsMatching(pattern: string): any;
    function findFunctionsNamed(name: string): any;
    function fromAddress(address: NativePointerValue): any;
    function fromName(name: string): any;
    function getFunctionByName(name: string): any;
}
declare namespace MemoryAccessMonitor {
    function disable(): any;
    function enable(): any;
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

declare interface StalkerOptions {
    events?: {
        call?: boolean;
        ret?: boolean;
        exec?: boolean;
        block?: boolean;
        compile?: boolean;
    }
    onReceive?: (events: any) => void;
    onCallSummary?: (summary: any) => void;
}

declare interface StalkerParseOptions {
    annotate?: boolean;
    stringify?: boolean;
}

declare type CallProbeId = number;

declare namespace Stalker {
    const queueCapacity: number;
    const queueDrainInterval: number;
    const trustThreshold: number;
    function addCallProbe(address: NativePointerValue, callback: InvocationListenerCallbacks): CallProbeId;
    function follow(threadId?: ThreadId, options?: StalkerOptions): any;
    function garbageCollect(): any;
    function removeCallProbe(callbackId: CallProbeId): any;
    function flush(): void;
    function parse(events: any, options: StalkerParseOptions): any;
    function unfollow(threadId?: ThreadId): any;
}

declare namespace ObjC {
    /**
     * Whether the current process has an Objective-C runtime loaded. Do not invoke any other ObjC properties or
     * methods unless this is the case.
     */
    const available: boolean;

    /**
     * Direct access to a big portion of the Objective-C runtime API.
     */
    const api: {
        [name: string]: any;
    };

    /**
     * Dynamically generated bindings for each of the currently registered classes.
     *
     * You can interact with objects by using dot notation and replacing colons with underscores, i.e.:
     *
     * ```
     *     [NSString stringWithString:@"Hello World"];
     * ```
     *
     * becomes:
     *
     * ```
     *     const NSString = ObjC.classes.NSString;
     *     NSString.stringWithString_("Hello World");
     * ```
     *
     * Note the underscore after the method name.
     */
    const classes: {
        [name: string]: ObjC.Object
    };

    /**
     * Dynamically generated bindings for each of the currently registered protocols.
     */
    const protocols: {
        [name: string]: ObjC.Protocol
    };

    /**
     * GCD queue of the main thread.
     */
    const mainQueue: NativePointer;

    /**
     * Schedule the JavaScript function `work` on the GCD queue specified by `queue`. An NSAutoreleasePool is created
     * just before calling `work`, and cleaned up on return.
     *
     * E.g. on macOS:
     * ```
     *     const { NSSound } = ObjC.classes;
     *     ObjC.schedule(ObjC.mainQueue, () => {
     *         const sound = NSSound.alloc().initWithContentsOfFile_byReference_("/Users/oleavr/.Trash/test.mp3", true).autorelease();
     *         sound.play();
     *     });
     * ```
     *
     * @param queue GCD queue to schedule `work` on.
     * @param work Function to call on the specified `queue`.
     */
    function schedule(queue: NativePointerValue, work: () => void): void;

    /**
     * Dynamically generated wrapper for any Objective-C instance, class, or meta-class.
     */
    class Object implements ObjectWrapper, ObjC.ObjectMethods {
        constructor(handle: NativePointer, protocol?: ObjC.Protocol);

        handle: NativePointer;

        /**
         * Whether this is an instance, class, or meta-class.
         */
        $kind: ObjectKind;

        /**
         * Instance used for chaining up to super-class method implementations.
         */
        $super: ObjC.Object;

        /**
         * Super-class of this object's class.
         */
        $superClass: ObjC.Object;

        /**
         * Class that this object is an instance of.
         */
        $class: ObjC.Object;

        /**
         * Class name of this object.
         */
        $className: string;

        /**
         * Protocols that this object conforms to.
         */
        $protocols: {
            [name: string]: ObjC.Protocol
        };

        /**
         * Native method names exposed by this object’s class and parent classes.
         */
        $methods: string[];

        /**
         * Native method names exposed by this object’s class, not including parent classes.
         */
        $ownMethods: string[];

        /**
         * Instance variables on this object. Supports both access and assignment.
         */
        $ivars: {
            [name: string]: any;
        };

        /**
         * Determines whether two instances refer to the same underlying object.
         *
         * @param other Other object instance or address to compare to.
         */
        equals(other: ObjC.Object | NativePointer): boolean;

        [name: string]: any;
    }

    interface ObjectMethods {
        [name: string]: ObjectMethod;
    }

    class ObjectMethod implements ObjectWrapper {
        handle: NativePointer;

        /**
         * Objective-C selector. Use `ObjC.selectorAsString()` to convert it to a string.
         */
        selector: NativePointer;

        /**
         * Current implementation.
         *
         * You may replace it by assigning to this property. See `ObjC.implement()` for details.
         */
        implementation: Function | NativePointer;

        /**
         * Return type name.
         */
        returnType: string;

        /**
         * Argument type names.
         */
        argumentTypes: string;

        /**
         * Signature.
         */
        types: string;
    }

    /**
     * What kind of object an ObjC.Object represents.
     */
    const enum ObjectKind {
        Instance = "instance",
        Class = "class",
        MetaClass = "meta-class"
    }

    /**
     * Dynamically generated language binding for any Objective-C protocol.
     */
    class Protocol implements ObjectWrapper {
        constructor(handle: NativePointer);

        handle: NativePointer;

        /**
         * Name visible to the Objective-C runtime.
         */
        name: string;

        /**
         * Protocols that this protocol conforms to.
         */
        protocols: {
            [name: string]: ObjC.Protocol
        };

        /**
         * Properties declared by this protocol.
         */
        properties: {
            [name: string]: ProtocolPropertyAttributes;
        };

        /**
         * Methods declared by this protocol.
         */
        methods: {
            [name: string]: ProtocolMethodDescription;
        };
    }

    interface ProtocolPropertyAttributes {
        [name: string]: string;
    }

    interface ProtocolMethodDescription {
        /**
         * Whether this method is required or optional.
         */
        required: boolean;

        /**
         * Method signature.
         */
        types: string;
    }

    /**
     * Dynamically generated language binding for any Objective-C block. Also supports implementing a block from
     * scratch by passing in a MethodDefinition.
     */
    class Block implements ObjectWrapper {
        constructor(target: NativePointer | MethodSpec);

        handle: NativePointer;

        /**
         * Current implementation. You may replace it by assigning to this property.
         */
        implementation: AnyFunction;
    }

    /**
     * Creates a JavaScript implementation compatible with the signature of `method`, where `fn` is used as the
     * implementation. Returns a `NativeCallback` that you may assign to an ObjC method’s `implementation` property.
     *
     * @param method Method to implement.
     * @param fn Implementation.
     */
    function implement(method: ObjectMethod, fn: AnyFunction): NativeCallback;

    /**
     * Creates a new class designed to act as a proxy for a target object.
     *
     * @param spec Proxy specification.
     */
    function registerProxy(spec: ProxySpec): ProxyConstructor;

    /**
     * Creates a new Objective-C class.
     *
     * @param spec Class specification.
     */
    function registerClass(spec: ClassSpec): ObjC.Object;

    /**
     * Creates a new Objective-C protocol.
     *
     * @param spec Protocol specification.
     */
    function registerProtocol(spec: ProtocolSpec): ObjC.Protocol;

    /**
     * Binds some JavaScript data to an Objective-C instance.
     *
     * @param obj Objective-C instance to bind data to.
     * @param data Data to bind.
     */
    function bind(obj: ObjC.Object | NativePointer, data: InstanceData): void;

    /**
     * Unbinds previously associated JavaScript data from an Objective-C instance.
     *
     * @param obj Objective-C instance to unbind data from.
     */
    function unbind(obj: ObjC.Object | NativePointer): void;

    /**
     * Looks up previously bound data from an Objective-C object.
     *
     * @param obj Objective-C instance to look up data for.
     */
    function getBoundData(obj: ObjC.Object | NativePointer): any;

    /**
     * Enumerates loaded classes.
     *
     * @param callbacks Object with callbacks.
     */
    function enumerateLoadedClasses(callbacks: EnumerateLoadedClassesCallbacks): void;

    /**
     * Enumerates loaded classes.
     *
     * @param options Options customizing the enumeration.
     * @param callbacks Object with callbacks.
     */
    function enumerateLoadedClasses(options: EnumerateLoadedClassesOptions, callbacks: EnumerateLoadedClassesCallbacks): void;

    /**
     * Synchronous version of `enumerateLoadedClasses()`.
     *
     * @param options Options customizing the enumeration.
     */
    function enumerateLoadedClassesSync(options?: EnumerateLoadedClassesOptions): EnumerateLoadedClassesResult;

    interface EnumerateLoadedClassesOptions {
        /**
         * Limit enumeration to modules in the given module map.
         */
        ownedBy?: ModuleMap;
    }

    interface EnumerateLoadedClassesCallbacks {
        onMatch: (name: string, owner: string) => void;
        onComplete: () => void;
    }

    interface EnumerateLoadedClassesResult {
        /**
         * Class names grouped by name of owner module.
         */
        [owner: string]: string[];
    }

    function choose(specifier: ChooseSpecifier, callbacks: EnumerateCallbacks<ObjC.Object>): void;

    /**
     * Synchronous version of `choose()`.
     *
     * @param specifier What kind of objects to look for.
     */
    function chooseSync(specifier: ChooseSpecifier): ObjC.Object[];

    /**
     * Converts the JavaScript string `name` to a selector.
     *
     * @param name Name to turn into a selector.
     */
    function selector(name: string): NativePointer;

    /**
     * Converts the selector `sel` to a JavaScript string.
     *
     * @param sel Selector to turn into a string.
     */
    function selectorAsString(sel: NativePointerValue): string;

    interface ProxySpec {
        /**
         * Protocols this proxy class conforms to.
         */
        protocols?: ObjC.Protocol[];

        /**
         * Methods to implement.
         */
        methods?: {
            [name: string]: AnyFunction | MethodSpec;
        };

        /**
         * Callbacks for getting notified about events.
         */
        events?: {
            /**
             * Gets notified about the method name that we’re about to forward a call to. This might be where you’d
             * start out with a temporary callback that just logs the names to help you decide which methods to
             * override.
             *
             * @param name Name of method that is about to get called.
             */
            forward?(name: string): void;
        }
    }

    /**
     * Constructor for instantiating a proxy object.
     *
     * @param target Target object to proxy to.
     * @param data Object with arbitrary data.
     */
    type ProxyConstructor = (target: ObjC.Object | NativePointer, data: InstanceData) => void;

    interface ClassSpec {
        /**
         * Name of the class.
         *
         * Omit this if you don’t care about the globally visible name and would like the runtime to auto-generate one
         * for you.
         */
        name?: string;

        /**
         * Super-class, or `null` to create a new root class. Omit to inherit from `NSObject`.
         */
        super?: ObjC.Object | null;

        /**
         * Protocols this class conforms to.
         */
        protocols?: ObjC.Protocol[];

        /**
         * Methods to implement.
         */
        methods?: {
            [name: string]: AnyFunction | MethodSpec;
        };
    }

    type MethodSpec = SimpleMethodSpec | DetailedMethodSpec;

    interface SimpleMethodSpec {
        /**
         * Return type.
         */
        retType: string;

        /**
         * Argument types.
         */
        argTypes: string[];

        /**
         * Implementation.
         */
        implementation: AnyFunction;
    }

    interface DetailedMethodSpec {
        /**
         * Signature.
         */
        types: string;

        /**
         * Implementation.
         */
        implementation: AnyFunction;
    }

    /**
     * User-defined data that can be accessed from method implementations.
     */
    interface InstanceData {
        [name: string]: any;
    }

    interface ProtocolSpec {
        /**
         * Name of the protocol.
         *
         * Omit this if you don’t care about the globally visible name and would like the runtime to auto-generate one
         * for you.
         */
        name?: string;

        /**
         * Protocols this protocol conforms to.
         */
        protocols?: ObjC.Protocol[];

        methods?: {
            [name: string]: ProtocolMethodSpec;
        };
    }

    type ProtocolMethodSpec = SimpleProtocolMethodSpec | DetailedProtocolMethodSpec;

    interface SimpleProtocolMethodSpec {
        /**
         * Return type.
         */
        retType: string;

        /**
         * Argument types.
         */
        argTypes: string[];

        /**
         * Whether this method is required or optional. Default is required.
         */
        optional?: boolean;
    }

    interface DetailedProtocolMethodSpec {
        /**
         * Method signature.
         */
        types: string;

        /**
         * Whether this method is required or optional. Default is required.
         */
        optional?: boolean;
    }

    type ChooseSpecifier = SimpleChooseSpecifier | DetailedChooseSpecifier;

    type SimpleChooseSpecifier = ObjC.Object;

    interface DetailedChooseSpecifier {
        /**
         * Which class to look for instances of. E.g.: `ObjC.classes.UIButton`.
         */
        class: ObjC.Object;

        /**
         * Whether you’re also interested in subclasses matching the given class selector.
         *
         * The default is to also include subclasses.
         */
        subclasses?: boolean;
    }
}

declare namespace Java {
    /**
     * Whether the current process has a Java runtime loaded. Do not invoke any other Java properties or
     * methods unless this is the case.
     */
    const available: boolean;

    const androidVersion: string;

    const vm: any;

    const classFactory: any;

    function synchronized(obj: any, fn: () => void): void;

    function enumerateLoadedClasses(callbacks: any): void;
    function enumerateLoadedClassesSync(): string[];

    function enumerateClassLoaders(callbacks: any): void;
    function enumerateClassLoadersSync(): any[];

    function scheduleOnMainThread(fn: () => void): void;

    function perform(fn: () => void): void;
    function performNow(fn: () => void): void;

    function use(className: string): any;

    function openClassFile(filePath: string): any;

    function choose(className: string, callbacks: any): void;

    function cast(obj: any, C: any): any;

    function array(type: string, elements: any[]): any;

    function isMainThread(): boolean;

    function registerClass(spec: any): any;

    function deoptimizeEverything(): void;
}

declare namespace WeakRef {
    function bind(): any;
    function unbind(): any;
}

declare class SQliteStatement {
    bindInteger(index: number, value: number): void;
    bindFloat(index: number, value: number): void;
    bindText(index: number, value: string): void;
    bindBlob(index: number, bytes: ArrayBuffer): void;
    bindNull(index: number): void;
    step(): any[] | null;
    reset(): void;
}

declare namespace SqliteDatabase {
    class Database {
        close(): void;
        exec(sql: string): void;
        prepare(sql: string): SQliteStatement;
        dump(): ArrayBuffer;
    }

    function open(path: string): Database;
    function openInline(encodedContents: ArrayBuffer): Database;
}

/**
 * Generates machine code for x86.
 */
declare class X86Writer {
    /**
     * Creates a new code writer for generating x86 machine code
     * written directly to memory at `codeAddress`.
     *
     * @param codeAddress Memory address to write generated code to.
     * @param options Options for customizing code generation.
     */
    constructor(codeAddress: NativePointerValue, options?: X86WriterOptions);

    /**
     * Recycles instance.
     */
    reset(codeAddress: NativePointerValue, options?: X86WriterOptions): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Resolves label references and writes pending data to memory. You
     * should always call this once you've finished generating code. It
     * is usually also desirable to do this between pieces of unrelated
     * code, e.g. when generating multiple functions in one go.
     */
    flush(): void;

    /**
     * Memory location of the first byte of output.
     */
    base: NativePointer;

    /**
     * Memory location of the next byte of output.
     */
    code: NativePointer;

    /**
     * Program counter at the next byte of output.
     */
    pc: NativePointer;

    /**
     * Current offset in bytes.
     */
    offset: number;

    /**
     * Puts a label at the current position, where `id` is an identifier
     * that may be referenced in past and future `put*Label()` calls.
     */
    putLabel(id: string): void;

    /**
     * Puts code needed for calling a C function with the specified `args`.
     */
    putCallAddressWithArguments(func: NativePointerValue, args: X86CallArgument[]): void;

    /**
     * Like `putCallWithArguments()`, but also
     * ensures that the argument list is aligned on a 16 byte boundary.
     */
    putCallAddressWithAlignedArguments(func: NativePointerValue, args: X86CallArgument[]): void;

    /**
     * Puts code needed for calling a C function with the specified `args`.
     */
    putCallRegWithArguments(reg: X86Register, args: X86CallArgument[]): void;

    /**
     * Like `putCallWithArguments()`, but also
     * ensures that the argument list is aligned on a 16 byte boundary.
     */
    putCallRegWithAlignedArguments(reg: X86Register, args: X86CallArgument[]): void;

    /**
     * Puts code needed for calling a C function with the specified `args`.
     */
    putCallRegOffsetPtrWithArguments(reg: X86Register, offset: number | Int64 | UInt64, args: X86CallArgument[]): void;

    /**
     * Puts a CALL instruction.
     */
    putCallAddress(address: NativePointerValue): void;

    /**
     * Puts a CALL instruction.
     */
    putCallReg(reg: X86Register): void;

    /**
     * Puts a CALL instruction.
     */
    putCallRegOffsetPtr(reg: X86Register, offset: number | Int64 | UInt64): void;

    /**
     * Puts a CALL instruction.
     */
    putCallIndirect(addr: NativePointerValue): void;

    /**
     * Puts a CALL instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putCallIndirectLabel(labelId: string): void;

    /**
     * Puts a CALL instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putCallNearLabel(labelId: string): void;

    /**
     * Puts a LEAVE instruction.
     */
    putLeave(): void;

    /**
     * Puts a RET instruction.
     */
    putRet(): void;

    /**
     * Puts a RET instruction.
     */
    putRetImm(immValue: number): void;

    /**
     * Puts a JMP instruction.
     */
    putJmpAddress(address: NativePointerValue): void;

    /**
     * Puts a JMP instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putJmpShortLabel(labelId: string): void;

    /**
     * Puts a JMP instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putJmpNearLabel(labelId: string): void;

    /**
     * Puts a JMP instruction.
     */
    putJmpReg(reg: X86Register): void;

    /**
     * Puts a JMP instruction.
     */
    putJmpRegPtr(reg: X86Register): void;

    /**
     * Puts a JMP instruction.
     */
    putJmpRegOffsetPtr(reg: X86Register, offset: number | Int64 | UInt64): void;

    /**
     * Puts a JMP instruction.
     */
    putJmpNearPtr(address: NativePointerValue): void;

    /**
     * Puts a JCC instruction.
     */
    putJccShort(instructionId: X86InstructionId, target: NativePointerValue, hint: X86BranchHint): void;

    /**
     * Puts a JCC instruction.
     */
    putJccNear(instructionId: X86InstructionId, target: NativePointerValue, hint: X86BranchHint): void;

    /**
     * Puts a JCC instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putJccShortLabel(instructionId: X86InstructionId, labelId: string, hint: X86BranchHint): void;

    /**
     * Puts a JCC instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putJccNearLabel(instructionId: X86InstructionId, labelId: string, hint: X86BranchHint): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegImm(reg: X86Register, immValue: number | Int64 | UInt64): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegReg(dstReg: X86Register, srcReg: X86Register): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegNearPtr(dstReg: X86Register, srcAddress: NativePointerValue): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegImm(reg: X86Register, immValue: number | Int64 | UInt64): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegReg(dstReg: X86Register, srcReg: X86Register): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegNearPtr(dstReg: X86Register, srcAddress: NativePointerValue): void;

    /**
     * Puts an INC instruction.
     */
    putIncReg(reg: X86Register): void;

    /**
     * Puts a DEC instruction.
     */
    putDecReg(reg: X86Register): void;

    /**
     * Puts an INC instruction.
     */
    putIncRegPtr(target: X86PointerTarget, reg: X86Register): void;

    /**
     * Puts a DEC instruction.
     */
    putDecRegPtr(target: X86PointerTarget, reg: X86Register): void;

    /**
     * Puts a LOCK XADD instruction.
     */
    putLockXaddRegPtrReg(dstReg: X86Register, srcReg: X86Register): void;

    /**
     * Puts a LOCK CMPXCHG instruction.
     */
    putLockCmpxchgRegPtrReg(dstReg: X86Register, srcReg: X86Register): void;

    /**
     * Puts a LOCK INC IMM32 instruction.
     */
    putLockIncImm32Ptr(target: NativePointerValue): void;

    /**
     * Puts a LOCK DEC IMM32 instruction.
     */
    putLockDecImm32Ptr(target: NativePointerValue): void;

    /**
     * Puts an AND instruction.
     */
    putAndRegReg(dstReg: X86Register, srcReg: X86Register): void;

    /**
     * Puts an AND instruction.
     */
    putAndRegU32(reg: X86Register, immValue: number): void;

    /**
     * Puts a SHL instruction.
     */
    putShlRegU8(reg: X86Register, immValue: number): void;

    /**
     * Puts a SHR instruction.
     */
    putShrRegU8(reg: X86Register, immValue: number): void;

    /**
     * Puts an XOR instruction.
     */
    putXorRegReg(dstReg: X86Register, srcReg: X86Register): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegReg(dstReg: X86Register, srcReg: X86Register): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegU32(dstReg: X86Register, immValue: number): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegU64(dstReg: X86Register, immValue: number | UInt64): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegAddress(dstReg: X86Register, address: NativePointerValue): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegPtrU32(dstReg: X86Register, immValue: number): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegOffsetPtrU32(dstReg: X86Register, dstOffset: number | Int64 | UInt64, immValue: number): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegPtrReg(dstReg: X86Register, srcReg: X86Register): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegOffsetPtrReg(dstReg: X86Register, dstOffset: number | Int64 | UInt64, srcReg: X86Register): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegRegPtr(dstReg: X86Register, srcReg: X86Register): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegRegOffsetPtr(dstReg: X86Register, srcReg: X86Register, srcOffset: number | Int64 | UInt64): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegBaseIndexScaleOffsetPtr(dstReg: X86Register, baseReg: X86Register, indexReg: X86Register, scale: number, offset: number | Int64 | UInt64): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegNearPtr(dstReg: X86Register, srcAddress: NativePointerValue): void;

    /**
     * Puts a MOV instruction.
     */
    putMovNearPtrReg(dstAddress: NativePointerValue, srcReg: X86Register): void;

    /**
     * Puts a MOV FS instruction.
     */
    putMovFsU32PtrReg(fsOffset: number, srcReg: X86Register): void;

    /**
     * Puts a MOV FS instruction.
     */
    putMovRegFsU32Ptr(dstReg: X86Register, fsOffset: number): void;

    /**
     * Puts a MOV GS instruction.
     */
    putMovGsU32PtrReg(fsOffset: number, srcReg: X86Register): void;

    /**
     * Puts a MOV GS instruction.
     */
    putMovRegGsU32Ptr(dstReg: X86Register, fsOffset: number): void;

    /**
     * Puts a MOVQ XMM0 ESP instruction.
     */
    putMovqXmm0EspOffsetPtr(offset: number): void;

    /**
     * Puts a MOVQ EAX XMM0 instruction.
     */
    putMovqEaxOffsetPtrXmm0(offset: number): void;

    /**
     * Puts a MOVDQU XMM0 ESP instruction.
     */
    putMovdquXmm0EspOffsetPtr(offset: number): void;

    /**
     * Puts a MOVDQU EAX XMM0 instruction.
     */
    putMovdquEaxOffsetPtrXmm0(offset: number): void;

    /**
     * Puts a LEA instruction.
     */
    putLeaRegRegOffset(dstReg: X86Register, srcReg: X86Register, srcOffset: number | Int64 | UInt64): void;

    /**
     * Puts an XCHG instruction.
     */
    putXchgRegRegPtr(leftReg: X86Register, rightReg: X86Register): void;

    /**
     * Puts a PUSH instruction.
     */
    putPushU32(immValue: number): void;

    /**
     * Puts a PUSH instruction.
     */
    putPushNearPtr(address: NativePointerValue): void;

    /**
     * Puts a PUSH instruction.
     */
    putPushReg(reg: X86Register): void;

    /**
     * Puts a POP instruction.
     */
    putPopReg(reg: X86Register): void;

    /**
     * Puts a PUSH instruction.
     */
    putPushImmPtr(immPtr: NativePointerValue): void;

    /**
     * Puts a PUSHAX instruction.
     */
    putPushax(): void;

    /**
     * Puts a POPAX instruction.
     */
    putPopax(): void;

    /**
     * Puts a PUSHFX instruction.
     */
    putPushfx(): void;

    /**
     * Puts a POPFX instruction.
     */
    putPopfx(): void;

    /**
     * Puts a TEST instruction.
     */
    putTestRegReg(regA: X86Register, regB: X86Register): void;

    /**
     * Puts a TEST instruction.
     */
    putTestRegU32(reg: X86Register, immValue: number): void;

    /**
     * Puts a CMP instruction.
     */
    putCmpRegI32(reg: X86Register, immValue: number): void;

    /**
     * Puts a CMP instruction.
     */
    putCmpRegOffsetPtrReg(regA: X86Register, offset: number | Int64 | UInt64, regB: X86Register): void;

    /**
     * Puts a CMP instruction.
     */
    putCmpImmPtrImmU32(immPtr: NativePointerValue, immValue: number): void;

    /**
     * Puts a CMP instruction.
     */
    putCmpRegReg(regA: X86Register, regB: X86Register): void;

    /**
     * Puts a CLC instruction.
     */
    putClc(): void;

    /**
     * Puts a STC instruction.
     */
    putStc(): void;

    /**
     * Puts a CLD instruction.
     */
    putCld(): void;

    /**
     * Puts a STD instruction.
     */
    putStd(): void;

    /**
     * Puts a CPUID instruction.
     */
    putCpuid(): void;

    /**
     * Puts an LFENCE instruction.
     */
    putLfence(): void;

    /**
     * Puts an RDTSC instruction.
     */
    putRdtsc(): void;

    /**
     * Puts a PAUSE instruction.
     */
    putPause(): void;

    /**
     * Puts a NOP instruction.
     */
    putNop(): void;

    /**
     * Puts an OS/architecture-specific breakpoint instruction.
     */
    putBreakpoint(): void;

    /**
     * Puts `n` guard instruction.
     */
    putPadding(n: number): void;

    /**
     * Puts `n` NOP instructions.
     */
    putNopPadding(n: number): void;

    /**
     * Puts a uint8.
     */
    putU8(value: number): void;

    /**
     * Puts an int8.
     */
    putS8(value: number): void;

    /**
     * Puts raw data.
     */
    putBytes(data: ArrayBuffer | number[] | string): void;
}

declare interface X86WriterOptions {
    /**
     * Specifies the initial program counter, which is useful when
     * generating code to a scratch buffer. This is essential when using
     * `Memory.patchCode()` on iOS, which may provide you with a
     * temporary location that later gets mapped into memory at the
     * intended memory location.
     */
    pc?: NativePointer;
}

declare type X86CallArgument = X86Register | number | UInt64 | Int64 | NativePointerValue;

/**
 * Relocates machine code for x86.
 */
declare class X86Relocator {
    /**
     * Creates a new code relocator for copying x86 instructions
     * from one memory location to another, taking care to adjust
     * position-dependent instructions accordingly.
     *
     * @param inputCode Source address to copy instructions from.
     * @param output X86Writer pointed at the desired target memory
     *               address.
     */
    constructor(inputCode: NativePointerValue, output: X86Writer);

    /**
     * Recycles instance.
     */
    reset(inputCode: NativePointerValue, output: X86Writer): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Latest `Instruction` read so far. Starts out `null` and changes
     * on every call to `readOne()`.
     */
    input: Instruction | null;

    /**
     * Indicates whether end-of-block has been reached, i.e. we've
     * reached a branch of any kind, like CALL, JMP, BL, RET.
     */
    eob: boolean;

    /**
     * Indicates whether end-of-input has been reached, e.g. we've
     * reached JMP/B/RET, an instruction after which there may or may
     * not be valid code.
     */
    eoi: boolean;

    /**
     * Reads the next instruction into the relocator's internal buffer
     * and returns the number of bytes read so far, including previous
     * calls.
     *
     * You may keep calling this method to keep buffering, or immediately
     * call either `writeOne()` or `skipOne()`. Or, you can buffer up
     * until the desired point and then call `writeAll()`.
     *
     * Returns zero when end-of-input is reached, which means the `eoi`
     * property is now `true`.
     */
    readOne(): number;

    /**
     * Peeks at the next `Instruction` to be written or skipped.
     */
    peekNextWriteInsn(): Instruction | null;

    /**
     * Peeks at the address of the next instruction to be written or skipped.
     */
    peekNextWriteSource(): NativePointer;

    /**
     * Skips the instruction that would have been written next.
     */
    skipOne(): void;

    /**
     * Skips the instruction that would have been written next,
     * but without a label for internal use. This breaks relocation of branches to
     * locations inside the relocated range, and is an optimization for use-cases
     * where all branches are rewritten (e.g. Frida's Stalker).
     */
    skipOneNoLabel(): void;

    /**
     * write the next buffered instruction.
     */
    writeOne(): boolean;

    /**
     * write the next buffered instruction, but without a
     * label for internal use. This breaks relocation of branches to locations
     * inside the relocated range, and is an optimization for use-cases where all
     * branches are rewritten (e.g. Frida's Stalker).
     */
    writeOneNoLabel(): boolean;

    /**
     * Writes all buffered instructions.
     */
    writeAll(): void;
}

declare const enum X86Register {
    Xax = "xax",
    Xcx = "xcx",
    Xdx = "xdx",
    Xbx = "xbx",
    Xsp = "xsp",
    Xbp = "xbp",
    Xsi = "xsi",
    Xdi = "xdi",
    Eax = "eax",
    Ecx = "ecx",
    Edx = "edx",
    Ebx = "ebx",
    Esp = "esp",
    Ebp = "ebp",
    Esi = "esi",
    Edi = "edi",
    Rax = "rax",
    Rcx = "rcx",
    Rdx = "rdx",
    Rbx = "rbx",
    Rsp = "rsp",
    Rbp = "rbp",
    Rsi = "rsi",
    Rdi = "rdi",
    R8 = "r8",
    R9 = "r9",
    R10 = "r10",
    R11 = "r11",
    R12 = "r12",
    R13 = "r13",
    R14 = "r14",
    R15 = "r15",
    R8d = "r8d",
    R9d = "r9d",
    R10d = "r10d",
    R11d = "r11d",
    R12d = "r12d",
    R13d = "r13d",
    R14d = "r14d",
    R15d = "r15d",
    Xip = "xip",
    Eip = "eip",
    Rip = "rip",
}

declare const enum X86InstructionId {
    Jo = "jo",
    Jno = "jno",
    Jb = "jb",
    Jae = "jae",
    Je = "je",
    Jne = "jne",
    Jbe = "jbe",
    Ja = "ja",
    Js = "js",
    Jns = "jns",
    Jp = "jp",
    Jnp = "jnp",
    Jl = "jl",
    Jge = "jge",
    Jle = "jle",
    Jg = "jg",
    Jcxz = "jcxz",
    Jecxz = "jecxz",
    Jrcxz = "jrcxz",
}

declare const enum X86BranchHint {
    NoHint = "no-hint",
    Likely = "likely",
    Unlikely = "unlikely",
}

declare const enum X86PointerTarget {
    Byte = "byte",
    Dword = "dword",
    Qword = "qword",
}

/**
 * Generates machine code for arm.
 */
declare class ArmWriter {
    /**
     * Creates a new code writer for generating ARM machine code
     * written directly to memory at `codeAddress`.
     *
     * @param codeAddress Memory address to write generated code to.
     * @param options Options for customizing code generation.
     */
    constructor(codeAddress: NativePointerValue, options?: ArmWriterOptions);

    /**
     * Recycles instance.
     */
    reset(codeAddress: NativePointerValue, options?: ArmWriterOptions): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Resolves label references and writes pending data to memory. You
     * should always call this once you've finished generating code. It
     * is usually also desirable to do this between pieces of unrelated
     * code, e.g. when generating multiple functions in one go.
     */
    flush(): void;

    /**
     * Memory location of the first byte of output.
     */
    base: NativePointer;

    /**
     * Memory location of the next byte of output.
     */
    code: NativePointer;

    /**
     * Program counter at the next byte of output.
     */
    pc: NativePointer;

    /**
     * Current offset in bytes.
     */
    offset: number;

    /**
     * Skips `nBytes`.
     */
    skip(nBytes: number): void;

    /**
     * Puts a label at the current position, where `id` is an identifier
     * that may be referenced in past and future `put*Label()` calls.
     */
    putLabel(id: string): void;

    /**
     * Puts a B instruction.
     */
    putBImm(target: NativePointerValue): void;

    /**
     * Puts a BX instruction.
     */
    putBxReg(reg: ArmRegister): void;

    /**
     * Puts a B instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBLabel(labelId: string): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegAddress(reg: ArmRegister, address: NativePointerValue): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegU32(reg: ArmRegister, val: number): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegRegImm(dstReg: ArmRegister, srcReg: ArmRegister, immVal: number): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegRegImm(dstReg: ArmRegister, srcReg: ArmRegister, immVal: number): void;

    /**
     * Puts a NOP instruction.
     */
    putNop(): void;

    /**
     * Puts an OS/architecture-specific breakpoint instruction.
     */
    putBreakpoint(): void;

    /**
     * Puts a raw instruction.
     */
    putInstruction(insn: number): void;

    /**
     * Puts raw data.
     */
    putBytes(data: ArrayBuffer | number[] | string): void;
}

declare interface ArmWriterOptions {
    /**
     * Specifies the initial program counter, which is useful when
     * generating code to a scratch buffer. This is essential when using
     * `Memory.patchCode()` on iOS, which may provide you with a
     * temporary location that later gets mapped into memory at the
     * intended memory location.
     */
    pc?: NativePointer;
}

declare type ArmCallArgument = ArmRegister | number | UInt64 | Int64 | NativePointerValue;

/**
 * Relocates machine code for arm.
 */
declare class ArmRelocator {
    /**
     * Creates a new code relocator for copying ARM instructions
     * from one memory location to another, taking care to adjust
     * position-dependent instructions accordingly.
     *
     * @param inputCode Source address to copy instructions from.
     * @param output ArmWriter pointed at the desired target memory
     *               address.
     */
    constructor(inputCode: NativePointerValue, output: ArmWriter);

    /**
     * Recycles instance.
     */
    reset(inputCode: NativePointerValue, output: ArmWriter): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Latest `Instruction` read so far. Starts out `null` and changes
     * on every call to `readOne()`.
     */
    input: Instruction | null;

    /**
     * Indicates whether end-of-block has been reached, i.e. we've
     * reached a branch of any kind, like CALL, JMP, BL, RET.
     */
    eob: boolean;

    /**
     * Indicates whether end-of-input has been reached, e.g. we've
     * reached JMP/B/RET, an instruction after which there may or may
     * not be valid code.
     */
    eoi: boolean;

    /**
     * Reads the next instruction into the relocator's internal buffer
     * and returns the number of bytes read so far, including previous
     * calls.
     *
     * You may keep calling this method to keep buffering, or immediately
     * call either `writeOne()` or `skipOne()`. Or, you can buffer up
     * until the desired point and then call `writeAll()`.
     *
     * Returns zero when end-of-input is reached, which means the `eoi`
     * property is now `true`.
     */
    readOne(): number;

    /**
     * Peeks at the next `Instruction` to be written or skipped.
     */
    peekNextWriteInsn(): Instruction | null;

    /**
     * Peeks at the address of the next instruction to be written or skipped.
     */
    peekNextWriteSource(): NativePointer;

    /**
     * Skips the instruction that would have been written next.
     */
    skipOne(): void;

    /**
     * write the next buffered instruction.
     */
    writeOne(): boolean;

    /**
     * Writes all buffered instructions.
     */
    writeAll(): void;
}

/**
 * Generates machine code for arm.
 */
declare class ThumbWriter {
    /**
     * Creates a new code writer for generating ARM machine code
     * written directly to memory at `codeAddress`.
     *
     * @param codeAddress Memory address to write generated code to.
     * @param options Options for customizing code generation.
     */
    constructor(codeAddress: NativePointerValue, options?: ThumbWriterOptions);

    /**
     * Recycles instance.
     */
    reset(codeAddress: NativePointerValue, options?: ThumbWriterOptions): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Resolves label references and writes pending data to memory. You
     * should always call this once you've finished generating code. It
     * is usually also desirable to do this between pieces of unrelated
     * code, e.g. when generating multiple functions in one go.
     */
    flush(): void;

    /**
     * Memory location of the first byte of output.
     */
    base: NativePointer;

    /**
     * Memory location of the next byte of output.
     */
    code: NativePointer;

    /**
     * Program counter at the next byte of output.
     */
    pc: NativePointer;

    /**
     * Current offset in bytes.
     */
    offset: number;

    /**
     * Skips `nBytes`.
     */
    skip(nBytes: number): void;

    /**
     * Puts a label at the current position, where `id` is an identifier
     * that may be referenced in past and future `put*Label()` calls.
     */
    putLabel(id: string): void;

    /**
     * Puts code needed for calling a C function with the specified `args`.
     */
    putCallAddressWithArguments(func: NativePointerValue, args: ArmCallArgument[]): void;

    /**
     * Puts code needed for calling a C function with the specified `args`.
     */
    putCallRegWithArguments(reg: ArmRegister, args: ArmCallArgument[]): void;

    /**
     * Puts a B instruction.
     */
    putBImm(target: NativePointerValue): void;

    /**
     * Puts a B instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBLabel(labelId: string): void;

    /**
     * Puts a B WIDE instruction.
     */
    putBLabelWide(labelId: string): void;

    /**
     * Puts a BX instruction.
     */
    putBxReg(reg: ArmRegister): void;

    /**
     * Puts a BL instruction.
     */
    putBlImm(target: NativePointerValue): void;

    /**
     * Puts a BL instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBlLabel(labelId: string): void;

    /**
     * Puts a BLX instruction.
     */
    putBlxImm(target: NativePointerValue): void;

    /**
     * Puts a BLX instruction.
     */
    putBlxReg(reg: ArmRegister): void;

    /**
     * Puts a CMP instruction.
     */
    putCmpRegImm(reg: ArmRegister, immValue: number): void;

    /**
     * Puts a BEQ instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBeqLabel(labelId: string): void;

    /**
     * Puts a BNE instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBneLabel(labelId: string): void;

    /**
     * Puts a B COND instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBCondLabel(cc: ArmConditionCode, labelId: string): void;

    /**
     * Puts a B COND WIDE instruction.
     */
    putBCondLabelWide(cc: ArmConditionCode, labelId: string): void;

    /**
     * Puts a CBZ instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putCbzRegLabel(reg: ArmRegister, labelId: string): void;

    /**
     * Puts a CBNZ instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putCbnzRegLabel(reg: ArmRegister, labelId: string): void;

    /**
     * Puts a PUSH instruction with the specified registers.
     */
    putPushRegs(regs: ArmRegister[]): void;

    /**
     * Puts a POP instruction with the specified registers.
     */
    putPopRegs(regs: ArmRegister[]): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegAddress(reg: ArmRegister, address: NativePointerValue): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegU32(reg: ArmRegister, val: number): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegReg(dstReg: ArmRegister, srcReg: ArmRegister): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegRegOffset(dstReg: ArmRegister, srcReg: ArmRegister, srcOffset: number | Int64 | UInt64): void;

    /**
     * Puts a STR instruction.
     */
    putStrRegReg(srcReg: ArmRegister, dstReg: ArmRegister): void;

    /**
     * Puts a STR instruction.
     */
    putStrRegRegOffset(srcReg: ArmRegister, dstReg: ArmRegister, dstOffset: number | Int64 | UInt64): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegReg(dstReg: ArmRegister, srcReg: ArmRegister): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegU8(dstReg: ArmRegister, immValue: number): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegImm(dstReg: ArmRegister, immValue: number | Int64 | UInt64): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegReg(dstReg: ArmRegister, srcReg: ArmRegister): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegRegReg(dstReg: ArmRegister, leftReg: ArmRegister, rightReg: ArmRegister): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegRegImm(dstReg: ArmRegister, leftReg: ArmRegister, rightValue: number | Int64 | UInt64): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegImm(dstReg: ArmRegister, immValue: number | Int64 | UInt64): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegReg(dstReg: ArmRegister, srcReg: ArmRegister): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegRegReg(dstReg: ArmRegister, leftReg: ArmRegister, rightReg: ArmRegister): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegRegImm(dstReg: ArmRegister, leftReg: ArmRegister, rightValue: number | Int64 | UInt64): void;

    /**
     * Puts a MRS instruction.
     */
    putMrsRegReg(dstReg: ArmRegister, srcReg: ArmSystemRegister): void;

    /**
     * Puts a MSR instruction.
     */
    putMsrRegReg(dstReg: ArmSystemRegister, srcReg: ArmRegister): void;

    /**
     * Puts a NOP instruction.
     */
    putNop(): void;

    /**
     * Puts a BKPT instruction.
     */
    putBkptImm(imm: number): void;

    /**
     * Puts an OS/architecture-specific breakpoint instruction.
     */
    putBreakpoint(): void;

    /**
     * Puts a raw instruction.
     */
    putInstruction(insn: number): void;

    /**
     * Puts a raw Thumb-2 instruction.
     */
    putInstructionWide(upper: number, lower: number): void;

    /**
     * Puts raw data.
     */
    putBytes(data: ArrayBuffer | number[] | string): void;
}

declare interface ThumbWriterOptions {
    /**
     * Specifies the initial program counter, which is useful when
     * generating code to a scratch buffer. This is essential when using
     * `Memory.patchCode()` on iOS, which may provide you with a
     * temporary location that later gets mapped into memory at the
     * intended memory location.
     */
    pc?: NativePointer;
}

/**
 * Relocates machine code for arm.
 */
declare class ThumbRelocator {
    /**
     * Creates a new code relocator for copying ARM instructions
     * from one memory location to another, taking care to adjust
     * position-dependent instructions accordingly.
     *
     * @param inputCode Source address to copy instructions from.
     * @param output ThumbWriter pointed at the desired target memory
     *               address.
     */
    constructor(inputCode: NativePointerValue, output: ThumbWriter);

    /**
     * Recycles instance.
     */
    reset(inputCode: NativePointerValue, output: ThumbWriter): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Latest `Instruction` read so far. Starts out `null` and changes
     * on every call to `readOne()`.
     */
    input: Instruction | null;

    /**
     * Indicates whether end-of-block has been reached, i.e. we've
     * reached a branch of any kind, like CALL, JMP, BL, RET.
     */
    eob: boolean;

    /**
     * Indicates whether end-of-input has been reached, e.g. we've
     * reached JMP/B/RET, an instruction after which there may or may
     * not be valid code.
     */
    eoi: boolean;

    /**
     * Reads the next instruction into the relocator's internal buffer
     * and returns the number of bytes read so far, including previous
     * calls.
     *
     * You may keep calling this method to keep buffering, or immediately
     * call either `writeOne()` or `skipOne()`. Or, you can buffer up
     * until the desired point and then call `writeAll()`.
     *
     * Returns zero when end-of-input is reached, which means the `eoi`
     * property is now `true`.
     */
    readOne(): number;

    /**
     * Peeks at the next `Instruction` to be written or skipped.
     */
    peekNextWriteInsn(): Instruction | null;

    /**
     * Peeks at the address of the next instruction to be written or skipped.
     */
    peekNextWriteSource(): NativePointer;

    /**
     * Skips the instruction that would have been written next.
     */
    skipOne(): void;

    /**
     * write the next buffered instruction.
     */
    writeOne(): boolean;

    /**
     * Writes all buffered instructions.
     */
    writeAll(): void;
}

declare const enum ArmRegister {
    R0 = "r0",
    R1 = "r1",
    R2 = "r2",
    R3 = "r3",
    R4 = "r4",
    R5 = "r5",
    R6 = "r6",
    R7 = "r7",
    R8 = "r8",
    R9 = "r9",
    R10 = "r10",
    R11 = "r11",
    R12 = "r12",
    R13 = "r13",
    R14 = "r14",
    R15 = "r15",
    Sp = "sp",
    Lr = "lr",
    Sb = "sb",
    Sl = "sl",
    Fp = "fp",
    Ip = "ip",
    Pc = "pc",
}

declare const enum ArmSystemRegister {
    ApsrNzcvq = "apsr-nzcvq",
}

declare const enum ArmConditionCode {
    Eq = "eq",
    Ne = "ne",
    Hs = "hs",
    Lo = "lo",
    Mi = "mi",
    Pl = "pl",
    Vs = "vs",
    Vc = "vc",
    Hi = "hi",
    Ls = "ls",
    Ge = "ge",
    Lt = "lt",
    Gt = "gt",
    Le = "le",
    Al = "al",
}

/**
 * Generates machine code for arm64.
 */
declare class Arm64Writer {
    /**
     * Creates a new code writer for generating AArch64 machine code
     * written directly to memory at `codeAddress`.
     *
     * @param codeAddress Memory address to write generated code to.
     * @param options Options for customizing code generation.
     */
    constructor(codeAddress: NativePointerValue, options?: Arm64WriterOptions);

    /**
     * Recycles instance.
     */
    reset(codeAddress: NativePointerValue, options?: Arm64WriterOptions): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Resolves label references and writes pending data to memory. You
     * should always call this once you've finished generating code. It
     * is usually also desirable to do this between pieces of unrelated
     * code, e.g. when generating multiple functions in one go.
     */
    flush(): void;

    /**
     * Memory location of the first byte of output.
     */
    base: NativePointer;

    /**
     * Memory location of the next byte of output.
     */
    code: NativePointer;

    /**
     * Program counter at the next byte of output.
     */
    pc: NativePointer;

    /**
     * Current offset in bytes.
     */
    offset: number;

    /**
     * Skips `nBytes`.
     */
    skip(nBytes: number): void;

    /**
     * Puts a label at the current position, where `id` is an identifier
     * that may be referenced in past and future `put*Label()` calls.
     */
    putLabel(id: string): void;

    /**
     * Puts code needed for calling a C function with the specified `args`.
     */
    putCallAddressWithArguments(func: NativePointerValue, args: Arm64CallArgument[]): void;

    /**
     * Puts code needed for calling a C function with the specified `args`.
     */
    putCallRegWithArguments(reg: Arm64Register, args: Arm64CallArgument[]): void;

    /**
     * Puts a BRANCH instruction.
     */
    putBranchAddress(address: NativePointerValue): void;

    /**
     * Puts a B instruction.
     */
    putBImm(address: NativePointerValue): void;

    /**
     * Puts a B instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBLabel(labelId: string): void;

    /**
     * Puts a B COND instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBCondLabel(cc: Arm64ConditionCode, labelId: string): void;

    /**
     * Puts a BL instruction.
     */
    putBlImm(address: NativePointerValue): void;

    /**
     * Puts a BL instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBlLabel(labelId: string): void;

    /**
     * Puts a BR instruction.
     */
    putBrReg(reg: Arm64Register): void;

    /**
     * Puts a BLR instruction.
     */
    putBlrReg(reg: Arm64Register): void;

    /**
     * Puts a RET instruction.
     */
    putRet(): void;

    /**
     * Puts a CBZ instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putCbzRegLabel(reg: Arm64Register, labelId: string): void;

    /**
     * Puts a CBNZ instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putCbnzRegLabel(reg: Arm64Register, labelId: string): void;

    /**
     * Puts a TBZ instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putTbzRegImmLabel(reg: Arm64Register, bit: number, labelId: string): void;

    /**
     * Puts a TBNZ instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putTbnzRegImmLabel(reg: Arm64Register, bit: number, labelId: string): void;

    /**
     * Puts a PUSH instruction.
     */
    putPushRegReg(regA: Arm64Register, regB: Arm64Register): void;

    /**
     * Puts a POP instruction.
     */
    putPopRegReg(regA: Arm64Register, regB: Arm64Register): void;

    /**
     * Puts code needed for pushing all X registers on the stack.
     */
    putPushAllXRegisters(): void;

    /**
     * Puts code needed for popping all X registers off the stack.
     */
    putPopAllXRegisters(): void;

    /**
     * Puts code needed for pushing all Q registers on the stack.
     */
    putPushAllQRegisters(): void;

    /**
     * Puts code needed for popping all Q registers off the stack.
     */
    putPopAllQRegisters(): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegAddress(reg: Arm64Register, address: NativePointerValue): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegU64(reg: Arm64Register, val: number | UInt64): void;

    /**
     * Puts an LDR instruction with a dangling data reference,
     * returning an opaque ref value that should be passed to `putLdrRegValue()`
     * at the desired location.
     */
    putLdrRegRef(reg: Arm64Register): number;

    /**
     * Puts the value and updates the LDR instruction
     * from a previous `putLdrRegRef()`.
     */
    putLdrRegValue(ref: number, value: NativePointerValue): void;

    /**
     * Puts an LDR instruction.
     */
    putLdrRegRegOffset(dstReg: Arm64Register, srcReg: Arm64Register, srcOffset: number | Int64 | UInt64): void;

    /**
     * Puts an LDRSW instruction.
     */
    putLdrswRegRegOffset(dstReg: Arm64Register, srcReg: Arm64Register, srcOffset: number | Int64 | UInt64): void;

    /**
     * Puts an ADRP instruction.
     */
    putAdrpRegAddress(reg: Arm64Register, address: NativePointerValue): void;

    /**
     * Puts a STR instruction.
     */
    putStrRegRegOffset(srcReg: Arm64Register, dstReg: Arm64Register, dstOffset: number | Int64 | UInt64): void;

    /**
     * Puts an LDP instruction.
     */
    putLdpRegRegRegOffset(regA: Arm64Register, regB: Arm64Register, regSrc: Arm64Register, srcOffset: number | Int64 | UInt64, mode: Arm64IndexMode): void;

    /**
     * Puts a STP instruction.
     */
    putStpRegRegRegOffset(regA: Arm64Register, regB: Arm64Register, regDst: Arm64Register, dstOffset: number | Int64 | UInt64, mode: Arm64IndexMode): void;

    /**
     * Puts a MOV instruction.
     */
    putMovRegReg(dstReg: Arm64Register, srcReg: Arm64Register): void;

    /**
     * Puts an UXTW instruction.
     */
    putUxtwRegReg(dstReg: Arm64Register, srcReg: Arm64Register): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegRegImm(dstReg: Arm64Register, leftReg: Arm64Register, rightValue: number | Int64 | UInt64): void;

    /**
     * Puts an ADD instruction.
     */
    putAddRegRegReg(dstReg: Arm64Register, leftReg: Arm64Register, rightReg: Arm64Register): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegRegImm(dstReg: Arm64Register, leftReg: Arm64Register, rightValue: number | Int64 | UInt64): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegRegReg(dstReg: Arm64Register, leftReg: Arm64Register, rightReg: Arm64Register): void;

    /**
     * Puts an AND instruction.
     */
    putAndRegRegImm(dstReg: Arm64Register, leftReg: Arm64Register, rightValue: number | Int64 | UInt64): void;

    /**
     * Puts a TST instruction.
     */
    putTstRegImm(reg: Arm64Register, immValue: number | UInt64): void;

    /**
     * Puts a CMP instruction.
     */
    putCmpRegReg(regA: Arm64Register, regB: Arm64Register): void;

    /**
     * Puts a NOP instruction.
     */
    putNop(): void;

    /**
     * Puts a BRK instruction.
     */
    putBrkImm(imm: number): void;

    /**
     * Puts a raw instruction.
     */
    putInstruction(insn: number): void;

    /**
     * Puts raw data.
     */
    putBytes(data: ArrayBuffer | number[] | string): void;
}

declare interface Arm64WriterOptions {
    /**
     * Specifies the initial program counter, which is useful when
     * generating code to a scratch buffer. This is essential when using
     * `Memory.patchCode()` on iOS, which may provide you with a
     * temporary location that later gets mapped into memory at the
     * intended memory location.
     */
    pc?: NativePointer;
}

declare type Arm64CallArgument = Arm64Register | number | UInt64 | Int64 | NativePointerValue;

/**
 * Relocates machine code for arm64.
 */
declare class Arm64Relocator {
    /**
     * Creates a new code relocator for copying AArch64 instructions
     * from one memory location to another, taking care to adjust
     * position-dependent instructions accordingly.
     *
     * @param inputCode Source address to copy instructions from.
     * @param output Arm64Writer pointed at the desired target memory
     *               address.
     */
    constructor(inputCode: NativePointerValue, output: Arm64Writer);

    /**
     * Recycles instance.
     */
    reset(inputCode: NativePointerValue, output: Arm64Writer): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Latest `Instruction` read so far. Starts out `null` and changes
     * on every call to `readOne()`.
     */
    input: Instruction | null;

    /**
     * Indicates whether end-of-block has been reached, i.e. we've
     * reached a branch of any kind, like CALL, JMP, BL, RET.
     */
    eob: boolean;

    /**
     * Indicates whether end-of-input has been reached, e.g. we've
     * reached JMP/B/RET, an instruction after which there may or may
     * not be valid code.
     */
    eoi: boolean;

    /**
     * Reads the next instruction into the relocator's internal buffer
     * and returns the number of bytes read so far, including previous
     * calls.
     *
     * You may keep calling this method to keep buffering, or immediately
     * call either `writeOne()` or `skipOne()`. Or, you can buffer up
     * until the desired point and then call `writeAll()`.
     *
     * Returns zero when end-of-input is reached, which means the `eoi`
     * property is now `true`.
     */
    readOne(): number;

    /**
     * Peeks at the next `Instruction` to be written or skipped.
     */
    peekNextWriteInsn(): Instruction | null;

    /**
     * Peeks at the address of the next instruction to be written or skipped.
     */
    peekNextWriteSource(): NativePointer;

    /**
     * Skips the instruction that would have been written next.
     */
    skipOne(): void;

    /**
     * write the next buffered instruction.
     */
    writeOne(): boolean;

    /**
     * Writes all buffered instructions.
     */
    writeAll(): void;
}

declare const enum Arm64Register {
    X0 = "x0",
    X1 = "x1",
    X2 = "x2",
    X3 = "x3",
    X4 = "x4",
    X5 = "x5",
    X6 = "x6",
    X7 = "x7",
    X8 = "x8",
    X9 = "x9",
    X10 = "x10",
    X11 = "x11",
    X12 = "x12",
    X13 = "x13",
    X14 = "x14",
    X15 = "x15",
    X16 = "x16",
    X17 = "x17",
    X18 = "x18",
    X19 = "x19",
    X20 = "x20",
    X21 = "x21",
    X22 = "x22",
    X23 = "x23",
    X24 = "x24",
    X25 = "x25",
    X26 = "x26",
    X27 = "x27",
    X28 = "x28",
    X29 = "x29",
    X30 = "x30",
    W0 = "w0",
    W1 = "w1",
    W2 = "w2",
    W3 = "w3",
    W4 = "w4",
    W5 = "w5",
    W6 = "w6",
    W7 = "w7",
    W8 = "w8",
    W9 = "w9",
    W10 = "w10",
    W11 = "w11",
    W12 = "w12",
    W13 = "w13",
    W14 = "w14",
    W15 = "w15",
    W16 = "w16",
    W17 = "w17",
    W18 = "w18",
    W19 = "w19",
    W20 = "w20",
    W21 = "w21",
    W22 = "w22",
    W23 = "w23",
    W24 = "w24",
    W25 = "w25",
    W26 = "w26",
    W27 = "w27",
    W28 = "w28",
    W29 = "w29",
    W30 = "w30",
    Sp = "sp",
    Lr = "lr",
    Fp = "fp",
    Wsp = "wsp",
    Wzr = "wzr",
    Xzr = "xzr",
    Nzcv = "nzcv",
    Ip0 = "ip0",
    Ip1 = "ip1",
    S0 = "s0",
    S1 = "s1",
    S2 = "s2",
    S3 = "s3",
    S4 = "s4",
    S5 = "s5",
    S6 = "s6",
    S7 = "s7",
    S8 = "s8",
    S9 = "s9",
    S10 = "s10",
    S11 = "s11",
    S12 = "s12",
    S13 = "s13",
    S14 = "s14",
    S15 = "s15",
    S16 = "s16",
    S17 = "s17",
    S18 = "s18",
    S19 = "s19",
    S20 = "s20",
    S21 = "s21",
    S22 = "s22",
    S23 = "s23",
    S24 = "s24",
    S25 = "s25",
    S26 = "s26",
    S27 = "s27",
    S28 = "s28",
    S29 = "s29",
    S30 = "s30",
    S31 = "s31",
    D0 = "d0",
    D1 = "d1",
    D2 = "d2",
    D3 = "d3",
    D4 = "d4",
    D5 = "d5",
    D6 = "d6",
    D7 = "d7",
    D8 = "d8",
    D9 = "d9",
    D10 = "d10",
    D11 = "d11",
    D12 = "d12",
    D13 = "d13",
    D14 = "d14",
    D15 = "d15",
    D16 = "d16",
    D17 = "d17",
    D18 = "d18",
    D19 = "d19",
    D20 = "d20",
    D21 = "d21",
    D22 = "d22",
    D23 = "d23",
    D24 = "d24",
    D25 = "d25",
    D26 = "d26",
    D27 = "d27",
    D28 = "d28",
    D29 = "d29",
    D30 = "d30",
    D31 = "d31",
    Q0 = "q0",
    Q1 = "q1",
    Q2 = "q2",
    Q3 = "q3",
    Q4 = "q4",
    Q5 = "q5",
    Q6 = "q6",
    Q7 = "q7",
    Q8 = "q8",
    Q9 = "q9",
    Q10 = "q10",
    Q11 = "q11",
    Q12 = "q12",
    Q13 = "q13",
    Q14 = "q14",
    Q15 = "q15",
    Q16 = "q16",
    Q17 = "q17",
    Q18 = "q18",
    Q19 = "q19",
    Q20 = "q20",
    Q21 = "q21",
    Q22 = "q22",
    Q23 = "q23",
    Q24 = "q24",
    Q25 = "q25",
    Q26 = "q26",
    Q27 = "q27",
    Q28 = "q28",
    Q29 = "q29",
    Q30 = "q30",
    Q31 = "q31",
}

declare const enum Arm64ConditionCode {
    Eq = "eq",
    Ne = "ne",
    Hs = "hs",
    Lo = "lo",
    Mi = "mi",
    Pl = "pl",
    Vs = "vs",
    Vc = "vc",
    Hi = "hi",
    Ls = "ls",
    Ge = "ge",
    Lt = "lt",
    Gt = "gt",
    Le = "le",
    Al = "al",
    Nv = "nv",
}

declare const enum Arm64IndexMode {
    PostAdjust = "post-adjust",
    SignedOffset = "signed-offset",
    PreAdjust = "pre-adjust",
}

/**
 * Generates machine code for mips.
 */
declare class MipsWriter {
    /**
     * Creates a new code writer for generating MIPS machine code
     * written directly to memory at `codeAddress`.
     *
     * @param codeAddress Memory address to write generated code to.
     * @param options Options for customizing code generation.
     */
    constructor(codeAddress: NativePointerValue, options?: MipsWriterOptions);

    /**
     * Recycles instance.
     */
    reset(codeAddress: NativePointerValue, options?: MipsWriterOptions): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Resolves label references and writes pending data to memory. You
     * should always call this once you've finished generating code. It
     * is usually also desirable to do this between pieces of unrelated
     * code, e.g. when generating multiple functions in one go.
     */
    flush(): void;

    /**
     * Memory location of the first byte of output.
     */
    base: NativePointer;

    /**
     * Memory location of the next byte of output.
     */
    code: NativePointer;

    /**
     * Program counter at the next byte of output.
     */
    pc: NativePointer;

    /**
     * Current offset in bytes.
     */
    offset: number;

    /**
     * Skips `nBytes`.
     */
    skip(nBytes: number): void;

    /**
     * Puts a label at the current position, where `id` is an identifier
     * that may be referenced in past and future `put*Label()` calls.
     */
    putLabel(id: string): void;

    /**
     * Puts code needed for calling a C function with the specified `args`.
     */
    putCallAddressWithArguments(func: NativePointerValue, args: MipsCallArgument[]): void;

    /**
     * Puts code needed for calling a C function with the specified `args`.
     */
    putCallRegWithArguments(reg: MipsRegister, args: MipsCallArgument[]): void;

    /**
     * Puts a J instruction.
     */
    putJAddress(address: NativePointerValue): void;

    /**
     * Puts a J instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putJLabel(labelId: string): void;

    /**
     * Puts a JR instruction.
     */
    putJrReg(reg: MipsRegister): void;

    /**
     * Puts a JAL instruction.
     */
    putJalAddress(address: number): void;

    /**
     * Puts a JALR instruction.
     */
    putJalrReg(reg: MipsRegister): void;

    /**
     * Puts a B instruction.
     */
    putBOffset(offset: number): void;

    /**
     * Puts a BEQ instruction referencing `labelId`, defined by a past
     * or future `putLabel()`.
     */
    putBeqRegRegLabel(rightReg: MipsRegister, leftReg: MipsRegister, labelId: string): void;

    /**
     * Puts a RET instruction.
     */
    putRet(): void;

    /**
     * Puts a LA instruction.
     */
    putLaRegAddress(reg: MipsRegister, address: NativePointerValue): void;

    /**
     * Puts a LUI instruction.
     */
    putLuiRegImm(reg: MipsRegister, imm: number): void;

    /**
     * Puts an ORI instruction.
     */
    putOriRegRegImm(rt: MipsRegister, rs: MipsRegister, imm: number): void;

    /**
     * Puts a LW instruction.
     */
    putLwRegRegOffset(dstReg: MipsRegister, srcReg: MipsRegister, srcOffset: number | Int64 | UInt64): void;

    /**
     * Puts a SW instruction.
     */
    putSwRegRegOffset(srcReg: MipsRegister, dstReg: MipsRegister, dstOffset: number | Int64 | UInt64): void;

    /**
     * Puts a MOVE instruction.
     */
    putMoveRegReg(dstReg: MipsRegister, srcReg: MipsRegister): void;

    /**
     * Puts an ADDU instruction.
     */
    putAdduRegRegReg(dstReg: MipsRegister, leftReg: MipsRegister, rightReg: MipsRegister): void;

    /**
     * Puts an ADDI instruction.
     */
    putAddiRegRegImm(destReg: MipsRegister, leftReg: MipsRegister, imm: number): void;

    /**
     * Puts an ADDI instruction.
     */
    putAddiRegImm(destReg: MipsRegister, imm: number): void;

    /**
     * Puts a SUB instruction.
     */
    putSubRegRegImm(destReg: MipsRegister, leftReg: MipsRegister, imm: number): void;

    /**
     * Puts a PUSH instruction.
     */
    putPushReg(reg: MipsRegister): void;

    /**
     * Puts a POP instruction.
     */
    putPopReg(reg: MipsRegister): void;

    /**
     * Puts a MFHI instruction.
     */
    putMfhiReg(reg: MipsRegister): void;

    /**
     * Puts a MFLO instruction.
     */
    putMfloReg(reg: MipsRegister): void;

    /**
     * Puts a MTHI instruction.
     */
    putMthiReg(reg: MipsRegister): void;

    /**
     * Puts a MTLO instruction.
     */
    putMtloReg(reg: MipsRegister): void;

    /**
     * Puts a NOP instruction.
     */
    putNop(): void;

    /**
     * Puts a BREAK instruction.
     */
    putBreak(): void;

    /**
     * Puts a raw instruction.
     */
    putInstruction(insn: number): void;

    /**
     * Puts raw data.
     */
    putBytes(data: ArrayBuffer | number[] | string): void;
}

declare interface MipsWriterOptions {
    /**
     * Specifies the initial program counter, which is useful when
     * generating code to a scratch buffer. This is essential when using
     * `Memory.patchCode()` on iOS, which may provide you with a
     * temporary location that later gets mapped into memory at the
     * intended memory location.
     */
    pc?: NativePointer;
}

declare type MipsCallArgument = MipsRegister | number | UInt64 | Int64 | NativePointerValue;

/**
 * Relocates machine code for mips.
 */
declare class MipsRelocator {
    /**
     * Creates a new code relocator for copying MIPS instructions
     * from one memory location to another, taking care to adjust
     * position-dependent instructions accordingly.
     *
     * @param inputCode Source address to copy instructions from.
     * @param output MipsWriter pointed at the desired target memory
     *               address.
     */
    constructor(inputCode: NativePointerValue, output: MipsWriter);

    /**
     * Recycles instance.
     */
    reset(inputCode: NativePointerValue, output: MipsWriter): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Latest `Instruction` read so far. Starts out `null` and changes
     * on every call to `readOne()`.
     */
    input: Instruction | null;

    /**
     * Indicates whether end-of-block has been reached, i.e. we've
     * reached a branch of any kind, like CALL, JMP, BL, RET.
     */
    eob: boolean;

    /**
     * Indicates whether end-of-input has been reached, e.g. we've
     * reached JMP/B/RET, an instruction after which there may or may
     * not be valid code.
     */
    eoi: boolean;

    /**
     * Reads the next instruction into the relocator's internal buffer
     * and returns the number of bytes read so far, including previous
     * calls.
     *
     * You may keep calling this method to keep buffering, or immediately
     * call either `writeOne()` or `skipOne()`. Or, you can buffer up
     * until the desired point and then call `writeAll()`.
     *
     * Returns zero when end-of-input is reached, which means the `eoi`
     * property is now `true`.
     */
    readOne(): number;

    /**
     * Peeks at the next `Instruction` to be written or skipped.
     */
    peekNextWriteInsn(): Instruction | null;

    /**
     * Peeks at the address of the next instruction to be written or skipped.
     */
    peekNextWriteSource(): NativePointer;

    /**
     * Skips the instruction that would have been written next.
     */
    skipOne(): void;

    /**
     * write the next buffered instruction.
     */
    writeOne(): boolean;

    /**
     * Writes all buffered instructions.
     */
    writeAll(): void;
}

declare const enum MipsRegister {
    V0 = "v0",
    V1 = "v1",
    A0 = "a0",
    A1 = "a1",
    A2 = "a2",
    A3 = "a3",
    T0 = "t0",
    T1 = "t1",
    T2 = "t2",
    T3 = "t3",
    T4 = "t4",
    T5 = "t5",
    T6 = "t6",
    T7 = "t7",
    S0 = "s0",
    S1 = "s1",
    S2 = "s2",
    S3 = "s3",
    S4 = "s4",
    S5 = "s5",
    S6 = "s6",
    S7 = "s7",
    T8 = "t8",
    T9 = "t9",
    K0 = "k0",
    K1 = "k1",
    Gp = "gp",
    Sp = "sp",
    Fp = "fp",
    S8 = "s8",
    Ra = "ra",
    Hi = "hi",
    Lo = "lo",
    Zero = "zero",
    At = "at",
    R0 = "0",
    R1 = "1",
    R2 = "2",
    R3 = "3",
    R4 = "4",
    R5 = "5",
    R6 = "6",
    R7 = "7",
    R8 = "8",
    R9 = "9",
    R10 = "10",
    R11 = "11",
    R12 = "12",
    R13 = "13",
    R14 = "14",
    R15 = "15",
    R16 = "16",
    R17 = "17",
    R18 = "18",
    R19 = "19",
    R20 = "20",
    R21 = "21",
    R22 = "22",
    R23 = "23",
    R24 = "24",
    R25 = "25",
    R26 = "26",
    R27 = "27",
    R28 = "28",
    R29 = "29",
    R30 = "30",
    R31 = "31",
}
