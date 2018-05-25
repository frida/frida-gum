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
 * This is useful if you e.g. dumped some memory using `Memory.readByteArray()`.
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

declare namespace console {
    function error(...args: any[]): void;
    function log(...args: any[]): void;
    function warn(...args: any[]): void;
}

declare namespace rpc {
    /**
     * Empty object that you can either replace or insert into to expose an RPC-style API to your application.
     * The key specifies the method name and the value is your exported function. This function may either return
     * a plain value for returning that to the caller immediately, or a Promise for returning asynchronously.
     */
    let exports: RpcExports;
}

declare interface RpcExports {
    [name: string]: Function;
}

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
     *
     * @param callbacks Object with callbacks.
     */
    function enumerateThreads(callbacks: EnumerateCallbacks<ThreadDetails>): void;

    /**
     * Synchronous version of `enumerateThreads()`.
     *
     * @param callbacks Object with callbacks.
     */
    function enumerateThreadsSync(): ThreadDetails[];

    /**
     * Looks up a module by address. Returns null if not found.
     */
    function findModuleByAddress(address: any): ModuleDetails | null;

    /**
     * Looks up a module by address. Throws an exception if not found.
     */
    function getModuleByAddress(address: any): ModuleDetails;

    /**
     * Looks up a module by name. Returns null if not found.
     */
    function findModuleByName(name: any): ModuleDetails | null;

    /**
     * Looks up a module by name. Throws an exception if not found.
     */
    function getModuleByName(name: any): ModuleDetails;

    /**
     * Enumerates all modules.
     *
     * @param callbacks Object with callbacks.
     */
    function enumerateModules(callbacks: EnumerateCallbacks<ModuleDetails>): void;

    /**
     * Synchronous version of `enumerateModules()`.
     *
     * @param callbacks Object with callbacks.
     */
    function enumerateModulesSync(): ModuleDetails[];

    /**
     * Looks up a memory range by address. Returns null if not found.
     */
    function findRangeByAddress(address: any): RangeDetails | null;

    /**
     * Looks up a memory range by address. Throws an exception if not found.
     */
    function getRangeByAddress(address: any): RangeDetails;

    /**
      * Enumerates all memory ranges matching `specifier`.
      *
      * @param specifier The kind of ranges to include.
      * @param callbacks Object with callbacks.
      */
    function enumerateRanges(specifier: PageProtection | EnumerateRangesSpecifier, callbacks: EnumerateCallbacks<RangeDetails>): void;

    /**
     * Synchronous version of `enumerateRanges()`.
     *
     * @param specifier The kind of ranges to include.
     */
    function enumerateRangesSync(specifier: PageProtection | EnumerateRangesSpecifier): RangeDetails[];

    /**
     * Just like `enumerateRanges()`, but for individual memory allocations known to the system heap.
     */
    function enumerateMallocRanges(callbacks: EnumerateCallbacks<RangeDetails>): void;

    /**
     * Synchronous version of `enumerateMallocRanges()`.
     */
    function enumerateMallocRangesSync(): RangeDetails[];

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

declare namespace Module {
    /**
     * Ensures that initializers of the specified module have been run. This is important during early instrumentation,
     * i.e. code run early in the process lifetime, to be able to safely interact with APIs.
     *
     * One such use-case is interacting with ObjC classes provided by a given module.
     */
    function ensureInitialized(name: string): void;

    /**
     * Enumerates imports of module with the `name` as seen in `Process#enumerateModules()`.
     *
     * @param name Module name or path.
     * @param callbacks Object with callbacks.
     */
    function enumerateImports(name: string, callbacks: EnumerateCallbacks<ModuleImportDetails>): void;

    /**
     * Synchronous version of `enumerateImports()`.
     *
     * @param name Module name or path.
     */
    function enumerateImportsSync(name: string): ModuleImportDetails[];

    /**
     * Enumerates exports of module with the `name` as seen in `Process#enumerateModules()`.
     *
     * @param name Module name or path.
     * @param callbacks Object with callbacks.
     */
    function enumerateExports(name: string, callbacks: EnumerateCallbacks<ModuleExportDetails>): void;

    /**
     * Synchronous version of `enumerateExports()`.
     *
     * @param name Module name or path.
     */
    function enumerateExportsSync(name: string): ModuleExportDetails[];

    /**
     * Enumerates symbols of module with the `name` as seen in `Process#enumerateModules()`.
     *
     * @param name Module name or path.
     * @param callbacks Object with callbacks.
     */
    function enumerateSymbols(name: string, callbacks: EnumerateCallbacks<ModuleSymbolDetails>): void;

    /**
     * Synchronous version of `enumerateSymbols()`.
     *
     * @param name Module name or path.
     */
    function enumerateSymbolsSync(name: string): ModuleSymbolDetails[];

    /**
     * Enumerates memory ranges of module with the `name` as seen in `Process#enumerateModules()`.
     *
     * @param name Module name or path.
     * @param protection Minimum protection of ranges to include.
     * @param callbacks Object with callbacks.
     */
    function enumerateRanges(name: string, protection: PageProtection, callbacks: EnumerateCallbacks<RangeDetails>): void;

    /**
     * Synchronous version of `enumerateRanges()`.
     *
     * @param name Module name or path.
     * @param protection Minimum protection of ranges to include.
     */
    function enumerateRangesSync(name: string, protection: PageProtection): RangeDetails[];

    /**
     * Looks up the base address of the `name` module, or null if the module isn’t loaded.
     *
     * @param name Module name or path.
     */
    function findBaseAddress(name: string): NativePointer | null;

    /**
     * Looks up the absolute address of the export named `exportName` in `moduleName`. If the module isn’t known you may
     * pass null instead of its name, but this can be a costly search and should be avoided.
     *
     * @param moduleName Module name or path.
     * @param exportName Export name to find the address of.
     */
    function findExportByName(moduleName: string | null, exportName: string): NativePointer | null;
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
    find(address: NativePointerValue): ModuleDetails | null;

    /**
     * Looks up a module by address. Throws an exception if not found.
     *
     * @param address Address that might belong to a module in the map.
     */
    get(address: NativePointerValue): ModuleDetails;

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
    values(): ModuleDetails[];
}

type ModuleMapFilter = (m: ModuleDetails) => boolean;

declare namespace Memory {
    /**
     * Scans memory for occurences of `pattern` in the memory range given by `address` and `size`.
     *
     * @param address Starting address to scan from.
     * @param size Number of bytes to scan.
     * @param pattern Match pattern of the form “13 37 ?? ff” to match 0x13 followed by 0x37 followed by any byte
     *                followed by 0xff.
     * @param callbacks Object with callbacks.
     */
    function scan(address: NativePointerValue, size: number | UInt64, pattern: string, callbacks: MemoryScanCallbacks): void;

    /**
     * Synchronous version of `scan()`.
     *
     * @param address Starting address to scan from.
     * @param size Number of bytes to scan.
     * @param pattern Match pattern of the form “13 37 ?? ff” to match 0x13 followed by 0x37 followed by any byte
     *                followed by 0xff.
     * @param callbacks Object with callbacks.
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

    function readPointer(address: NativePointerValue): NativePointer;
    function readS8(address: NativePointerValue): number;
    function readU8(address: NativePointerValue): number;
    function readS16(address: NativePointerValue): number;
    function readU16(address: NativePointerValue): number;
    function readS32(address: NativePointerValue): number;
    function readU32(address: NativePointerValue): number;
    function readS64(address: NativePointerValue): Int64;
    function readU64(address: NativePointerValue): UInt64;
    function readShort(address: NativePointerValue): number;
    function readUShort(address: NativePointerValue): number;
    function readInt(address: NativePointerValue): number;
    function readUInt(address: NativePointerValue): number;
    function readLong(address: NativePointerValue): number | Int64;
    function readULong(address: NativePointerValue): number | UInt64;
    function readFloat(address: NativePointerValue): number;
    function readDouble(address: NativePointerValue): number;
    function readByteArray(address: NativePointerValue, length: number): ArrayBuffer | null;
    function readCString(address: NativePointerValue, size?: number): string | null;
    function readUtf8String(address: NativePointerValue, size?: number): string | null;
    function readUtf16String(address: NativePointerValue, length?: number): string | null;
    function readAnsiString(address: NativePointerValue, size?: number): string | null;

    function writePointer(address: NativePointerValue, value: NativePointerValue): void;
    function writeS8(address: NativePointerValue, value: number | Int64): void;
    function writeU8(address: NativePointerValue, value: number | UInt64): void;
    function writeS16(address: NativePointerValue, value: number | Int64): void;
    function writeU16(address: NativePointerValue, value: number | UInt64): void;
    function writeS32(address: NativePointerValue, value: number | Int64): void;
    function writeU32(address: NativePointerValue, value: number | UInt64): void;
    function writeS64(address: NativePointerValue, value: number | Int64): void;
    function writeU64(address: NativePointerValue, value: number | UInt64): void;
    function writeShort(address: NativePointerValue, value: number | Int64): void;
    function writeUShort(address: NativePointerValue, value: number | UInt64): void;
    function writeInt(address: NativePointerValue, value: number | Int64): void;
    function writeUInt(address: NativePointerValue, value: number | UInt64): void;
    function writeLong(address: NativePointerValue, value: number | Int64): void;
    function writeULong(address: NativePointerValue, value: number | UInt64): void;
    function writeFloat(address: NativePointerValue, value: number): void;
    function writeDouble(address: NativePointerValue, value: number): void;
    function writeByteArray(address: NativePointerValue, value: ArrayBuffer | number[]): void;
    function writeUtf8String(address: NativePointerValue, value: string): void;
    function writeUtf16String(address: NativePointerValue, value: string): void;
    function writeAnsiString(address: NativePointerValue, value: string): void;
}

declare enum Architecture {
    Ia32 = "ia32",
    X64 = "x64",
    Arm = "arm",
    Arm64 = "arm64",
    Mips = "mips"
}

declare enum Platform {
    Windows = "windows",
    Darwin = "darwin",
    Linux = "linux",
    Qnx = "qnx"
}

declare enum CodeSigningPolicy {
    Optional = "optional",
    Required = "required"
}

/**
 * Given as a string of the form: rwx, where rw- means “readable and writable”.
 */
declare type PageProtection = string;

declare type ThreadId = number;

declare enum ThreadState {
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

declare interface ModuleDetails {
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

declare enum ModuleImportType {
    Function = "function",
    Variable = "variable"
}

declare enum ModuleExportType {
    Function = "function",
    Variable = "variable"
}

declare enum ModuleSymbolType {
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

declare enum ExceptionType {
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

declare enum ExceptionMemoryOperation {
    read = "read",
    write = "write",
    execute = "execute"
}

declare interface EnumerateCallbacks<T> {
    onMatch: (item: T) => void | EnumerateAction;
    onComplete: () => void;
}

declare enum EnumerateAction {
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
     * Returns an integer comparison result just like String#localeCompare().
     */
    compare(v: Int64 | number | string): number;

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
     * Returns an integer comparison result just like String#localeCompare().
     */
    compare(v: UInt64 | number | string): number;

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
}

declare interface ObjectWrapper {
    handle: NativePointer;
}

declare type NativePointerValue = NativePointer | ObjectWrapper;

declare class NativeFunction extends NativePointer {
    constructor(address: NativePointerValue, retType: NativeType, argTypes: NativeType[], abi?: NativeABI);
    apply(thisArg: NativePointerValue | null | undefined, args: NativeArgumentValue[]): NativeReturnValue;
    call(): NativeReturnValue;
    call(thisArg: NativePointerValue | null | undefined, ...args: NativeArgumentValue[]): NativeReturnValue;
}

declare class SystemFunction extends NativePointer {
    constructor(address: NativePointerValue, retType: NativeType, argTypes: NativeType[], abi?: NativeABI);
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

declare enum NativeABI {
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

declare type InvocationContext = WindowsInvocationContext | UnixInvocationContext;

declare interface WindowsInvocationContext {
    /**
     * Return address.
     */
    returnAddress: NativePointer;

    /**
     * CPU registers. You may also update register values by assigning to these keys.
     */
    context: CpuContext;

    /**
     * Current OS error value (you may replace it).
     */
    lastError: number;

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

declare interface UnixInvocationContext {
    /**
     * Return address.
     */
    returnAddress: NativePointer;

    /**
     * CPU registers. You may also update register values by assigning to these keys.
     */
    context: CpuContext;

    /**
     * Current errno value (you may replace it).
     */
    errno: number;

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
declare const Backtracer: {
    ACCURATE: any;
    FUZZY: any;
};
declare function UnixInputStream(): any;
declare function UnixOutputStream(): any;
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
    function readByteArray(pointer: any, size: number): any;
    function writeByteArray(): any;
}
declare namespace MemoryAccessMonitor {
    function disable(): any;
    function enable(): any;
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
    const mainQueue: NativePointer;
    function Object(handle: any, protocol?: any, cachedIsClass?: any, superSpecifier?: any): void;
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
    function backtrace(context: any): NativePointer[];
    function sleep(duration: number): void;
}
declare namespace WeakRef {
    function bind(): any;
    function unbind(): any;
}
