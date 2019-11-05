/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukcore.h"

#include "gumdukinterceptor.h"
#include "gumdukmacros.h"
#include "gumdukscript-java.h"
#include "gumdukscript-objc.h"
#include "gumdukscript-promise.h"
#include "gumdukstalker.h"
#include "gumffi.h"
#include "gumsourcemap.h"

#include <ffi.h>

#define GUM_DUK_NATIVE_POINTER_CACHE_SIZE 8

typedef struct _GumDukFlushCallback GumDukFlushCallback;
typedef struct _GumDukNativeFunctionParams GumDukNativeFunctionParams;
typedef guint8 GumDukSchedulingBehavior;
typedef guint8 GumDukExceptionsBehavior;
typedef guint8 GumDukReturnValueShape;
typedef struct _GumDukNativeFunction GumDukNativeFunction;
typedef struct _GumDukNativeCallback GumDukNativeCallback;

struct _GumDukFlushCallback
{
  GumDukFlushNotify func;
  GumDukScript * script;
};

struct _GumDukWeakRef
{
  guint id;
  GumDukHeapPtr callback;

  GumDukCore * core;
};

struct _GumDukScheduledCallback
{
  gint id;
  gboolean repeat;
  GumDukHeapPtr func;
  GSource * source;

  GumDukCore * core;
};

struct _GumDukExceptionSink
{
  GumDukHeapPtr callback;
  GumDukCore * core;
};

struct _GumDukMessageSink
{
  GumDukHeapPtr callback;
  GumDukCore * core;
};

struct _GumDukNativeFunctionParams
{
  GumDukHeapPtr prototype;

  GCallback implementation;
  GumDukHeapPtr return_type;
  GumDukHeapPtr argument_types;
  const gchar * abi_name;
  GumDukSchedulingBehavior scheduling;
  GumDukExceptionsBehavior exceptions;
  GumDukReturnValueShape return_shape;
};

enum _GumDukSchedulingBehavior
{
  GUM_DUK_SCHEDULING_COOPERATIVE,
  GUM_DUK_SCHEDULING_EXCLUSIVE
};

enum _GumDukExceptionsBehavior
{
  GUM_DUK_EXCEPTIONS_STEAL,
  GUM_DUK_EXCEPTIONS_PROPAGATE
};

enum _GumDukReturnValueShape
{
  GUM_DUK_RETURN_PLAIN,
  GUM_DUK_RETURN_DETAILED
};

struct _GumDukNativeFunction
{
  GumDukNativePointer parent;

  GCallback implementation;
  GumDukSchedulingBehavior scheduling;
  GumDukExceptionsBehavior exceptions;
  GumDukReturnValueShape return_shape;
  ffi_cif cif;
  ffi_type ** atypes;
  gsize arglist_size;
  gboolean is_variadic;
  duk_size_t nargs_fixed;
  ffi_abi abi;
  GSList * data;

  GumDukCore * core;
};

struct _GumDukNativeCallback
{
  GumDukNativePointer parent;

  GumDukHeapPtr func;
  ffi_closure * closure;
  ffi_cif cif;
  ffi_type ** atypes;
  GSList * data;

  GumDukCore * core;
};

static void gum_duk_flush_callback_free (GumDukFlushCallback * self);
static gboolean gum_duk_flush_callback_notify (GumDukFlushCallback * self);

GUMJS_DECLARE_FUNCTION (gumjs_set_timeout)
GUMJS_DECLARE_FUNCTION (gumjs_set_interval)
GUMJS_DECLARE_FUNCTION (gumjs_clear_timer)
GUMJS_DECLARE_FUNCTION (gumjs_gc)
GUMJS_DECLARE_FUNCTION (gumjs_send)
GUMJS_DECLARE_FUNCTION (gumjs_set_unhandled_exception_callback)
GUMJS_DECLARE_FUNCTION (gumjs_set_incoming_message_callback)
GUMJS_DECLARE_FUNCTION (gumjs_wait_for_event)

GUMJS_DECLARE_GETTER (gumjs_get_promise)

GUMJS_DECLARE_GETTER (gumjs_frida_get_heap_size)
GUMJS_DECLARE_GETTER (gumjs_frida_get_source_map)
GUMJS_DECLARE_GETTER (gumjs_frida_objc_get_source_map)
GUMJS_DECLARE_GETTER (gumjs_frida_java_get_source_map)
GUMJS_DECLARE_FUNCTION (gumjs_frida_objc_load)
GUMJS_DECLARE_FUNCTION (gumjs_frida_java_load)

GUMJS_DECLARE_GETTER (gumjs_script_get_file_name)
GUMJS_DECLARE_GETTER (gumjs_script_get_source_map)
GUMJS_DECLARE_FUNCTION (gumjs_script_next_tick)
GUMJS_DECLARE_FUNCTION (gumjs_script_pin)
GUMJS_DECLARE_FUNCTION (gumjs_script_unpin)
GUMJS_DECLARE_FUNCTION (gumjs_script_set_global_access_handler)
static int gum_duk_core_on_global_enumerate (duk_context * ctx, void * udata);
static int gum_duk_core_on_global_get (duk_context * ctx, const char * name,
    void * udata);

GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_bind)
GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_unbind)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_weak_ref_construct)
GUMJS_DECLARE_FINALIZER (gumjs_weak_ref_finalize)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_int64_construct)
GUMJS_DECLARE_FINALIZER (gumjs_int64_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_int64_add)
GUMJS_DECLARE_FUNCTION (gumjs_int64_sub)
GUMJS_DECLARE_FUNCTION (gumjs_int64_and)
GUMJS_DECLARE_FUNCTION (gumjs_int64_or)
GUMJS_DECLARE_FUNCTION (gumjs_int64_xor)
GUMJS_DECLARE_FUNCTION (gumjs_int64_shr)
GUMJS_DECLARE_FUNCTION (gumjs_int64_shl)
GUMJS_DECLARE_FUNCTION (gumjs_int64_not)
GUMJS_DECLARE_FUNCTION (gumjs_int64_compare)
GUMJS_DECLARE_FUNCTION (gumjs_int64_to_number)
GUMJS_DECLARE_FUNCTION (gumjs_int64_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_int64_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_int64_value_of)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_uint64_construct)
GUMJS_DECLARE_FINALIZER (gumjs_uint64_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_add)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_sub)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_and)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_or)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_xor)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_shr)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_shl)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_not)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_compare)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_to_number)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_value_of)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_pointer_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_pointer_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_is_null)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_add)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_sub)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_and)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_or)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_xor)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_shr)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_shl)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_not)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_compare)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_int32)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_uint32)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_match_pattern)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_resource_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_resource_finalize)
GUMJS_DECLARE_CONSTRUCTOR (gumjs_kernel_resource_construct)
GUMJS_DECLARE_FINALIZER (gumjs_kernel_resource_finalize)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_function_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_function_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_invoke)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_call)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_apply)
static void gumjs_native_function_get (duk_context * ctx,
    GumDukHeapPtr receiver, GumDukCore * core, GumDukNativeFunction ** func,
    GCallback * implementation);
static int gumjs_native_function_init (duk_context * ctx,
    const GumDukNativeFunctionParams * params, GumDukCore * core);
static void gum_duk_native_function_finalize (
    GumDukNativeFunction * func);
static int gum_duk_native_function_invoke (GumDukNativeFunction * self,
    duk_context * ctx, GCallback implementation, duk_size_t argc,
    duk_idx_t argv_index);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_system_function_construct)
GUMJS_DECLARE_FINALIZER (gumjs_system_function_finalize)

static void gum_duk_native_function_params_init (
    GumDukNativeFunctionParams * params, GumDukHeapPtr prototype,
    GumDukReturnValueShape return_shape, const GumDukArgs * args);
static GumDukSchedulingBehavior gum_duk_require_scheduling_behavior (
    duk_context * ctx, duk_idx_t index);
static GumDukExceptionsBehavior gum_duk_require_exceptions_behavior (
    duk_context * ctx, duk_idx_t index);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_callback_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_callback_finalize)
static void gum_duk_native_callback_finalize (
    GumDukNativeCallback * func, gboolean heap_destruct);
static void gum_duk_native_callback_invoke (ffi_cif * cif,
    void * return_value, void ** args, void * user_data);

static GumDukCpuContext * gumjs_cpu_context_from_args (const GumDukArgs * args);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_cpu_context_construct)
GUMJS_DECLARE_FINALIZER (gumjs_cpu_context_finalize)
static void gumjs_cpu_context_set_register (GumDukCpuContext * self,
    duk_context * ctx, const GumDukArgs * args, gpointer * reg);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_source_map_construct)
GUMJS_DECLARE_FINALIZER (gumjs_source_map_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_source_map_resolve)

static GumDukWeakRef * gum_duk_weak_ref_new (guint id, GumDukHeapPtr callback,
    GumDukCore * core);
static void gum_duk_weak_ref_clear (GumDukWeakRef * ref);

static gint gum_duk_core_schedule_callback (GumDukCore * self,
    const GumDukArgs * args, gboolean repeat);
static GumDukScheduledCallback * gum_duk_core_try_steal_scheduled_callback (
    GumDukCore * self, gint id);

static GumDukScheduledCallback * gum_scheduled_callback_new (guint id,
    GumDukHeapPtr func, gboolean repeat, GSource * source, GumDukCore * core);
static void gum_scheduled_callback_free (GumDukScheduledCallback * callback);
static gboolean gum_scheduled_callback_invoke (GumDukScheduledCallback * self);

static GumDukExceptionSink * gum_duk_exception_sink_new (GumDukHeapPtr callback,
    GumDukCore * core);
static void gum_duk_exception_sink_free (GumDukExceptionSink * sink);
static void gum_duk_exception_sink_handle_exception (
    GumDukExceptionSink * self);

static GumDukMessageSink * gum_duk_message_sink_new (GumDukHeapPtr callback,
    GumDukCore * core);
static void gum_duk_message_sink_free (GumDukMessageSink * sink);
static void gum_duk_message_sink_post (GumDukMessageSink * self,
    const gchar * message, GBytes * data, GumDukScope * scope);

static gboolean gum_duk_get_ffi_type (duk_context * ctx, GumDukHeapPtr value,
    ffi_type ** type, GSList ** data);
static gboolean gum_duk_get_ffi_abi (duk_context * ctx, const gchar * name,
    ffi_abi * abi);
static gboolean gum_duk_get_ffi_value (duk_context * ctx, duk_idx_t index,
    const ffi_type * type, GumDukCore * core, GumFFIValue * value);
static void gum_duk_push_ffi_value (duk_context * ctx,
    const GumFFIValue * value, const ffi_type * type, GumDukCore * core);

static const GumDukPropertyEntry gumjs_frida_values[] =
{
  { "heapSize", gumjs_frida_get_heap_size, NULL },
  { "sourceMap", gumjs_frida_get_source_map, NULL },
  { "_objcSourceMap", gumjs_frida_objc_get_source_map, NULL },
  { "_javaSourceMap", gumjs_frida_java_get_source_map, NULL },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_frida_functions[] =
{
  { "_loadObjC", gumjs_frida_objc_load, 0 },
  { "_loadJava", gumjs_frida_java_load, 0 },

  { NULL, NULL, 0 }
};

static const GumDukPropertyEntry gumjs_script_values[] =
{
  { "fileName", gumjs_script_get_file_name, NULL },
  { "sourceMap", gumjs_script_get_source_map, NULL },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_script_functions[] =
{
  { "_nextTick", gumjs_script_next_tick, 1 },
  { "pin", gumjs_script_pin, 0 },
  { "unpin", gumjs_script_unpin, 0 },
  { "setGlobalAccessHandler", gumjs_script_set_global_access_handler, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_weak_ref_module_functions[] =
{
  { "bind", gumjs_weak_ref_bind, 2 },
  { "unbind", gumjs_weak_ref_unbind, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_int64_functions[] =
{
  { "add", gumjs_int64_add, 1 },
  { "sub", gumjs_int64_sub, 1 },
  { "and", gumjs_int64_and, 1 },
  { "or", gumjs_int64_or, 1 },
  { "xor", gumjs_int64_xor, 1 },
  { "shr", gumjs_int64_shr, 1 },
  { "shl", gumjs_int64_shl, 1 },
  { "not", gumjs_int64_not, 1 },
  { "compare", gumjs_int64_compare, 1 },
  { "toNumber", gumjs_int64_to_number, 0 },
  { "toString", gumjs_int64_to_string, 1 },
  { "toJSON", gumjs_int64_to_json, 0 },
  { "valueOf", gumjs_int64_value_of, 0 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_uint64_functions[] =
{
  { "add", gumjs_uint64_add, 1 },
  { "sub", gumjs_uint64_sub, 1 },
  { "and", gumjs_uint64_and, 1 },
  { "or", gumjs_uint64_or, 1 },
  { "xor", gumjs_uint64_xor, 1 },
  { "shr", gumjs_uint64_shr, 1 },
  { "shl", gumjs_uint64_shl, 1 },
  { "not", gumjs_uint64_not, 1 },
  { "compare", gumjs_uint64_compare, 1 },
  { "toNumber", gumjs_uint64_to_number, 0 },
  { "toString", gumjs_uint64_to_string, 1 },
  { "toJSON", gumjs_uint64_to_json, 0 },
  { "valueOf", gumjs_uint64_value_of, 0 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_native_pointer_functions[] =
{
  { "isNull", gumjs_native_pointer_is_null, 0 },
  { "add", gumjs_native_pointer_add, 1 },
  { "sub", gumjs_native_pointer_sub, 1 },
  { "and", gumjs_native_pointer_and, 1 },
  { "or", gumjs_native_pointer_or, 1 },
  { "xor", gumjs_native_pointer_xor, 1 },
  { "shr", gumjs_native_pointer_shr, 1 },
  { "shl", gumjs_native_pointer_shl, 1 },
  { "not", gumjs_native_pointer_not, 0 },
  { "compare", gumjs_native_pointer_compare, 1 },
  { "toInt32", gumjs_native_pointer_to_int32, 0 },
  { "toUInt32", gumjs_native_pointer_to_uint32, 0 },
  { "toString", gumjs_native_pointer_to_string, 1 },
  { "toJSON", gumjs_native_pointer_to_json, 0 },
  { "toMatchPattern", gumjs_native_pointer_to_match_pattern, 0 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_native_function_functions[] =
{
  { "call", gumjs_native_function_call, DUK_VARARGS },
  { "apply", gumjs_native_function_apply, 2 },

  { NULL, NULL, 0 }
};

#define GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED(A, R) \
  GUMJS_DEFINE_GETTER (gumjs_cpu_context_get_##A) \
  { \
    GumDukCpuContext * self = gumjs_cpu_context_from_args (args); \
    \
    _gum_duk_push_native_pointer (ctx, GSIZE_TO_POINTER (self->handle->R), \
        args->core); \
    return 1; \
  } \
  \
  GUMJS_DEFINE_SETTER (gumjs_cpu_context_set_##A) \
  { \
    GumDukCpuContext * self = gumjs_cpu_context_from_args (args); \
    \
    gumjs_cpu_context_set_register (self, ctx, args, \
        (gpointer *) &self->handle->R); \
    return 0; \
  }
#define GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR(R) \
  GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (R, R)

#define GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED(A, R) \
  { G_STRINGIFY (A), gumjs_cpu_context_get_##R, gumjs_cpu_context_set_##R }
#define GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR(R) \
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (R, R)

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (eax)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (ecx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (edx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (ebx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (esp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (ebp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (esi)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (edi)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (eip)
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rax)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rcx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rdx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rbx)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rsp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rbp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rsi)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rdi)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r8)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r9)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r10)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r11)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r12)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r13)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r14)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r15)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (rip)
#elif defined (HAVE_ARM)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (pc)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (sp)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r0, r[0])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r1, r[1])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r2, r[2])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r3, r[3])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r4, r[4])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r5, r[5])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r6, r[6])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (r7, r[7])

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r8)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r9)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r10)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r11)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (r12)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (lr)
#elif defined (HAVE_ARM64)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (pc)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (sp)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x0, x[0])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x1, x[1])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x2, x[2])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x3, x[3])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x4, x[4])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x5, x[5])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x6, x[6])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x7, x[7])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x8, x[8])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x9, x[9])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x10, x[10])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x11, x[11])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x12, x[12])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x13, x[13])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x14, x[14])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x15, x[15])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x16, x[16])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x17, x[17])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x18, x[18])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x19, x[19])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x20, x[20])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x21, x[21])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x22, x[22])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x23, x[23])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x24, x[24])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x25, x[25])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x26, x[26])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x27, x[27])
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (x28, x[28])

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (fp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (lr)
#elif defined (HAVE_MIPS)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (pc)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (gp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (sp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (fp)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (ra)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (hi)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (lo)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (at)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (v0)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (v1)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (a0)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (a1)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (a2)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (a3)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t0)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t1)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t2)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t3)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t4)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t5)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t6)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t7)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t8)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (t9)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (s0)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (s1)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (s2)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (s3)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (s4)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (s5)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (s6)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (s7)

GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (k0)
GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR (k1)
#endif

static const GumDukPropertyEntry gumjs_cpu_context_values[] =
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (pc, eip),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (sp, esp),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (eax),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (ecx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (edx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (ebx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (esp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (ebp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (esi),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (edi),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (eip),
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (pc, rip),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (sp, rsp),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rax),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rcx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rdx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rbx),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rsp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rbp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rsi),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rdi),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r8),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r9),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r10),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r11),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r12),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r13),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r14),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r15),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (rip),
#elif defined (HAVE_ARM)
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (pc),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (sp),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r0),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r1),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r2),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r3),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r4),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r5),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r6),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r7),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r8),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r9),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r10),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r11),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (r12),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (lr),
#elif defined (HAVE_ARM64)
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (pc),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (sp),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x0),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x1),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x2),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x3),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x4),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x5),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x6),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x7),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x8),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x9),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x10),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x11),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x12),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x13),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x14),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x15),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x16),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x17),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x18),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x19),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x20),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x21),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x22),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x23),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x24),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x25),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x26),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x27),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (x28),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (fp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (lr),
#elif defined (HAVE_MIPS)
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (pc),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (gp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (sp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (fp),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (ra),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (hi),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (lo),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (at),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (v0),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (v1),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (a0),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (a1),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (a2),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (a3),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t0),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t1),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t2),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t3),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t4),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t5),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t6),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t7),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t8),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (t9),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (s0),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (s1),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (s2),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (s3),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (s4),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (s5),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (s6),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (s7),

  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (k0),
  GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR (k1),
#endif

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_source_map_functions[] =
{
  { "_resolve", gumjs_source_map_resolve, DUK_VARARGS },

  { NULL, NULL, 0 }
};

void
_gum_duk_core_init (GumDukCore * self,
                    GumDukScript * script,
                    GRecMutex * mutex,
                    const gchar * runtime_source_map,
                    GumDukInterceptor * interceptor,
                    GumDukStalker * stalker,
                    GumDukMessageEmitter message_emitter,
                    GumScriptScheduler * scheduler,
                    duk_context * ctx)
{
  guint i;

  g_object_get (script, "backend", &self->backend, NULL);
  g_object_unref (self->backend);

  self->script = script;
  self->runtime_source_map = runtime_source_map;
  self->interceptor = interceptor;
  self->stalker = stalker;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->heap_ctx = ctx;
  self->current_scope = NULL;

  self->mutex = mutex;
  self->usage_count = 0;
  self->mutex_depth = 0;
  self->heap_thread_in_use = FALSE;
  self->flush_notify = NULL;

  self->event_loop = g_main_loop_new (
      gum_script_scheduler_get_js_context (scheduler), FALSE);
  g_mutex_init (&self->event_mutex);
  g_cond_init (&self->event_cond);
  self->event_count = 0;
  self->event_source_available = TRUE;

  self->weak_refs = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_duk_weak_ref_clear);

  self->scheduled_callbacks = g_hash_table_new (NULL, NULL);
  self->next_callback_id = 1;

  _gum_duk_store_module_data (ctx, "core", self);

  /* set `global` to the global object */
  duk_push_global_object (ctx);
  duk_put_global_string (ctx, "global");

  duk_push_global_object (ctx);
  duk_push_string (ctx, "Promise");
  duk_push_c_function (ctx, gumjs_get_promise, 0);
  duk_def_prop (ctx, -3, DUK_DEFPROP_SET_ENUMERABLE |
      DUK_DEFPROP_SET_CONFIGURABLE | DUK_DEFPROP_HAVE_GETTER);
  duk_pop (ctx);

  duk_push_object (ctx);
  duk_push_string (ctx, FRIDA_VERSION);
  duk_put_prop_string (ctx, -2, "version");
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), gumjs_frida_values);
  duk_put_function_list (ctx, -1, gumjs_frida_functions);
  duk_put_global_string (ctx, "Frida");

  duk_push_object (ctx);
  duk_push_string (ctx, "DUK");
  duk_put_prop_string (ctx, -2, "runtime");
  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), gumjs_script_values);
  duk_put_function_list (ctx, -1, gumjs_script_functions);
  duk_put_global_string (ctx, "Script");

  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_weak_ref_module_functions);
  duk_put_global_string (ctx, "WeakRef");

  duk_push_c_function (ctx, gumjs_weak_ref_construct, 2);
  duk_push_object (ctx);
  duk_push_c_function (ctx, gumjs_weak_ref_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->weak_ref = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  GUMJS_ADD_GLOBAL_FUNCTION ("_setTimeout", gumjs_set_timeout, 2);
  GUMJS_ADD_GLOBAL_FUNCTION ("_setInterval", gumjs_set_interval, 2);
  GUMJS_ADD_GLOBAL_FUNCTION ("clearTimeout", gumjs_clear_timer, 1);
  GUMJS_ADD_GLOBAL_FUNCTION ("clearInterval", gumjs_clear_timer, 1);
  GUMJS_ADD_GLOBAL_FUNCTION ("gc", gumjs_gc, 0);
  GUMJS_ADD_GLOBAL_FUNCTION ("_send", gumjs_send, 2);
  GUMJS_ADD_GLOBAL_FUNCTION ("_setUnhandledExceptionCallback",
      gumjs_set_unhandled_exception_callback, 1);
  GUMJS_ADD_GLOBAL_FUNCTION ("_setIncomingMessageCallback",
      gumjs_set_incoming_message_callback, 1);
  GUMJS_ADD_GLOBAL_FUNCTION ("_waitForEvent", gumjs_wait_for_event, 0);

  duk_push_c_function (ctx, gumjs_int64_construct, 1);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_int64_functions);
  duk_push_c_function (ctx, gumjs_int64_finalize, 2);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->int64 = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "Int64");

  duk_push_c_function (ctx, gumjs_uint64_construct, 1);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_uint64_functions);
  duk_push_c_function (ctx, gumjs_uint64_finalize, 2);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->uint64 = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "UInt64");

  duk_push_c_function (ctx, gumjs_native_pointer_construct, 1);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_native_pointer_functions);
  duk_push_c_function (ctx, gumjs_native_pointer_finalize, 2);
  duk_set_finalizer (ctx, -2);
  self->native_pointer_prototype = _gum_duk_require_heapptr (ctx, -1);
  duk_put_prop_string (ctx, -2, "prototype");
  self->native_pointer = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "NativePointer");

  _gum_duk_create_subclass (ctx, "NativePointer", "NativeResource",
      gumjs_native_resource_construct, 2, gumjs_native_resource_finalize);
  duk_get_global_string (ctx, "NativeResource");
  self->native_resource = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  _gum_duk_create_subclass (ctx, "UInt64", "KernelResource",
      gumjs_kernel_resource_construct, 2, gumjs_kernel_resource_finalize);
  duk_get_global_string (ctx, "KernelResource");
  self->kernel_resource = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  _gum_duk_create_subclass (ctx, "NativePointer", "NativeFunction",
      gumjs_native_function_construct, 4, gumjs_native_function_finalize);
  duk_get_global_string (ctx, "NativeFunction");
  self->native_function = _gum_duk_require_heapptr (ctx, -1);
  duk_get_prop_string (ctx, -1, "prototype");
  duk_put_function_list (ctx, -1, gumjs_native_function_functions);
  self->native_function_prototype = _gum_duk_require_heapptr (ctx, -1);
  duk_pop_2 (ctx);

  _gum_duk_create_subclass (ctx, "NativePointer", "SystemFunction",
      gumjs_system_function_construct, 4, gumjs_system_function_finalize);
  duk_get_global_string (ctx, "SystemFunction");
  self->system_function = _gum_duk_require_heapptr (ctx, -1);
  duk_get_prop_string (ctx, -1, "prototype");
  self->system_function_prototype = _gum_duk_require_heapptr (ctx, -1);
  duk_pop_2 (ctx);

  _gum_duk_create_subclass (ctx, "NativePointer", "NativeCallback",
      gumjs_native_callback_construct, 4, gumjs_native_callback_finalize);

  duk_push_c_function (ctx, gumjs_cpu_context_construct, 0);
  duk_push_object (ctx);
  duk_push_c_function (ctx, gumjs_cpu_context_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->cpu_context = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "CpuContext");
  _gum_duk_add_properties_to_class (ctx, "CpuContext",
      gumjs_cpu_context_values);

  for (i = 0; i != GUM_DUK_NATIVE_POINTER_CACHE_SIZE; i++)
  {
    GumDukNativePointerImpl * ptr;

    duk_push_heapptr (ctx, self->native_pointer);
    duk_push_pointer (ctx, NULL);
    duk_new (ctx, 1);

    ptr = _gum_duk_require_data (ctx, -1);
    ptr->object = duk_require_heapptr (ctx, -1);
    ptr->id = g_strdup_printf ("np%u", i + 1);
    ptr->next = self->cached_native_pointers;
    self->cached_native_pointers = ptr;

    duk_push_global_stash (ctx);
    duk_dup (ctx, -2);
    duk_put_prop_string (ctx, -2, ptr->id);

    duk_pop_2 (ctx);
  }

  duk_push_c_function (ctx, gumjs_source_map_construct, 1);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_source_map_functions);
  duk_push_c_function (ctx, gumjs_source_map_finalize, 2);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->source_map = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "SourceMap");
}

gboolean
_gum_duk_core_flush (GumDukCore * self,
                     GumDukFlushNotify flush_notify)
{
  GHashTableIter iter;
  GumDukScheduledCallback * callback;
  gboolean done;

  self->flush_notify = flush_notify;

  g_mutex_lock (&self->event_mutex);
  self->event_source_available = FALSE;
  g_cond_broadcast (&self->event_cond);
  g_mutex_unlock (&self->event_mutex);
  g_main_loop_quit (self->event_loop);

  if (self->usage_count > 1)
    return FALSE;

  g_hash_table_iter_init (&iter, self->scheduled_callbacks);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &callback))
  {
    _gum_duk_core_pin (self);
    g_source_destroy (callback->source);
  }
  g_hash_table_remove_all (self->scheduled_callbacks);

  if (self->usage_count > 1)
    return FALSE;

  g_hash_table_remove_all (self->weak_refs);

  done = self->usage_count == 1;
  if (done)
    self->flush_notify = NULL;

  return done;
}

static void
gum_duk_core_notify_flushed (GumDukCore * self,
                             GumDukFlushNotify func)
{
  GumDukFlushCallback * callback;
  GSource * source;

  callback = g_slice_new (GumDukFlushCallback);
  callback->func = func;
  callback->script = g_object_ref (self->script);

  source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) gum_duk_flush_callback_notify,
      callback, (GDestroyNotify) gum_duk_flush_callback_free);
  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));
  g_source_unref (source);
}

static void
gum_duk_flush_callback_free (GumDukFlushCallback * self)
{
  g_object_unref (self->script);

  g_slice_free (GumDukFlushCallback, self);
}

static gboolean
gum_duk_flush_callback_notify (GumDukFlushCallback * self)
{
  self->func (self->script);
  return FALSE;
}

void
_gum_duk_core_dispose (GumDukCore * self)
{
  duk_context * ctx = self->current_scope->ctx;

  duk_set_global_access_functions (ctx, NULL);

  _gum_duk_unprotect (ctx, self->on_global_enumerate);
  _gum_duk_unprotect (ctx, self->on_global_get);
  _gum_duk_unprotect (ctx, self->global_receiver);
  self->on_global_enumerate = NULL;
  self->on_global_get = NULL;
  self->global_receiver = NULL;

  g_clear_pointer (&self->unhandled_exception_sink,
      gum_duk_exception_sink_free);

  g_clear_pointer (&self->incoming_message_sink, gum_duk_message_sink_free);

  g_clear_pointer (&self->exceptor, g_object_unref);

  self->cached_native_pointers = NULL;

  _gum_duk_release_heapptr (ctx, self->weak_ref);
  _gum_duk_release_heapptr (ctx, self->int64);
  _gum_duk_release_heapptr (ctx, self->uint64);
  _gum_duk_release_heapptr (ctx, self->native_pointer);
  _gum_duk_release_heapptr (ctx, self->native_pointer_prototype);
  _gum_duk_release_heapptr (ctx, self->native_resource);
  _gum_duk_release_heapptr (ctx, self->native_function);
  _gum_duk_release_heapptr (ctx, self->native_function_prototype);
  _gum_duk_release_heapptr (ctx, self->system_function);
  _gum_duk_release_heapptr (ctx, self->system_function_prototype);
  _gum_duk_release_heapptr (ctx, self->cpu_context);
  _gum_duk_release_heapptr (ctx, self->source_map);
}

void
_gum_duk_core_finalize (GumDukCore * self)
{
  g_hash_table_unref (self->scheduled_callbacks);
  self->scheduled_callbacks = NULL;

  g_hash_table_unref (self->weak_refs);
  self->weak_refs = NULL;

  g_main_loop_unref (self->event_loop);
  self->event_loop = NULL;
  g_mutex_clear (&self->event_mutex);
  g_cond_clear (&self->event_cond);

  g_assert (self->current_scope == NULL);
  self->heap_ctx = NULL;
}

void
_gum_duk_core_pin (GumDukCore * self)
{
  self->usage_count++;
}

void
_gum_duk_core_unpin (GumDukCore * self)
{
  self->usage_count--;
}

void
_gum_duk_core_post (GumDukCore * self,
                    const gchar * message,
                    GBytes * data)
{
  gboolean delivered = FALSE;
  GumDukScope scope;

  _gum_duk_scope_enter (&scope, self);

  if (self->incoming_message_sink != NULL)
  {
    gum_duk_message_sink_post (self->incoming_message_sink, message, data,
        &scope);
    delivered = TRUE;
  }

  _gum_duk_scope_leave (&scope);

  if (delivered)
  {
    g_mutex_lock (&self->event_mutex);
    self->event_count++;
    g_cond_broadcast (&self->event_cond);
    g_mutex_unlock (&self->event_mutex);

    g_main_loop_quit (self->event_loop);
  }
  else
  {
    g_bytes_unref (data);
  }
}

void
_gum_duk_core_push_job (GumDukCore * self,
                        GumScriptJobFunc job_func,
                        gpointer data,
                        GDestroyNotify data_destroy)
{
  gum_script_scheduler_push_job_on_thread_pool (self->scheduler, job_func,
      data, data_destroy);
}

duk_context *
_gum_duk_scope_enter (GumDukScope * self,
                      GumDukCore * core)
{
  duk_context * heap_ctx = core->heap_ctx;

  self->core = core;

  g_rec_mutex_lock (core->mutex);

  gum_interceptor_begin_transaction (core->interceptor->interceptor);

  _gum_duk_core_pin (core);
  core->mutex_depth++;

  if (core->mutex_depth == 1)
  {
    if (!core->heap_thread_in_use)
    {
      core->heap_thread_in_use = TRUE;

      self->ctx = heap_ctx;
    }
    else
    {
      gchar name[32];
      duk_idx_t thread_index;

      sprintf (name, "thread_%p", self);

      thread_index = duk_push_thread (heap_ctx);
      self->ctx = duk_get_context (heap_ctx, thread_index);

      duk_push_global_stash (heap_ctx);
      duk_dup (heap_ctx, -2);
      duk_put_prop_string (heap_ctx, -2, name);

      duk_pop_2 (heap_ctx);
    }

    g_assert (core->current_scope == NULL);
    core->current_scope = self;
  }
  else
  {
    self->ctx = core->current_scope->ctx;
  }

  self->exception = NULL;

  g_queue_init (&self->tick_callbacks);
  g_queue_init (&self->scheduled_sources);

  self->pending_stalker_level = 0;
  self->pending_stalker_transformer = NULL;
  self->pending_stalker_sink = NULL;

  return self->ctx;
}

void
_gum_duk_scope_suspend (GumDukScope * self)
{
  GumDukCore * core = self->core;
  guint i;

  gum_interceptor_end_transaction (core->interceptor->interceptor);

  duk_suspend (self->ctx, &self->thread_state);

  g_assert (core->current_scope != NULL);
  g_assert (core->current_scope->ctx == self->ctx);
  self->previous_scope = g_steal_pointer (&core->current_scope);

  self->previous_mutex_depth = core->mutex_depth;
  core->mutex_depth = 0;

  for (i = 0; i != self->previous_mutex_depth; i++)
    g_rec_mutex_unlock (core->mutex);
}

void
_gum_duk_scope_resume (GumDukScope * self)
{
  GumDukCore * core = self->core;
  guint i;

  for (i = 0; i != self->previous_mutex_depth; i++)
    g_rec_mutex_lock (core->mutex);

  g_assert (core->current_scope == NULL);
  core->current_scope = g_steal_pointer (&self->previous_scope);

  core->mutex_depth = self->previous_mutex_depth;
  self->previous_mutex_depth = 0;

  duk_resume (self->ctx, &self->thread_state);

  gum_interceptor_begin_transaction (core->interceptor->interceptor);
}

gboolean
_gum_duk_scope_call (GumDukScope * self,
                     duk_idx_t nargs)
{
  GumDukCore * core = self->core;
  gboolean success;

  success = duk_pcall (self->ctx, nargs) == 0;
  if (!success)
  {
    if (core->unhandled_exception_sink != NULL)
      gum_duk_exception_sink_handle_exception (core->unhandled_exception_sink);
  }

  return success;
}

gboolean
_gum_duk_scope_call_method (GumDukScope * self,
                            duk_idx_t nargs)
{
  GumDukCore * core = self->core;
  gboolean success;

  success = duk_pcall_method (self->ctx, nargs) == 0;
  if (!success)
  {
    if (core->unhandled_exception_sink != NULL)
      gum_duk_exception_sink_handle_exception (core->unhandled_exception_sink);
  }

  return success;
}

gboolean
_gum_duk_scope_call_sync (GumDukScope * self,
                          duk_idx_t nargs)
{
  gboolean success;

  success = duk_pcall (self->ctx, nargs) == 0;
  if (!success)
  {
    g_assert (self->exception == NULL);
    self->exception = _gum_duk_require_heapptr (self->ctx, -1);
  }

  return success;
}

void
_gum_duk_scope_flush (GumDukScope * self)
{
  duk_context * ctx = self->ctx;

  if (self->exception == NULL)
    return;

  duk_push_heapptr (ctx, self->exception);
  _gum_duk_release_heapptr (ctx, self->exception);
  self->exception = NULL;
  (void) duk_throw (ctx);
}

void
_gum_duk_scope_perform_pending_io (GumDukScope * self)
{
  duk_context * ctx = self->ctx;
  GumDukHeapPtr tick_callback;
  GSource * source;

  while ((tick_callback = g_queue_pop_head (&self->tick_callbacks)) != NULL)
  {
    duk_push_heapptr (ctx, tick_callback);
    _gum_duk_scope_call (self, 0);
    duk_pop (ctx);

    _gum_duk_unprotect (ctx, tick_callback);
  }

  while ((source = g_queue_pop_head (&self->scheduled_sources)) != NULL)
  {
    if (!g_source_is_destroyed (source))
    {
      g_source_attach (source,
          gum_script_scheduler_get_js_context (self->core->scheduler));
    }

    g_source_unref (source);
  }
}

void
_gum_duk_scope_leave (GumDukScope * self)
{
  GumDukCore * core = self->core;
  duk_context * heap_ctx = core->heap_ctx;
  GumDukFlushNotify pending_flush_notify = NULL;

  g_assert (core->current_scope != NULL);
  g_assert (core->current_scope->ctx == self->ctx);

  _gum_duk_scope_perform_pending_io (self);

  if (core->mutex_depth == 1)
  {
    core->current_scope = NULL;

    if (self->ctx == heap_ctx)
    {
      core->heap_thread_in_use = FALSE;
    }
    else
    {
      gchar name[32];

      sprintf (name, "thread_%p", self);

      duk_push_global_stash (heap_ctx);
      duk_del_prop_string (heap_ctx, -1, name);
      duk_pop (heap_ctx);
    }
  }

  core->mutex_depth--;
  _gum_duk_core_unpin (core);

  if (core->flush_notify != NULL && core->usage_count == 0)
  {
    pending_flush_notify = core->flush_notify;
    core->flush_notify = NULL;
  }

  gum_interceptor_end_transaction (self->core->interceptor->interceptor);

  g_rec_mutex_unlock (core->mutex);

  if (pending_flush_notify != NULL)
    gum_duk_core_notify_flushed (core, pending_flush_notify);

  _gum_duk_stalker_process_pending (core->stalker, self);
}

GUMJS_DEFINE_GETTER (gumjs_get_promise)
{
  duk_push_global_object (ctx);

  duk_del_prop_string (ctx, -1, "Promise");

  gum_duk_bundle_load (gumjs_promise_modules, ctx);

  duk_get_prop_string (ctx, -1, "Frida");
  duk_get_prop_string (ctx, -1, "_promise");

  duk_push_string (ctx, "Promise");
  duk_dup (ctx, -2);
  duk_def_prop (ctx, -5, DUK_DEFPROP_SET_ENUMERABLE |
      DUK_DEFPROP_SET_CONFIGURABLE | DUK_DEFPROP_HAVE_VALUE);

  duk_swap_top (ctx, -3);
  duk_pop_2 (ctx);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_frida_get_heap_size)
{
  duk_push_uint (ctx, gum_peek_private_memory_usage ());
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_frida_get_source_map)
{
  GumDukCore * self = args->core;

  duk_push_heapptr (ctx, self->source_map);
  duk_push_string (ctx, self->runtime_source_map);
  duk_new (ctx, 1);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_frida_objc_get_source_map)
{
  duk_push_heapptr (ctx, args->core->source_map);
  duk_push_string (ctx, gumjs_objc_source_map);
  duk_new (ctx, 1);
  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_frida_java_get_source_map)
{
  duk_push_heapptr (ctx, args->core->source_map);
  duk_push_string (ctx, gumjs_java_source_map);
  duk_new (ctx, 1);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_objc_load)
{
  gum_duk_bundle_load (gumjs_objc_modules, ctx);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_java_load)
{
  gum_duk_bundle_load (gumjs_java_modules, ctx);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_script_get_file_name)
{
  gchar * name, * file_name;

  g_object_get (args->core->script, "name", &name, NULL);
  file_name = g_strconcat ("/", name, ".js", NULL);
  duk_push_string (ctx, file_name);
  g_free (file_name);
  g_free (name);

  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_script_get_source_map)
{
  GumDukCore * self = args->core;
  gchar * source;
  GRegex * regex;
  GMatchInfo * match_info;

  g_object_get (self->script, "source", &source, NULL);

  if (source == NULL)
  {
    duk_push_null (ctx);
    return 1;
  }

  regex = g_regex_new ("//[#@][ \t]sourceMappingURL=[ \t]*"
      "data:application/json;.*?base64,([^\\s\'\"]*)[ \t]*$", 0, 0, NULL);
  g_regex_match (regex, source, 0, &match_info);
  if (g_match_info_matches (match_info))
  {
    gchar * data_encoded;
    gsize size;
    gchar * data;

    data_encoded = g_match_info_fetch (match_info, 1);

    data = (gchar *) g_base64_decode (data_encoded, &size);
    if (data != NULL && g_utf8_validate (data, size, NULL))
    {
      gchar * data_utf8;

      duk_push_heapptr (ctx, self->source_map);
      data_utf8 = g_strndup (data, size);
      duk_push_string (ctx, data_utf8);
      g_free (data_utf8);
      duk_new (ctx, 1);
    }
    else
    {
      duk_push_null (ctx);
    }
    g_free (data);

    g_free (data_encoded);
  }
  else
  {
    duk_push_null (ctx);
  }
  g_match_info_free (match_info);
  g_regex_unref (regex);

  g_free (source);

  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_next_tick)
{
  GumDukHeapPtr callback;

  _gum_duk_args_parse (args, "F", &callback);

  _gum_duk_protect (ctx, callback);
  g_queue_push_tail (&args->core->current_scope->tick_callbacks, callback);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_pin)
{
  _gum_duk_core_pin (args->core);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_unpin)
{
  _gum_duk_core_unpin (args->core);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_set_global_access_handler)
{
  GumDukCore * self = args->core;
  GumDukHeapPtr receiver, enumerate, get;

  if (!duk_is_null (ctx, 0))
  {
    receiver = duk_get_heapptr (ctx, 0);
    _gum_duk_args_parse (args, "F{enumerate,get}", &enumerate, &get);
  }
  else
  {
    receiver = NULL;
    enumerate = NULL;
    get = NULL;
  }

  if (receiver == NULL)
    duk_set_global_access_functions (ctx, NULL);

  _gum_duk_unprotect (ctx, self->on_global_enumerate);
  _gum_duk_unprotect (ctx, self->on_global_get);
  _gum_duk_unprotect (ctx, self->global_receiver);
  self->on_global_enumerate = NULL;
  self->on_global_get = NULL;
  self->global_receiver = NULL;

  if (receiver != NULL)
  {
    duk_global_access_functions funcs;

    _gum_duk_protect (ctx, enumerate);
    _gum_duk_protect (ctx, get);
    _gum_duk_protect (ctx, receiver);
    self->on_global_enumerate = enumerate;
    self->on_global_get = get;
    self->global_receiver = receiver;

    funcs.enumerate_func = gum_duk_core_on_global_enumerate;
    funcs.get_func = gum_duk_core_on_global_get;
    funcs.udata = self;
    duk_set_global_access_functions (ctx, &funcs);
  }

  return 0;
}

static int
gum_duk_core_on_global_enumerate (duk_context * ctx,
                                  void * udata)
{
  GumDukCore * self = udata;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self);
  int result;

  duk_push_heapptr (ctx, self->on_global_enumerate);
  duk_push_heapptr (ctx, self->global_receiver);
  _gum_duk_scope_call_method (&scope, 0);
  if (duk_is_array (ctx, -1))
  {
    result = 1;
  }
  else
  {
    result = 0;
    duk_pop (ctx);
  }

  return result;
}

static int
gum_duk_core_on_global_get (duk_context * ctx,
                            const char * name,
                            void * udata)
{
  GumDukCore * self = udata;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self);
  int result;

  duk_push_heapptr (ctx, self->on_global_get);
  duk_push_heapptr (ctx, self->global_receiver);
  duk_push_string (ctx, name);
  _gum_duk_scope_call_method (&scope, 1);
  if (!duk_is_undefined (ctx, -1))
  {
    result = 1;
  }
  else
  {
    result = 0;
    duk_pop (ctx);
  }

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_bind)
{
  GumDukCore * core = args->core;
  GumDukHeapPtr target;
  GumDukHeapPtr callback;
  gboolean target_is_valid;
  guint id;
  gchar prop_name[1 + 2 + 8 + 1];
  GumDukWeakRef * ref;

  _gum_duk_args_parse (args, "VF", &target, &callback);

  duk_push_heapptr (ctx, target);
  target_is_valid = !duk_is_null (ctx, -1) && duk_is_object (ctx, -1);
  if (!target_is_valid)
    _gum_duk_throw (ctx, "expected a heap value");

  id = ++core->last_weak_ref_id;

  ref = gum_duk_weak_ref_new (id, callback, core);
  g_hash_table_insert (core->weak_refs, GUINT_TO_POINTER (id), ref);

  duk_push_heapptr (ctx, core->weak_ref);
  duk_new (ctx, 0);

  _gum_duk_put_data (ctx, -1, ref);

  sprintf (prop_name, "\xffwr%x", id);
  duk_put_prop_string (ctx, -2, prop_name);

  duk_pop (ctx);

  duk_push_int (ctx, id);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_unbind)
{
  guint id;
  gboolean removed;

  _gum_duk_args_parse (args, "u", &id);

  removed = !g_hash_table_remove (args->core->weak_refs, GUINT_TO_POINTER (id));

  duk_push_boolean (ctx, removed);
  return 1;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_weak_ref_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_weak_ref_finalize)
{
  GumDukWeakRef * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  if (self->core != NULL)
  {
    g_hash_table_remove (self->core->weak_refs, GUINT_TO_POINTER (self->id));
  }

  g_slice_free (GumDukWeakRef, self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_timeout)
{
  GumDukCore * self = args->core;

  return gum_duk_core_schedule_callback (self, args, FALSE);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_interval)
{
  GumDukCore * self = args->core;

  return gum_duk_core_schedule_callback (self, args, TRUE);
}

GUMJS_DEFINE_FUNCTION (gumjs_clear_timer)
{
  GumDukCore * self = args->core;
  gint id;
  GumDukScheduledCallback * callback;

  if (!duk_is_number (ctx, 0))
    goto invalid_handle;

  _gum_duk_args_parse (args, "i", &id);

  callback = gum_duk_core_try_steal_scheduled_callback (self, id);
  if (callback != NULL)
  {
    _gum_duk_core_pin (self);
    g_source_destroy (callback->source);
  }

  duk_push_boolean (ctx, callback != NULL);
  return 1;

invalid_handle:
  {
    duk_push_boolean (ctx, FALSE);
    return 1;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_gc)
{
  duk_gc (ctx, 0);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_send)
{
  GumDukCore * self = args->core;
  GumInterceptor * interceptor = self->interceptor->interceptor;
  const gchar * message;
  GBytes * data;

  _gum_duk_args_parse (args, "sB?", &message, &data);

  /*
   * Synchronize Interceptor state before sending the message. The application
   * might be waiting for an acknowledgement that APIs have been instrumented.
   *
   * This is very important for the RPC API.
   */
  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_begin_transaction (interceptor);

  self->message_emitter (self->script, message, data);

  g_bytes_unref (data);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  GumDukCore * self = args->core;
  GumDukHeapPtr callback;
  GumDukExceptionSink * new_sink, * old_sink;

  _gum_duk_args_parse (args, "F?", &callback);

  new_sink = (callback != NULL)
      ? gum_duk_exception_sink_new (callback, self)
      : NULL;

  old_sink = self->unhandled_exception_sink;
  self->unhandled_exception_sink = new_sink;

  if (old_sink != NULL)
    gum_duk_exception_sink_free (old_sink);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_incoming_message_callback)
{
  GumDukCore * self = args->core;
  GumDukHeapPtr callback;
  GumDukMessageSink * new_sink, * old_sink;

  _gum_duk_args_parse (args, "F?", &callback);

  new_sink = (callback != NULL)
      ? gum_duk_message_sink_new (callback, self)
      : NULL;

  old_sink = self->incoming_message_sink;
  self->incoming_message_sink = new_sink;

  if (old_sink != NULL)
    gum_duk_message_sink_free (old_sink);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_wait_for_event)
{
  GumDukCore * self = args->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self);
  GMainContext * context;
  gboolean called_from_js_thread;
  guint start_count;
  gboolean event_source_available;

  _gum_duk_scope_perform_pending_io (self->current_scope);

  _gum_duk_scope_suspend (&scope);

  context = gum_script_scheduler_get_js_context (self->scheduler);
  called_from_js_thread = g_main_context_is_owner (context);

  g_mutex_lock (&self->event_mutex);

  start_count = self->event_count;
  while (self->event_count == start_count && self->event_source_available)
  {
    if (called_from_js_thread)
    {
      g_mutex_unlock (&self->event_mutex);
      g_main_loop_run (self->event_loop);
      g_mutex_lock (&self->event_mutex);
    }
    else
    {
      g_cond_wait (&self->event_cond, &self->event_mutex);
    }
  }

  event_source_available = self->event_source_available;

  g_mutex_unlock (&self->event_mutex);

  _gum_duk_scope_resume (&scope);

  if (!event_source_available)
    _gum_duk_throw (ctx, "script is unloading");

  return 0;
}

static gint64
gumjs_int64_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  gint64 value;

  duk_push_this (ctx);
  value = _gum_duk_require_int64 (ctx, -1, args->core);
  duk_pop (ctx);

  return value;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_int64_construct)
{
  gint64 value;
  GumDukInt64 * self;

  if (!duk_is_constructor_call (ctx))
  {
    _gum_duk_throw (ctx, "use `new Int64()` to create a new instance, "
        "or use the shorthand: `int64()`");
  }

  _gum_duk_args_parse (args, "q~", &value);

  self = g_slice_new (GumDukInt64);
  self->value = value;

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, self);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_int64_finalize)
{
  GumDukInt64 * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumDukInt64, self);

  return 0;
}

#define GUM_DEFINE_INT64_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_int64_##name) \
  { \
    gint64 lhs, rhs, result; \
    \
    lhs = gumjs_int64_from_args (args); \
    \
    _gum_duk_args_parse (args, "q~", &rhs); \
    \
    result = lhs op rhs; \
    \
    _gum_duk_push_int64 (ctx, result, args->core); \
    return 1; \
  }

GUM_DEFINE_INT64_OP_IMPL (add, +)
GUM_DEFINE_INT64_OP_IMPL (sub, -)
GUM_DEFINE_INT64_OP_IMPL (and, &)
GUM_DEFINE_INT64_OP_IMPL (or,  |)
GUM_DEFINE_INT64_OP_IMPL (xor, ^)
GUM_DEFINE_INT64_OP_IMPL (shr, >>)
GUM_DEFINE_INT64_OP_IMPL (shl, <<)

#define GUM_DEFINE_INT64_UNARY_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_int64_##name) \
  { \
    gint64 value, result; \
    \
    value = gumjs_int64_from_args (args); \
    \
    result = op value; \
    \
    _gum_duk_push_int64 (ctx, result, args->core); \
    return 1; \
  }

GUM_DEFINE_INT64_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_int64_compare)
{
  gint64 lhs, rhs;
  gint result;

  lhs = gumjs_int64_from_args (args);

  _gum_duk_args_parse (args, "q~", &rhs);

  result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  duk_push_int (ctx, result);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_to_number)
{
  duk_push_number (ctx, gumjs_int64_from_args (args));
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_to_string)
{
  gint64 value;
  gint radix;
  gchar str[32];

  value = gumjs_int64_from_args (args);

  radix = 10;
  _gum_duk_args_parse (args, "|u", &radix);
  if (radix != 10 && radix != 16)
    _gum_duk_throw (ctx, "unsupported radix");

  if (radix == 10)
    sprintf (str, "%" G_GINT64_FORMAT, value);
  else if (value >= 0)
    sprintf (str, "%" G_GINT64_MODIFIER "x", value);
  else
    sprintf (str, "-%" G_GINT64_MODIFIER "x", -value);

  duk_push_string (ctx, str);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_to_json)
{
  gchar str[32];

  sprintf (str, "%" G_GINT64_FORMAT, gumjs_int64_from_args (args));

  duk_push_string (ctx, str);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_value_of)
{
  duk_push_number (ctx, gumjs_int64_from_args (args));
  return 1;
}

static guint64
gumjs_uint64_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  guint64 value;

  duk_push_this (ctx);
  value = _gum_duk_require_uint64 (ctx, -1, args->core);
  duk_pop (ctx);

  return value;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_uint64_construct)
{
  guint64 value;
  GumDukUInt64 * self;

  if (!duk_is_constructor_call (ctx))
  {
    _gum_duk_throw (ctx, "use `new UInt64()` to create a new instance, "
        "or use the shorthand: `uint64()`");
  }

  _gum_duk_args_parse (args, "Q~", &value);

  self = g_slice_new (GumDukUInt64);
  self->value = value;

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, self);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_uint64_finalize)
{
  GumDukUInt64 * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumDukUInt64, self);

  return 0;
}

#define GUM_DEFINE_UINT64_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_uint64_##name) \
  { \
    guint64 lhs, rhs, result; \
    \
    lhs = gumjs_uint64_from_args (args); \
    \
    _gum_duk_args_parse (args, "Q~", &rhs); \
    \
    result = lhs op rhs; \
    \
    _gum_duk_push_uint64 (ctx, result, args->core); \
    return 1; \
  }

GUM_DEFINE_UINT64_OP_IMPL (add, +)
GUM_DEFINE_UINT64_OP_IMPL (sub, -)
GUM_DEFINE_UINT64_OP_IMPL (and, &)
GUM_DEFINE_UINT64_OP_IMPL (or,  |)
GUM_DEFINE_UINT64_OP_IMPL (xor, ^)
GUM_DEFINE_UINT64_OP_IMPL (shr, >>)
GUM_DEFINE_UINT64_OP_IMPL (shl, <<)

#define GUM_DEFINE_UINT64_UNARY_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_uint64_##name) \
  { \
    guint64 value, result; \
    \
    value = gumjs_uint64_from_args (args); \
    \
    result = op value; \
    \
    _gum_duk_push_uint64 (ctx, result, args->core); \
    return 1; \
  }

GUM_DEFINE_UINT64_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_uint64_compare)
{
  guint64 lhs, rhs;
  gint result;

  lhs = gumjs_uint64_from_args (args);

  _gum_duk_args_parse (args, "Q~", &rhs);

  result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  duk_push_int (ctx, result);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_number)
{
  duk_push_number (ctx, gumjs_uint64_from_args (args));
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_string)
{
  guint64 value;
  gint radix;
  gchar str[32];

  value = gumjs_uint64_from_args (args);

  radix = 10;
  _gum_duk_args_parse (args, "|u", &radix);
  if (radix != 10 && radix != 16)
    _gum_duk_throw (ctx, "unsupported radix");

  if (radix == 10)
    sprintf (str, "%" G_GUINT64_FORMAT, value);
  else
    sprintf (str, "%" G_GINT64_MODIFIER "x", value);

  duk_push_string (ctx, str);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_json)
{
  gchar str[32];

  sprintf (str, "%" G_GUINT64_FORMAT, gumjs_uint64_from_args (args));

  duk_push_string (ctx, str);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_value_of)
{
  duk_push_number (ctx, gumjs_uint64_from_args (args));
  return 1;
}

static GumDukNativePointer *
gumjs_native_pointer_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukNativePointer * self;

  duk_push_this (ctx);
  self = _gum_duk_require_native_pointer (ctx, -1, args->core);
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_pointer_construct)
{
  gpointer ptr = NULL;
  GumDukNativePointerImpl * self;

  if (!duk_is_constructor_call (ctx))
  {
    _gum_duk_throw (ctx, "use `new NativePointer()` to create a new instance, "
        "or use one of the two shorthands: `ptr()` and `NULL`");
  }

  _gum_duk_args_parse (args, "p~", &ptr);

  self = g_slice_new0 (GumDukNativePointerImpl);
  self->parent.value = ptr;

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, self);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_native_pointer_finalize)
{
  GumDukCore * core = args->core;
  GumDukNativePointerImpl * self;
  gboolean heap_destruct;

  duk_push_heapptr (ctx, core->native_pointer_prototype);
  if (duk_equals (ctx, 0, -1))
  {
    duk_pop (ctx);
    return 0;
  }
  duk_pop (ctx);

  heap_destruct = duk_require_boolean (ctx, 1);
  if (!heap_destruct)
  {
    self = _gum_duk_get_data (ctx, 0);
    if (self == NULL)
      return 0;

    if (self->id != NULL)
    {
      self->next = core->cached_native_pointers;
      core->cached_native_pointers = self;

      duk_push_global_stash (ctx);
      duk_dup (ctx, 0);
      duk_put_prop_string (ctx, -2, self->id);
      duk_pop (ctx);

      return 0;
    }
  }

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_free (self->id);

  g_slice_free (GumDukNativePointerImpl, self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_is_null)
{
  GumDukNativePointer * self = gumjs_native_pointer_from_args (args);

  duk_push_boolean (ctx, self->value == NULL);
  return 1;
}

#define GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
  { \
    GumDukNativePointer * self; \
    gpointer rhs_ptr; \
    gsize lhs, rhs; \
    gpointer result; \
    \
    self = gumjs_native_pointer_from_args (args); \
    \
    _gum_duk_args_parse (args, "p~", &rhs_ptr); \
    \
    lhs = GPOINTER_TO_SIZE (self->value); \
    rhs = GPOINTER_TO_SIZE (rhs_ptr); \
    \
    result = GSIZE_TO_POINTER (lhs op rhs); \
    \
    _gum_duk_push_native_pointer (ctx, result, args->core); \
    return 1; \
  }

GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (add, +)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (sub, -)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (and, &)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (or,  |)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (xor, ^)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (shr, >>)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (shl, <<)

#define GUM_DEFINE_NATIVE_POINTER_UNARY_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
  { \
    GumDukNativePointer * self; \
    gpointer result; \
    \
    self = gumjs_native_pointer_from_args (args); \
    \
    result = GSIZE_TO_POINTER (op GPOINTER_TO_SIZE (self->value)); \
    \
    _gum_duk_push_native_pointer (ctx, result, args->core); \
    return 1; \
  }

GUM_DEFINE_NATIVE_POINTER_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_compare)
{
  GumDukNativePointer * self;
  gpointer rhs_ptr;
  gsize lhs, rhs;
  gint result;

  self = gumjs_native_pointer_from_args (args);

  _gum_duk_args_parse (args, "p~", &rhs_ptr);

  lhs = GPOINTER_TO_SIZE (self->value);
  rhs = GPOINTER_TO_SIZE (rhs_ptr);

  result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  duk_push_int (ctx, result);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_int32)
{
  GumDukNativePointer * self;
  gint32 result;

  self = gumjs_native_pointer_from_args (args);

  result = (gint32) GPOINTER_TO_SIZE (self->value);

  duk_push_int (ctx, result);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_uint32)
{
  GumDukNativePointer * self;
  guint32 result;

  self = gumjs_native_pointer_from_args (args);

  result = (guint32) GPOINTER_TO_SIZE (self->value);

  duk_push_uint (ctx, result);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_string)
{
  GumDukNativePointer * self;
  gint radix = 0;
  gboolean radix_specified;
  gsize ptr;
  gchar str[32];

  self = gumjs_native_pointer_from_args (args);

  _gum_duk_args_parse (args, "|u", &radix);

  radix_specified = radix != 0;
  if (!radix_specified)
    radix = 16;
  else if (radix != 10 && radix != 16)
    _gum_duk_throw (ctx, "unsupported radix");

  ptr = GPOINTER_TO_SIZE (self->value);

  if (radix == 10)
  {
    sprintf (str, "%" G_GSIZE_MODIFIER "u", ptr);
  }
  else
  {
    if (radix_specified)
      sprintf (str, "%" G_GSIZE_MODIFIER "x", ptr);
    else
      sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr);
  }

  duk_push_string (ctx, str);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_json)
{
  GumDukNativePointer * self;
  gchar str[32];

  self = gumjs_native_pointer_from_args (args);

  sprintf (str, "0x%" G_GSIZE_MODIFIER "x", GPOINTER_TO_SIZE (self->value));

  duk_push_string (ctx, str);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_match_pattern)
{
  GumDukNativePointer * self;
  gsize ptr;
  gchar str[24];
  gint src, dst;
  const gint num_bits = GLIB_SIZEOF_VOID_P * 8;
  const gchar nibble_to_char[] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f'
  };

  self = gumjs_native_pointer_from_args (args);

  ptr = GPOINTER_TO_SIZE (self->value);

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  for (src = 0, dst = 0; src != num_bits; src += 8)
#else
  for (src = num_bits - 8, dst = 0; src >= 0; src -= 8)
#endif
  {
    if (dst != 0)
      str[dst++] = ' ';
    str[dst++] = nibble_to_char[(ptr >> (src + 4)) & 0xf];
    str[dst++] = nibble_to_char[(ptr >> (src + 0)) & 0xf];
  }
  str[dst] = '\0';

  duk_push_string (ctx, str);
  return 1;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_resource_construct)
{
  gpointer data;
  GDestroyNotify notify;
  GumDukNativeResource * resource;
  GumDukNativePointer * ptr;

  data = duk_require_pointer (ctx, 0);
  notify = GUM_POINTER_TO_FUNCPTR (GDestroyNotify,
      duk_require_pointer (ctx, 1));

  resource = g_slice_new (GumDukNativeResource);
  ptr = &resource->parent;
  ptr->value = data;
  resource->notify = notify;

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, resource);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_native_resource_finalize)
{
  GumDukNativeResource * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  if (self->notify != NULL)
    self->notify (self->parent.value);

  g_slice_free (GumDukNativeResource, self);

  return 0;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_kernel_resource_construct)
{
  GumDukCore * core = args->core;
  guint64 data;
  GumDukKernelNotify notify;
  GumDukKernelResource * resource;
  GumDukUInt64 * u64;

  data = _gum_duk_require_uint64 (ctx, 0, core);
  notify = GUM_POINTER_TO_FUNCPTR (GumDukKernelNotify,
      duk_require_pointer (ctx, 1));

  resource = g_slice_new (GumDukKernelResource);
  u64 = &resource->parent;
  u64->value = data;
  resource->notify = notify;

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, resource);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_kernel_resource_finalize)
{
  GumDukKernelResource * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  if (self->notify != NULL)
    self->notify (self->parent.value);

  g_slice_free (GumDukKernelResource, self);

  return 0;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_function_construct)
{
  GumDukCore * core = args->core;
  GumDukNativeFunctionParams params;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use `new NativeFunction()` to create a new instance");

  gum_duk_native_function_params_init (&params, core->native_function_prototype,
      GUM_DUK_RETURN_PLAIN, args);

  return gumjs_native_function_init (ctx, &params, core);
}

GUMJS_DEFINE_FINALIZER (gumjs_native_function_finalize)
{
  GumDukNativeFunction * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  gum_duk_native_function_finalize (self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_invoke)
{
  GumDukNativeFunction * self;
  duk_size_t argc;
  duk_idx_t argv_index;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);

  argc = args->count;
  argv_index = 0;

  return gum_duk_native_function_invoke (self, ctx, self->implementation, argc,
      argv_index);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_call)
{
  GumDukHeapPtr receiver;
  GumDukNativeFunction * func;
  GCallback implementation;
  duk_size_t argc;
  duk_idx_t argv_index;

  if (args->count == 0 || duk_is_undefined (ctx, 0) || duk_is_null (ctx, 0))
  {
    receiver = NULL;
  }
  else if (duk_is_object (ctx, 0))
  {
    receiver = duk_require_heapptr (ctx, 0);
  }
  else
  {
    _gum_duk_throw (ctx, "invalid receiver");
    return 0;
  }

  gumjs_native_function_get (ctx, receiver, args->core, &func, &implementation);

  argc = args->count - 1;
  argv_index = 1;

  return gum_duk_native_function_invoke (func, ctx, implementation, argc,
      argv_index);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_apply)
{
  GumDukHeapPtr receiver;
  const duk_idx_t argv_array_index = 1;
  GumDukNativeFunction * func;
  GCallback implementation;
  duk_size_t argc, i;
  duk_idx_t argv_index;

  if (args->count < 2)
    _gum_duk_throw (ctx, "missing argument");

  if (duk_is_undefined (ctx, 0) || duk_is_null (ctx, 0))
  {
    receiver = NULL;
  }
  else if (duk_is_object (ctx, 0))
  {
    receiver = duk_require_heapptr (ctx, 0);
  }
  else
  {
    _gum_duk_throw (ctx, "invalid receiver");
    return 0;
  }

  if (!duk_is_array (ctx, 1))
    _gum_duk_throw (ctx, "expected an array");

  gumjs_native_function_get (ctx, receiver, args->core, &func, &implementation);

  argc = duk_get_length (ctx, argv_array_index);
  argv_index = duk_get_top_index (ctx) + 1;
  for (i = 0; i != argc; i++)
  {
    duk_get_prop_index (ctx, argv_array_index, (duk_uarridx_t) i);
  }

  return gum_duk_native_function_invoke (func, ctx, implementation, argc,
      argv_index);
}

static void
gumjs_native_function_get (duk_context * ctx,
                           GumDukHeapPtr receiver,
                           GumDukCore * core,
                           GumDukNativeFunction ** func,
                           GCallback * implementation)
{
  GumDukNativeFunction * f;

  duk_push_heapptr (ctx, core->native_function);
  duk_push_this (ctx);

  if (duk_instanceof (ctx, -1, -2))
  {
    f = _gum_duk_require_data (ctx, -1);

    *func = f;

    if (receiver != NULL)
    {
      duk_push_heapptr (ctx, receiver);
      *implementation = GUM_POINTER_TO_FUNCPTR (GCallback,
          _gum_duk_require_pointer (ctx, -1, core));

      duk_pop_3 (ctx);
    }
    else
    {
      *implementation = f->implementation;

      duk_pop_2 (ctx);
    }
  }
  else
  {
    if (receiver == NULL)
      _gum_duk_throw (ctx, "expected a NativeFunction");
    duk_push_heapptr (ctx, receiver);
    if (!duk_instanceof (ctx, -1, -3))
      _gum_duk_throw (ctx, "expected a NativeFunction");

    f = _gum_duk_require_data (ctx, -1);

    *func = f;
    *implementation = f->implementation;

    duk_pop_3 (ctx);
  }
}

static int
gumjs_native_function_init (duk_context * ctx,
                            const GumDukNativeFunctionParams * params,
                            GumDukCore * core)
{
  GumDukNativeFunction * func;
  GumDukNativePointer * ptr;
  ffi_type * rtype;
  duk_size_t nargs_fixed, nargs_total, length, i;
  gboolean is_variadic;
  ffi_abi abi;

  func = g_slice_new0 (GumDukNativeFunction);
  ptr = &func->parent;
  ptr->value = GUM_FUNCPTR_TO_POINTER (params->implementation);
  func->implementation = params->implementation;
  func->scheduling = params->scheduling;
  func->exceptions = params->exceptions;
  func->return_shape = params->return_shape;
  func->core = core;

  if (!gum_duk_get_ffi_type (ctx, params->return_type, &rtype, &func->data))
    goto invalid_return_type;

  duk_push_heapptr (ctx, params->argument_types);

  length = duk_get_length (ctx, -1);
  nargs_fixed = nargs_total = length;
  is_variadic = FALSE;

  func->atypes = g_new (ffi_type *, nargs_total);

  for (i = 0; i != nargs_total; i++)
  {
    gboolean is_marker;

    duk_get_prop_index (ctx, -1, (duk_uarridx_t) i);

    if (duk_is_string (ctx, -1))
      is_marker = strcmp (duk_require_string (ctx, -1), "...") == 0;
    else
      is_marker = FALSE;

    if (is_marker)
    {
      if (i == 0 || is_variadic)
        goto unexpected_marker;

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else
    {
      GumDukHeapPtr atype_value;
      ffi_type ** atype;

      atype_value = duk_get_heapptr (ctx, -1);
      atype = &func->atypes[is_variadic ? i - 1 : i];

      if (!gum_duk_get_ffi_type (ctx, atype_value, atype, &func->data))
        goto invalid_argument_type;

      if (is_variadic && *atype == &ffi_type_float)
      {
        /* Must be promoted to double in the variadic portion. */
        *atype = &ffi_type_double;
      }
    }

    duk_pop (ctx);
  }

  duk_pop (ctx);

  if (is_variadic)
    nargs_total--;

  if (params->abi_name != NULL)
  {
    if (!gum_duk_get_ffi_abi (ctx, params->abi_name, &abi))
      goto invalid_abi;
  }
  else
  {
    abi = FFI_DEFAULT_ABI;
  }

  if (is_variadic)
  {
    if (ffi_prep_cif_var (&func->cif, abi, (guint) nargs_fixed,
        (guint) nargs_total, rtype, func->atypes) != FFI_OK)
      goto compilation_failed;
  }
  else
  {
    if (ffi_prep_cif (&func->cif, abi, (guint) nargs_total, rtype,
        func->atypes) != FFI_OK)
      goto compilation_failed;
  }

  func->is_variadic = nargs_fixed < nargs_total;
  func->nargs_fixed = nargs_fixed;
  func->abi = abi;

  for (i = 0; i != nargs_total; i++)
  {
    ffi_type * t = func->atypes[i];

    func->arglist_size = GUM_ALIGN_SIZE (func->arglist_size, t->alignment);
    func->arglist_size += t->size;
  }

  duk_push_c_function (ctx, gumjs_native_function_invoke, DUK_VARARGS);

  _gum_duk_put_data (ctx, -1, func);

  /* bound_func = func.bind(func); */
  duk_push_string (ctx, "bind");
  duk_dup (ctx, -2);
  duk_call_prop (ctx, -3, 1);
  duk_swap (ctx, -2, -1);
  duk_pop (ctx);

  /* `bound_func instanceof NativeFunction` should be true */
  duk_push_heapptr (ctx, params->prototype);
  duk_set_prototype (ctx, -2);

  /* `bound_func` needs the private data to be used as a NativePointer */
  _gum_duk_put_data (ctx, -1, func);

  /* we ignore `this` and return `bound_func` instead */
  return 1;

invalid_return_type:
  {
    gum_duk_native_function_finalize (func);
    _gum_duk_throw (ctx, "invalid return type");
  }
invalid_argument_type:
  {
    gum_duk_native_function_finalize (func);
    _gum_duk_throw (ctx, "invalid argument type");
  }
invalid_abi:
  {
    gum_duk_native_function_finalize (func);
    _gum_duk_throw (ctx, "invalid abi");
  }
unexpected_marker:
  {
    gum_duk_native_function_finalize (func);
    _gum_duk_throw (ctx, "only one variadic marker may be specified, and can "
        "not be the first argument");
  }
compilation_failed:
  {
    gum_duk_native_function_finalize (func);
    _gum_duk_throw (ctx, "failed to compile function call interface");
  }

  g_assert_not_reached ();
  return 0;
}

static void
gum_duk_native_function_finalize (GumDukNativeFunction * func)
{
  while (func->data != NULL)
  {
    GSList * head = func->data;
    g_free (head->data);
    func->data = g_slist_delete_link (func->data, head);
  }
  g_free (func->atypes);

  g_slice_free (GumDukNativeFunction, func);
}

static int
gum_duk_native_function_invoke (GumDukNativeFunction * self,
                                duk_context * ctx,
                                GCallback implementation,
                                duk_size_t argc,
                                duk_idx_t argv_index)
{
  GumDukCore * core;
  ffi_cif * cif;
  gsize nargs, nargs_fixed;
  gboolean is_variadic;
  ffi_type * rtype;
  ffi_type ** atypes;
  gsize rsize, ralign;
  GumFFIValue * rvalue;
  void ** avalue;
  guint8 * avalues;
  ffi_cif tmp_cif;
  GumFFIValue tmp_value = { 0, };
  GumDukSchedulingBehavior scheduling;
  GumDukExceptionsBehavior exceptions;
  GumDukReturnValueShape return_shape;
  GumExceptorScope exceptor_scope;
  gint system_error;

  core = self->core;
  cif = &self->cif;
  nargs = cif->nargs;
  nargs_fixed = self->nargs_fixed;
  is_variadic = self->is_variadic;

  if ((is_variadic && argc < nargs_fixed) || (!is_variadic && argc != nargs))
    _gum_duk_throw (ctx, "bad argument count");

  rtype = cif->rtype;
  atypes = cif->arg_types;
  rsize = MAX (rtype->size, sizeof (gsize));
  ralign = MAX (rtype->alignment, sizeof (gsize));
  rvalue = g_alloca (rsize + ralign - 1);
  rvalue = GUM_ALIGN_POINTER (GumFFIValue *, rvalue, ralign);

  if (argc > 0)
  {
    gsize arglist_size, arglist_alignment, offset, i;

    avalue = g_alloca (MAX (nargs, argc) * sizeof (void *));

    arglist_size = self->arglist_size;
    if (is_variadic && argc > nargs)
    {
      gsize type_idx;

      atypes = g_newa (ffi_type *, argc);

      memcpy (atypes, cif->arg_types, nargs * sizeof (void *));
      for (i = nargs, type_idx = nargs_fixed; i != argc; i++)
      {
        ffi_type * t = cif->arg_types[type_idx];

        atypes[i] = t;
        arglist_size = GUM_ALIGN_SIZE (arglist_size, t->alignment);
        arglist_size += t->size;

        if (++type_idx >= nargs)
          type_idx = nargs_fixed;
      }

      cif = &tmp_cif;
      if (ffi_prep_cif_var (cif, self->abi, (guint) nargs_fixed,
          (guint) argc, rtype, atypes) != FFI_OK)
      {
        _gum_duk_throw (ctx, "failed to compile function call interface");
      }
    }

    arglist_alignment = atypes[0]->alignment;
    avalues = g_alloca (arglist_size + arglist_alignment - 1);
    avalues = GUM_ALIGN_POINTER (guint8 *, avalues, arglist_alignment);

    /* Prefill with zero to clear high bits of values smaller than a pointer. */
    memset (avalues, 0, arglist_size);

    offset = 0;
    for (i = 0; i != argc; i++)
    {
      ffi_type * t;
      GumFFIValue * v;

      t = atypes[i];
      offset = GUM_ALIGN_SIZE (offset, t->alignment);
      v = (GumFFIValue *) (avalues + offset);

      if (!gum_duk_get_ffi_value (ctx, argv_index + i, t, core, v))
        _gum_duk_throw (ctx, "invalid argument value");
      avalue[i] = v;

      offset += t->size;
    }

    while (i < nargs)
      avalue[i++] = &tmp_value;
  }
  else
  {
    avalue = NULL;
  }

  scheduling = self->scheduling;
  exceptions = self->exceptions;
  return_shape = self->return_shape;
  system_error = -1;

  {
    GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
    GumInterceptor * interceptor = core->interceptor->interceptor;

    if (exceptions == GUM_DUK_EXCEPTIONS_PROPAGATE ||
        gum_exceptor_try (core->exceptor, &exceptor_scope))
    {
      if (scheduling == GUM_DUK_SCHEDULING_COOPERATIVE)
      {
        _gum_duk_scope_suspend (&scope);

        gum_interceptor_unignore_current_thread (interceptor);
      }

      ffi_call (cif, implementation, rvalue, avalue);

      if (return_shape == GUM_DUK_RETURN_DETAILED)
        system_error = gum_thread_get_system_error ();
    }

    if (scheduling == GUM_DUK_SCHEDULING_COOPERATIVE)
    {
      gum_interceptor_ignore_current_thread (interceptor);

      _gum_duk_scope_resume (&scope);
    }
  }

  if (exceptions == GUM_DUK_EXCEPTIONS_STEAL &&
      gum_exceptor_catch (core->exceptor, &exceptor_scope))
  {
    _gum_duk_throw_native (ctx, &exceptor_scope.exception, core);
  }

  if (return_shape == GUM_DUK_RETURN_DETAILED)
  {
    duk_push_object (ctx);

    gum_duk_push_ffi_value (ctx, rvalue, rtype, core);
    duk_put_prop_string (ctx, -2, "value");

    duk_push_int (ctx, system_error);
    duk_put_prop_string (ctx, -2, GUMJS_SYSTEM_ERROR_FIELD);
  }
  else
  {
    gum_duk_push_ffi_value (ctx, rvalue, rtype, core);
  }
  return 1;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_system_function_construct)
{
  GumDukCore * core = args->core;
  GumDukNativeFunctionParams params;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use `new SystemFunction()` to create a new instance");

  gum_duk_native_function_params_init (&params, core->system_function_prototype,
      GUM_DUK_RETURN_DETAILED, args);

  return gumjs_native_function_init (ctx, &params, core);
}

GUMJS_DEFINE_FINALIZER (gumjs_system_function_finalize)
{
  GumDukNativeFunction * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  gum_duk_native_function_finalize (self);

  return 0;
}

static void
gum_duk_native_function_params_init (GumDukNativeFunctionParams * params,
                                     GumDukHeapPtr prototype,
                                     GumDukReturnValueShape return_shape,
                                     const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukHeapPtr abi_or_options;

  params->prototype = prototype;

  abi_or_options = NULL;
  _gum_duk_args_parse (args, "pVA|V", &params->implementation,
      &params->return_type, &params->argument_types, &abi_or_options);
  params->abi_name = NULL;
  params->scheduling = GUM_DUK_SCHEDULING_COOPERATIVE;
  params->exceptions = GUM_DUK_EXCEPTIONS_STEAL;
  params->return_shape = return_shape;

  duk_push_heapptr (ctx, abi_or_options);
  if (duk_is_string (ctx, -1))
  {
    params->abi_name = duk_require_string (ctx, -1);
  }
  else if (duk_is_object (ctx, -1) && !duk_is_null (ctx, -1))
  {
    duk_idx_t options_index;

    options_index = duk_require_top_index (ctx);

    duk_get_prop_string (ctx, options_index, "abi");
    if (!duk_is_undefined (ctx, -1))
      params->abi_name = duk_require_string (ctx, -1);

    duk_get_prop_string (ctx, options_index, "scheduling");
    if (!duk_is_undefined (ctx, -1))
      params->scheduling = gum_duk_require_scheduling_behavior (ctx, -1);

    duk_get_prop_string (ctx, options_index, "exceptions");
    if (!duk_is_undefined (ctx, -1))
      params->exceptions = gum_duk_require_exceptions_behavior (ctx, -1);

    duk_pop_3 (ctx);
  }
  else if (!duk_is_undefined (ctx, -1))
  {
    _gum_duk_throw (ctx, "expected string or object containing options");
  }
  duk_pop (ctx);
}

static GumDukSchedulingBehavior
gum_duk_require_scheduling_behavior (duk_context * ctx,
                                     duk_idx_t index)
{
  const gchar * value;

  value = duk_require_string (ctx, index);

  if (strcmp (value, "cooperative") == 0)
    return GUM_DUK_SCHEDULING_COOPERATIVE;

  if (strcmp (value, "exclusive") != 0)
    _gum_duk_throw (ctx, "invalid scheduling behavior value");
  return GUM_DUK_SCHEDULING_EXCLUSIVE;
}

static GumDukExceptionsBehavior
gum_duk_require_exceptions_behavior (duk_context * ctx,
                                     duk_idx_t index)
{
  const gchar * value;

  value = duk_require_string (ctx, index);

  if (strcmp (value, "steal") == 0)
    return GUM_DUK_EXCEPTIONS_STEAL;

  if (strcmp (value, "propagate") != 0)
    _gum_duk_throw (ctx, "invalid exceptions behavior value");
  return GUM_DUK_EXCEPTIONS_PROPAGATE;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_callback_construct)
{
  GumDukHeapPtr func, rtype_value, atypes_array;
  gchar * abi_str = NULL;
  GumDukCore * core = args->core;
  GumDukNativeCallback * callback;
  GumDukNativePointer * ptr;
  ffi_type * rtype;
  duk_size_t nargs, i;
  ffi_abi abi;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use `new NativeCallback()` to create a new instance");

  _gum_duk_args_parse (args, "FVA|s", &func, &rtype_value, &atypes_array,
      &abi_str);

  callback = g_slice_new0 (GumDukNativeCallback);
  ptr = &callback->parent;
  callback->func = func;
  callback->core = core;

  if (!gum_duk_get_ffi_type (ctx, rtype_value, &rtype, &callback->data))
    goto invalid_return_type;

  duk_push_heapptr (ctx, atypes_array);

  nargs = duk_get_length (ctx, -1);

  callback->atypes = g_new (ffi_type *, nargs);

  for (i = 0; i != nargs; i++)
  {
    GumDukHeapPtr atype_value;
    ffi_type ** atype;

    duk_get_prop_index (ctx, -1, (duk_uarridx_t) i);
    atype_value = duk_get_heapptr (ctx, -1);

    atype = &callback->atypes[i];

    if (!gum_duk_get_ffi_type (ctx, atype_value, atype, &callback->data))
      goto invalid_argument_type;

    duk_pop (ctx);
  }

  duk_pop (ctx);

  if (abi_str != NULL)
  {
    if (!gum_duk_get_ffi_abi (ctx, abi_str, &abi))
      goto invalid_abi;
  }
  else
  {
    abi = FFI_DEFAULT_ABI;
  }

  callback->closure = ffi_closure_alloc (sizeof (ffi_closure), &ptr->value);
  if (callback->closure == NULL)
    goto alloc_failed;

  if (ffi_prep_cif (&callback->cif, abi, (guint) nargs, rtype,
      callback->atypes) != FFI_OK)
    goto compilation_failed;

  if (ffi_prep_closure_loc (callback->closure, &callback->cif,
      gum_duk_native_callback_invoke, callback, ptr->value) != FFI_OK)
    goto prepare_failed;

  duk_push_this (ctx);

  _gum_duk_put_data (ctx, -1, callback);

  duk_push_heapptr (ctx, func);
  duk_put_prop_string (ctx, -2, DUK_HIDDEN_SYMBOL ("func"));

  duk_pop (ctx);

  return 0;

invalid_return_type:
  {
    gum_duk_native_callback_finalize (callback, FALSE);
    _gum_duk_throw (ctx, "invalid return type");
  }
invalid_argument_type:
  {
    gum_duk_native_callback_finalize (callback, FALSE);
    _gum_duk_throw (ctx, "invalid argument type");
  }
invalid_abi:
  {
    gum_duk_native_callback_finalize (callback, FALSE);
    _gum_duk_throw (ctx, "invalid abi");
  }
alloc_failed:
  {
    gum_duk_native_callback_finalize (callback, FALSE);
    _gum_duk_throw (ctx, "failed to allocate closure");
  }
compilation_failed:
  {
    gum_duk_native_callback_finalize (callback, FALSE);
    _gum_duk_throw (ctx, "failed to compile function call interface");
  }
prepare_failed:
  {
    gum_duk_native_callback_finalize (callback, FALSE);
    _gum_duk_throw (ctx, "failed to prepare closure");
  }

  g_assert_not_reached ();
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_native_callback_finalize)
{
  GumDukNativeCallback * self;
  gboolean heap_destruct;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  heap_destruct = duk_require_boolean (ctx, 1);
  gum_duk_native_callback_finalize (self, heap_destruct);

  return 0;
}

static void
gum_duk_native_callback_finalize (GumDukNativeCallback * callback,
                                  gboolean heap_destruct)
{
  ffi_closure_free (callback->closure);

  while (callback->data != NULL)
  {
    GSList * head = callback->data;
    g_free (head->data);
    callback->data = g_slist_delete_link (callback->data, head);
  }
  g_free (callback->atypes);

  g_slice_free (GumDukNativeCallback, callback);
}

static void
gum_duk_native_callback_invoke (ffi_cif * cif,
                                void * return_value,
                                void ** args,
                                void * user_data)
{
  GumDukNativeCallback * self = user_data;
  GumDukCore * core = self->core;
  GumDukScope scope;
  duk_context * ctx;
  ffi_type * rtype = cif->rtype;
  GumFFIValue * retval = return_value;
  guint i;
  GumInvocationContext * ic;
  GumDukInvocationContext * jic = NULL;
  gboolean success;

  ctx = _gum_duk_scope_enter (&scope, core);

  if (rtype != &ffi_type_void)
  {
    /*
     * Ensure:
     * - high bits of values smaller than a pointer are cleared to zero
     * - we return something predictable in case of a JS exception
     */
    retval->v_pointer = NULL;
  }

  duk_push_heapptr (ctx, self->func);

  ic = gum_interceptor_get_current_invocation ();
  if (ic != NULL)
  {
    jic = _gum_duk_interceptor_obtain_invocation_context (core->interceptor);
    _gum_duk_invocation_context_reset (jic, ic);
    duk_push_heapptr (ctx, jic->object);
  }
  else
  {
    duk_push_undefined (ctx);
  }

  for (i = 0; i != cif->nargs; i++)
    gum_duk_push_ffi_value (ctx, args[i], cif->arg_types[i], core);

  success = _gum_duk_scope_call_method (&scope, cif->nargs);

  if (jic != NULL)
  {
    _gum_duk_invocation_context_reset (jic, NULL);
    _gum_duk_interceptor_release_invocation_context (core->interceptor, jic);
  }

  if (success && cif->rtype != &ffi_type_void)
  {
    gum_duk_get_ffi_value (ctx, -1, cif->rtype, core, retval);
  }

  duk_pop (ctx);

  _gum_duk_scope_leave (&scope);
}

static GumDukCpuContext *
gumjs_cpu_context_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDukCpuContext * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  if (self->handle == NULL)
    _gum_duk_throw (ctx, "invalid operation");
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cpu_context_construct)
{
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_cpu_context_finalize)
{
  GumDukCpuContext * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_slice_free (GumDukCpuContext, self);

  return 0;
}

static void
gumjs_cpu_context_set_register (GumDukCpuContext * self,
                                duk_context * ctx,
                                const GumDukArgs * args,
                                gpointer * reg)
{
  if (self->access == GUM_CPU_CONTEXT_READONLY)
    _gum_duk_throw (ctx, "invalid operation");

  _gum_duk_args_parse (args, "p~", reg);
}

static GumSourceMap *
gumjs_source_map_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumSourceMap * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_source_map_construct)
{
  const gchar * json;
  GumSourceMap * self;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use `new SourceMap()` to create a new instance");

  _gum_duk_args_parse (args, "s", &json);

  self = gum_source_map_new (json);
  if (self == NULL)
    _gum_duk_throw (ctx, "invalid source map");

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, self);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_source_map_finalize)
{
  GumSourceMap * self;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  g_object_unref (self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_source_map_resolve)
{
  GumSourceMap * self;
  guint line, column;
  const gchar * source, * name;

  self = gumjs_source_map_from_args (args);

  if (args->count == 1)
  {
    _gum_duk_args_parse (args, "u", &line);
    column = G_MAXUINT;
  }
  else
  {
    _gum_duk_args_parse (args, "uu", &line, &column);
  }

  if (gum_source_map_resolve (self, &line, &column, &source, &name))
  {
    duk_push_array (ctx);

    duk_push_string (ctx, source);
    duk_put_prop_index (ctx, -2, 0);

    duk_push_uint (ctx, line);
    duk_put_prop_index (ctx, -2, 1);

    duk_push_uint (ctx, column);
    duk_put_prop_index (ctx, -2, 2);

    if (name != NULL)
      duk_push_string (ctx, name);
    else
      duk_push_null (ctx);
    duk_put_prop_index (ctx, -2, 3);
  }
  else
  {
    duk_push_null (ctx);
  }

  return 1;
}

static GumDukWeakRef *
gum_duk_weak_ref_new (guint id,
                      GumDukHeapPtr callback,
                      GumDukCore * core)
{
  GumDukWeakRef * ref;

  ref = g_slice_new (GumDukWeakRef);
  ref->id = id;
  _gum_duk_protect (core->current_scope->ctx, callback);
  ref->callback = callback;
  ref->core = core;

  return ref;
}

static void
gum_duk_weak_ref_clear (GumDukWeakRef * ref)
{
  GumDukCore * core = ref->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  duk_push_heapptr (ctx, ref->callback);
  _gum_duk_scope_call (&scope, 0);
  duk_pop (ctx);

  _gum_duk_unprotect (ctx, ref->callback);
  ref->callback = NULL;

  ref->core = NULL;
}

static gint
gum_duk_core_schedule_callback (GumDukCore * self,
                                const GumDukArgs * args,
                                gboolean repeat)
{
  GumDukHeapPtr func;
  gsize delay;
  guint id;
  GSource * source;
  GumDukScheduledCallback * callback;

  if (repeat)
  {
    _gum_duk_args_parse (args, "FZ", &func, &delay);
  }
  else
  {
    delay = 0;
    _gum_duk_args_parse (args, "F|Z", &func, &delay);
  }

  id = self->next_callback_id++;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new ((guint) delay);

  callback = gum_scheduled_callback_new (id, func, repeat, source, self);
  g_source_set_callback (source, (GSourceFunc) gum_scheduled_callback_invoke,
      callback, (GDestroyNotify) gum_scheduled_callback_free);

  g_hash_table_insert (self->scheduled_callbacks, GINT_TO_POINTER (id),
      callback);
  g_queue_push_tail (&self->current_scope->scheduled_sources, source);

  duk_push_number (args->ctx, id);
  return 1;
}

static GumDukScheduledCallback *
gum_duk_core_try_steal_scheduled_callback (GumDukCore * self,
                                           gint id)
{
  GumDukScheduledCallback * callback;
  gpointer raw_id;

  raw_id = GINT_TO_POINTER (id);

  callback = g_hash_table_lookup (self->scheduled_callbacks, raw_id);
  if (callback == NULL)
    return NULL;

  g_hash_table_remove (self->scheduled_callbacks, raw_id);

  return callback;
}

static GumDukScheduledCallback *
gum_scheduled_callback_new (guint id,
                            GumDukHeapPtr func,
                            gboolean repeat,
                            GSource * source,
                            GumDukCore * core)
{
  GumDukScheduledCallback * callback;

  callback = g_slice_new (GumDukScheduledCallback);
  callback->id = id;
  _gum_duk_protect (core->current_scope->ctx, func);
  callback->func = func;
  callback->repeat = repeat;
  callback->source = source;
  callback->core = core;

  return callback;
}

static void
gum_scheduled_callback_free (GumDukScheduledCallback * callback)
{
  GumDukCore * core = callback->core;
  GumDukScope scope;
  duk_context * ctx;

  ctx = _gum_duk_scope_enter (&scope, core);
  _gum_duk_core_unpin (core);
  _gum_duk_unprotect (ctx, callback->func);
  _gum_duk_scope_leave (&scope);

  g_slice_free (GumDukScheduledCallback, callback);
}

static gboolean
gum_scheduled_callback_invoke (GumDukScheduledCallback * self)
{
  GumDukCore * core = self->core;
  duk_context * ctx;
  GumDukScope scope;

  ctx = _gum_duk_scope_enter (&scope, self->core);

  duk_push_heapptr (ctx, self->func);
  _gum_duk_scope_call (&scope, 0);
  duk_pop (ctx);

  if (!self->repeat)
  {
    if (gum_duk_core_try_steal_scheduled_callback (core, self->id) != NULL)
      _gum_duk_core_pin (core);
  }

  _gum_duk_scope_leave (&scope);

  return self->repeat;
}

static GumDukExceptionSink *
gum_duk_exception_sink_new (GumDukHeapPtr callback,
                            GumDukCore * core)
{
  GumDukExceptionSink * sink;

  sink = g_slice_new (GumDukExceptionSink);
  _gum_duk_protect (core->current_scope->ctx, callback);
  sink->callback = callback;
  sink->core = core;

  return sink;
}

static void
gum_duk_exception_sink_free (GumDukExceptionSink * sink)
{
  _gum_duk_unprotect (sink->core->current_scope->ctx, sink->callback);
  g_slice_free (GumDukExceptionSink, sink);
}

static void
gum_duk_exception_sink_handle_exception (GumDukExceptionSink * self)
{
  GumDukCore * core = self->core;
  duk_context * ctx = core->current_scope->ctx;
  GumDukHeapPtr callback = self->callback;

  duk_push_heapptr (ctx, callback);
  duk_dup (ctx, -2);
  duk_pcall (ctx, 1);
  duk_pop (ctx);
}

static GumDukMessageSink *
gum_duk_message_sink_new (GumDukHeapPtr callback,
                          GumDukCore * core)
{
  GumDukMessageSink * sink;

  sink = g_slice_new (GumDukMessageSink);
  _gum_duk_protect (core->current_scope->ctx, callback);
  sink->callback = callback;
  sink->core = core;

  return sink;
}

static void
gum_duk_message_sink_free (GumDukMessageSink * sink)
{
  _gum_duk_unprotect (sink->core->current_scope->ctx, sink->callback);
  g_slice_free (GumDukMessageSink, sink);
}

GUMJS_DEFINE_FINALIZER (gum_duk_message_data_finalize)
{
  gpointer data;

  data = duk_require_buffer_data (ctx, 0, NULL);
  g_free (data);

  return 0;
}

static void
gum_duk_message_sink_post (GumDukMessageSink * self,
                           const gchar * message,
                           GBytes * data,
                           GumDukScope * scope)
{
  duk_context * ctx = self->core->current_scope->ctx;

  duk_push_heapptr (ctx, self->callback);

  duk_push_string (ctx, message);
  if (data != NULL)
  {
    gpointer data_buffer;
    gsize data_size;

    data_buffer = g_bytes_unref_to_data (data, &data_size);

    duk_push_external_buffer (ctx);
    duk_config_buffer (ctx, -1, data_buffer, data_size);

    duk_push_buffer_object (ctx, -1, 0, data_size, DUK_BUFOBJ_ARRAYBUFFER);

    duk_swap (ctx, -2, -1);
    duk_pop (ctx);

    duk_push_c_function (ctx, gum_duk_message_data_finalize, 1);
    duk_set_finalizer (ctx, -2);
  }
  else
  {
    duk_push_null (ctx);
  }

  _gum_duk_scope_call (scope, 2);

  duk_pop (ctx);
}

static gboolean
gum_duk_get_ffi_type (duk_context * ctx,
                      GumDukHeapPtr value,
                      ffi_type ** type,
                      GSList ** data)
{
  gboolean success = FALSE;
  duk_size_t i;

  duk_push_heapptr (ctx, value);

  if (duk_is_string (ctx, -1))
  {
    const gchar * type_name = duk_require_string (ctx, -1);

    success = gum_ffi_try_get_type_by_name (type_name, type);
  }
  else if (duk_is_array (ctx, -1))
  {
    duk_size_t length;
    ffi_type ** fields, * struct_type;

    length = duk_get_length (ctx, -1);

    fields = g_new (ffi_type *, length + 1);
    *data = g_slist_prepend (*data, fields);

    for (i = 0; i != length; i++)
    {
      GumDukHeapPtr field_value;

      duk_get_prop_index (ctx, -1, (duk_uarridx_t) i);
      field_value = duk_get_heapptr (ctx, -1);
      duk_pop (ctx);

      if (!gum_duk_get_ffi_type (ctx, field_value, &fields[i], data))
        goto beach;
    }

    fields[length] = NULL;

    struct_type = g_new0 (ffi_type, 1);
    struct_type->type = FFI_TYPE_STRUCT;
    struct_type->elements = fields;
    *data = g_slist_prepend (*data, struct_type);

    *type = struct_type;
    success = TRUE;
  }

beach:
  duk_pop (ctx);

  return success;
}

static gboolean
gum_duk_get_ffi_abi (duk_context * ctx,
                     const gchar * name,
                     ffi_abi * abi)
{
  if (gum_ffi_try_get_abi_by_name (name, abi))
    return TRUE;

  _gum_duk_throw (ctx, "invalid abi specified");
  return FALSE;
}

static gboolean
gum_duk_get_ffi_value (duk_context * ctx,
                       duk_idx_t index,
                       const ffi_type * type,
                       GumDukCore * core,
                       GumFFIValue * value)
{
  guint u;
  gint64 i64;
  guint64 u64;

  if (type == &ffi_type_void)
  {
    value->v_pointer = NULL;
  }
  else if (type == &ffi_type_pointer)
  {
    if (!_gum_duk_get_pointer (ctx, index, core, &value->v_pointer))
      return FALSE;
  }
  else if (type == &ffi_type_sint8)
  {
    if (!duk_is_number (ctx, index))
      return FALSE;
    value->v_sint8 = duk_require_int (ctx, index);
  }
  else if (type == &ffi_type_uint8)
  {
    if (_gum_duk_get_uint (ctx, index, &u))
      value->v_uint8 = u;
    else
      return FALSE;
  }
  else if (type == &ffi_type_sint16)
  {
    if (!duk_is_number (ctx, index))
      return FALSE;
    value->v_sint16 = duk_require_int (ctx, index);
  }
  else if (type == &ffi_type_uint16)
  {
    if (_gum_duk_get_uint (ctx, index, &u))
      value->v_uint16 = u;
    else
      return FALSE;
  }
  else if (type == &ffi_type_sint32)
  {
    if (!duk_is_number (ctx, index))
      return FALSE;
    value->v_sint32 = duk_require_int (ctx, index);
  }
  else if (type == &ffi_type_uint32)
  {
    if (_gum_duk_get_uint (ctx, index, &u))
      value->v_uint32 = u;
    else
      return FALSE;
  }
  else if (type == &ffi_type_sint64)
  {
    if (!_gum_duk_get_int64 (ctx, index, core, &i64))
      return FALSE;
    value->v_sint64 = i64;
  }
  else if (type == &ffi_type_uint64)
  {
    if (!_gum_duk_get_uint64 (ctx, index, core, &u64))
      return FALSE;
    value->v_uint64 = u64;
  }
  else if (type == &ffi_type_float)
  {
    if (!duk_is_number (ctx, index))
      return FALSE;
    value->v_float = duk_require_number (ctx, index);
  }
  else if (type == &ffi_type_double)
  {
    if (!duk_is_number (ctx, index))
      return FALSE;
    value->v_double = duk_require_number (ctx, index);
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    ffi_type ** const field_types = type->elements, ** t;
    duk_size_t length, expected_length, i;
    guint8 * field_values;
    gsize offset;

    if (!duk_is_array (ctx, index))
      return FALSE;

    length = duk_get_length (ctx, index);

    expected_length = 0;
    for (t = field_types; *t != NULL; t++)
      expected_length++;

    if (length != expected_length)
      return FALSE;

    field_values = (guint8 *) value;
    offset = 0;

    for (i = 0; i != length; i++)
    {
      const ffi_type * field_type = field_types[i];
      GumFFIValue * field_value;
      gboolean valid;

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);

      field_value = (GumFFIValue *) (field_values + offset);
      duk_get_prop_index (ctx, index, (duk_uarridx_t) i);
      valid = gum_duk_get_ffi_value (ctx, -1, field_type, core, field_value);
      duk_pop (ctx);

      if (!valid)
        return FALSE;

      offset += field_type->size;
    }
  }
  else
  {
    g_assert_not_reached ();
  }

  return TRUE;
}

static void
gum_duk_push_ffi_value (duk_context * ctx,
                        const GumFFIValue * value,
                        const ffi_type * type,
                        GumDukCore * core)
{
  if (type == &ffi_type_void)
  {
    duk_push_undefined (ctx);
  }
  else if (type == &ffi_type_pointer)
  {
    _gum_duk_push_native_pointer (ctx, value->v_pointer, core);
  }
  else if (type == &ffi_type_sint8)
  {
    duk_push_int (ctx, value->v_sint8);
  }
  else if (type == &ffi_type_uint8)
  {
    duk_push_uint (ctx, value->v_uint8);
  }
  else if (type == &ffi_type_sint16)
  {
    duk_push_int (ctx, value->v_sint16);
  }
  else if (type == &ffi_type_uint16)
  {
    duk_push_uint (ctx, value->v_uint16);
  }
  else if (type == &ffi_type_sint32)
  {
    duk_push_int (ctx, value->v_sint32);
  }
  else if (type == &ffi_type_uint32)
  {
    duk_push_uint (ctx, value->v_uint32);
  }
  else if (type == &ffi_type_sint64)
  {
    _gum_duk_push_int64 (ctx, value->v_sint64, core);
  }
  else if (type == &ffi_type_uint64)
  {
    _gum_duk_push_uint64 (ctx, value->v_uint64, core);
  }
  else if (type == &ffi_type_float)
  {
    duk_push_number (ctx, value->v_float);
  }
  else if (type == &ffi_type_double)
  {
    duk_push_number (ctx, value->v_double);
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    ffi_type ** const field_types = type->elements, ** t;
    guint length, i;
    const guint8 * field_values;
    gsize offset;

    length = 0;
    for (t = field_types; *t != NULL; t++)
      length++;

    field_values = (const guint8 *) value;
    offset = 0;

    duk_push_array (ctx);

    for (i = 0; i != length; i++)
    {
      const ffi_type * field_type = field_types[i];
      const GumFFIValue * field_value;

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);
      field_value = (const GumFFIValue *) (field_values + offset);

      gum_duk_push_ffi_value (ctx, field_value, field_type, core);
      duk_put_prop_index (ctx, -2, i);

      offset += field_type->size;
    }
  }
  else
  {
    g_assert_not_reached ();
  }
}
