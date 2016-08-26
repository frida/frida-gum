/*
 * Copyright (C) 2015-2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukcore.h"

#include "gumdukinterceptor.h"
#include "gumdukmacros.h"

#include <ffi.h>

#define GUM_DUK_NATIVE_POINTER_CACHE_SIZE 8

typedef struct _GumDukFlushCallback GumDukFlushCallback;
typedef struct _GumDukNativeFunction GumDukNativeFunction;
typedef struct _GumDukNativeCallback GumDukNativeCallback;
typedef union _GumFFIValue GumFFIValue;
typedef struct _GumFFITypeMapping GumFFITypeMapping;
typedef struct _GumFFIABIMapping GumFFIABIMapping;

struct _GumDukFlushCallback
{
  GumDukFlushNotify func;
  GumDukScript * script;
};

struct _GumDukWeakRef
{
  guint id;
  GumDukHeapPtr target;
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

struct _GumDukNativeFunction
{
  GumDukNativePointer parent;

  GCallback fn;
  ffi_cif cif;
  ffi_type ** atypes;
  gsize arglist_size;
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

union _GumFFIValue
{
  gpointer v_pointer;
  gint v_sint;
  guint v_uint;
  glong v_slong;
  gulong v_ulong;
  gchar v_schar;
  guchar v_uchar;
  gfloat v_float;
  gdouble v_double;
  gint8 v_sint8;
  guint8 v_uint8;
  gint16 v_sint16;
  guint16 v_uint16;
  gint32 v_sint32;
  guint32 v_uint32;
  gint64 v_sint64;
  guint64 v_uint64;
};

struct _GumFFITypeMapping
{
  const gchar * name;
  ffi_type * type;
};

struct _GumFFIABIMapping
{
  const gchar * name;
  ffi_abi abi;
};

static gboolean gum_duk_core_notify_flushed_when_idle (gpointer user_data);

GUMJS_DECLARE_FUNCTION (gumjs_set_timeout)
GUMJS_DECLARE_FUNCTION (gumjs_set_interval)
GUMJS_DECLARE_FUNCTION (gumjs_clear_timer)
GUMJS_DECLARE_FUNCTION (gumjs_gc)
GUMJS_DECLARE_FUNCTION (gumjs_send)
GUMJS_DECLARE_FUNCTION (gumjs_set_unhandled_exception_callback)
GUMJS_DECLARE_FUNCTION (gumjs_set_incoming_message_callback)
GUMJS_DECLARE_FUNCTION (gumjs_wait_for_event)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_script_construct)
GUMJS_DECLARE_GETTER (gumjs_script_get_file_name)
GUMJS_DECLARE_GETTER (gumjs_script_get_source_map_data)
GUMJS_DECLARE_FUNCTION (gumjs_script_pin)
GUMJS_DECLARE_FUNCTION (gumjs_script_unpin)
GUMJS_DECLARE_FUNCTION (gumjs_script_set_global_access_handler)
static int gum_duk_core_on_global_enumerate (duk_context * ctx, void * udata);
static int gum_duk_core_on_global_get (duk_context * ctx, const char * name,
    void * udata);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_weak_ref_construct)
GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_bind)
GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_unbind)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_int64_construct)
GUMJS_DECLARE_FINALIZER (gumjs_int64_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_int64_add)
GUMJS_DECLARE_FUNCTION (gumjs_int64_sub)
GUMJS_DECLARE_FUNCTION (gumjs_int64_and)
GUMJS_DECLARE_FUNCTION (gumjs_int64_or)
GUMJS_DECLARE_FUNCTION (gumjs_int64_xor)
GUMJS_DECLARE_FUNCTION (gumjs_int64_shr)
GUMJS_DECLARE_FUNCTION (gumjs_int64_shl)
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
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_compare)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_int32)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_match_pattern)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_resource_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_resource_finalize)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_function_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_function_finalize)
static void gum_duk_native_function_finalize (
    GumDukNativeFunction * func);
GUMJS_DECLARE_FUNCTION (gumjs_native_function_invoke)

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
    duk_context * ctx, const GumDukArgs * args, gsize * reg);

static GumDukWeakRef * gum_duk_weak_ref_new (guint id, GumDukHeapPtr target,
    GumDukHeapPtr callback, GumDukCore * core);
static void gum_duk_weak_ref_clear (GumDukWeakRef * ref);
static void gum_duk_weak_ref_free (GumDukWeakRef * ref);

static gint gum_duk_core_schedule_callback (GumDukCore * self,
    const GumDukArgs * args, gboolean repeat);
static void gum_duk_core_add_scheduled_callback (GumDukCore * self,
    GumDukScheduledCallback * cb);
static gboolean gum_duk_core_remove_scheduled_callback (GumDukCore * self,
    GumDukScheduledCallback * cb);

static GumDukScheduledCallback * gum_scheduled_callback_new (guint id,
    GumDukHeapPtr func, gboolean repeat, GSource * source, GumDukCore * core);
static void gum_scheduled_callback_free (GumDukScheduledCallback * callback);
static gboolean gum_scheduled_callback_invoke (gpointer user_data);

static GumDukExceptionSink * gum_duk_exception_sink_new (GumDukHeapPtr callback,
    GumDukCore * core);
static void gum_duk_exception_sink_free (GumDukExceptionSink * sink);
static void gum_duk_exception_sink_handle_exception (
    GumDukExceptionSink * self);

static GumDukMessageSink * gum_duk_message_sink_new (GumDukHeapPtr callback,
    GumDukCore * core);
static void gum_duk_message_sink_free (GumDukMessageSink * sink);
static void gum_duk_message_sink_handle_message (GumDukMessageSink * self,
    const gchar * message, GumDukScope * scope);

static gboolean gum_duk_get_ffi_type (duk_context * ctx, GumDukHeapPtr value,
    ffi_type ** type, GSList ** data);
static gboolean gum_duk_get_ffi_abi (duk_context * ctx, const gchar * name,
    ffi_abi * abi);
static gboolean gum_duk_get_ffi_value (duk_context * ctx, duk_idx_t index,
    const ffi_type * type, GumDukCore * core, GumFFIValue * value);
static void gum_duk_push_ffi_value (duk_context * ctx,
    const GumFFIValue * value, const ffi_type * type, GumDukCore * core);

static const GumDukPropertyEntry gumjs_script_values[] =
{
  { "fileName", gumjs_script_get_file_name, NULL },
  { "_sourceMapData", gumjs_script_get_source_map_data, NULL },

  { NULL, NULL, NULL }
};

static const duk_function_list_entry gumjs_script_functions[] =
{
  { "pin", gumjs_script_pin, 0 },
  { "unpin", gumjs_script_unpin, 0 },
  { "setGlobalAccessHandler", gumjs_script_set_global_access_handler, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_weak_ref_functions[] =
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
  { "compare", gumjs_native_pointer_compare, 1 },
  { "toInt32", gumjs_native_pointer_to_int32, 0 },
  { "toString", gumjs_native_pointer_to_string, 1 },
  { "toJSON", gumjs_native_pointer_to_json, 0 },
  { "toMatchPattern", gumjs_native_pointer_to_match_pattern, 0 },

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
        (gsize *) &self->handle->R); \
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

void
_gum_duk_core_init (GumDukCore * self,
                    GumDukScript * script,
                    GumDukInterceptor * interceptor,
                    GumDukMessageEmitter message_emitter,
                    GumScriptScheduler * scheduler,
                    duk_context * ctx)
{
  guint i;

  g_object_get (script, "backend", &self->backend, NULL);
  g_object_unref (self->backend);

  self->script = script;
  self->interceptor = interceptor;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->heap_ctx = ctx;
  self->current_ctx = NULL;

  g_rec_mutex_init (&self->mutex);
  self->usage_count = 0;
  self->mutex_depth = 0;
  self->heap_thread_in_use = FALSE;
  self->flush_notify = NULL;

  g_mutex_init (&self->event_mutex);
  g_cond_init (&self->event_cond);
  self->event_count = 0;

  self->weak_refs = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_duk_weak_ref_free);

  _gum_duk_store_module_data (ctx, "core", self);

  /* set `global` to the global object */
  duk_push_global_object (ctx);
  duk_put_global_string (ctx, "global");

  duk_push_object (ctx);
  duk_push_string (ctx, FRIDA_VERSION);
  duk_put_prop_string (ctx, -2, "version");
  duk_put_global_string (ctx, "Frida");

  duk_push_c_function (ctx, gumjs_script_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_script_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  duk_put_global_string (ctx, "Script");

  duk_push_c_function (ctx, gumjs_weak_ref_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_weak_ref_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  _gum_duk_put_data (ctx, -1, self);
  duk_put_global_string (ctx, "WeakRef");

  GUMJS_ADD_GLOBAL_FUNCTION ("setTimeout", gumjs_set_timeout, 2);
  GUMJS_ADD_GLOBAL_FUNCTION ("clearTimeout", gumjs_clear_timer, 1);
  GUMJS_ADD_GLOBAL_FUNCTION ("setInterval", gumjs_set_interval, 2);
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
  duk_put_prop_string (ctx, -2, "prototype");
  self->native_pointer = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "NativePointer");

  _gum_duk_create_subclass (ctx, "NativePointer", "NativeResource",
      gumjs_native_resource_construct, 2, gumjs_native_resource_finalize);
  duk_get_global_string (ctx, "NativeResource");
  self->native_resource = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  _gum_duk_create_subclass (ctx, "NativePointer", "NativeFunction",
      gumjs_native_function_construct, 4, gumjs_native_function_finalize);
  duk_get_global_string (ctx, "NativeFunction");
  self->native_function = _gum_duk_require_heapptr (ctx, -1);
  duk_get_prop_string (ctx, -1, "prototype");
  self->native_function_prototype = duk_require_heapptr (ctx, -1);
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
}

gboolean
_gum_duk_core_flush (GumDukCore * self,
                     GumDukFlushNotify flush_notify)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self);
  gboolean done;

  self->flush_notify = flush_notify;

  if (self->usage_count > 1)
    return FALSE;

  while (self->scheduled_callbacks != NULL)
  {
    GumDukScheduledCallback * callback =
        (GumDukScheduledCallback *) self->scheduled_callbacks->data;
    GSource * source;

    self->scheduled_callbacks = g_slist_delete_link (
        self->scheduled_callbacks, self->scheduled_callbacks);

    source = g_source_ref (callback->source);

    _gum_duk_core_pin (self);
    _gum_duk_scope_suspend (&scope);

    g_source_destroy (source);
    g_source_unref (source);

    _gum_duk_scope_resume (&scope);
  }

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
  callback->script = self->script;

  source = g_idle_source_new ();
  g_source_set_callback (source, gum_duk_core_notify_flushed_when_idle,
      callback, NULL);
  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));
  g_source_unref (source);
}

static gboolean
gum_duk_core_notify_flushed_when_idle (gpointer user_data)
{
  GumDukFlushCallback * callback = user_data;

  callback->func (callback->script);

  g_slice_free (GumDukFlushCallback, callback);

  return FALSE;
}

void
_gum_duk_core_dispose (GumDukCore * self)
{
  duk_context * ctx = self->current_ctx;

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

  _gum_duk_release_heapptr (ctx, self->int64);
  _gum_duk_release_heapptr (ctx, self->uint64);
  _gum_duk_release_heapptr (ctx, self->native_pointer);
  _gum_duk_release_heapptr (ctx, self->native_resource);
  _gum_duk_release_heapptr (ctx, self->native_function);
  _gum_duk_release_heapptr (ctx, self->cpu_context);
}

void
_gum_duk_core_finalize (GumDukCore * self)
{
  g_clear_pointer (&self->weak_refs, g_hash_table_unref);

  g_mutex_clear (&self->event_mutex);
  g_cond_clear (&self->event_cond);

  g_rec_mutex_clear (&self->mutex);

  g_assert (self->current_ctx == NULL);
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
_gum_duk_core_post_message (GumDukCore * self,
                            const gchar * message)
{
  gboolean delivered = FALSE;
  GumDukScope scope;

  _gum_duk_scope_enter (&scope, self);

  if (self->incoming_message_sink != NULL)
  {
    gum_duk_message_sink_handle_message (self->incoming_message_sink, message,
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
  duk_context * ctx = core->heap_ctx;

  self->core = core;

  gum_interceptor_begin_transaction (core->interceptor->interceptor);

  g_rec_mutex_lock (&core->mutex);

  _gum_duk_core_pin (core);
  core->mutex_depth++;

  if (core->mutex_depth == 1)
  {
    if (!core->heap_thread_in_use)
    {
      core->heap_thread_in_use = TRUE;

      self->ctx = ctx;
    }
    else
    {
      gchar name[32];
      duk_idx_t thread_index;

      sprintf (name, "thread_%p", self);

      thread_index = duk_push_thread (ctx);
      self->ctx = duk_get_context (ctx, thread_index);

      duk_push_global_stash (ctx);
      duk_dup (ctx, -2);
      duk_put_prop_string (ctx, -2, name);

      duk_pop_2 (ctx);
    }

    g_assert (core->current_ctx == NULL);
    core->current_ctx = self->ctx;
  }
  else
  {
    self->ctx = core->current_ctx;
  }

  self->exception = NULL;

  return self->ctx;
}

void
_gum_duk_scope_suspend (GumDukScope * self)
{
  GumDukCore * core = self->core;
  guint i;

  duk_suspend (core->current_ctx, &self->thread_state);

  g_assert (core->current_ctx == self->ctx);
  core->current_ctx = NULL;

  self->previous_mutex_depth = core->mutex_depth;
  core->mutex_depth = 0;

  for (i = 0; i != self->previous_mutex_depth; i++)
    g_rec_mutex_unlock (&core->mutex);
}

void
_gum_duk_scope_resume (GumDukScope * self)
{
  GumDukCore * core = self->core;
  guint i;

  for (i = 0; i != self->previous_mutex_depth; i++)
    g_rec_mutex_lock (&core->mutex);

  core->mutex_depth = self->previous_mutex_depth;
  self->previous_mutex_depth = 0;

  g_assert (core->current_ctx == NULL);
  core->current_ctx = self->ctx;

  duk_resume (core->current_ctx, &self->thread_state);
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
  duk_throw (ctx);
}

void
_gum_duk_scope_leave (GumDukScope * self)
{
  GumDukCore * core = self->core;
  duk_context * ctx = core->heap_ctx;
  GumDukFlushNotify pending_flush_notify = NULL;

  g_assert (core->current_ctx == self->ctx);

  if (core->mutex_depth == 1)
  {
    core->current_ctx = NULL;

    if (self->ctx == ctx)
    {
      core->heap_thread_in_use = FALSE;
    }
    else
    {
      gchar name[32];

      sprintf (name, "thread_%p", self);

      duk_push_global_stash (ctx);
      duk_del_prop_string (ctx, -1, name);
      duk_pop (ctx);
    }
  }

  core->mutex_depth--;
  _gum_duk_core_unpin (core);

  if (core->flush_notify != NULL && core->usage_count == 0)
  {
    pending_flush_notify = core->flush_notify;
    core->flush_notify = NULL;
  }

  g_rec_mutex_unlock (&core->mutex);

  gum_interceptor_end_transaction (self->core->interceptor->interceptor);

  if (pending_flush_notify != NULL)
    gum_duk_core_notify_flushed (core, pending_flush_notify);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_script_construct)
{
  (void) args;

  duk_push_this (ctx);

  duk_push_string (ctx, "DUK");
  duk_put_prop_string (ctx, -2, "runtime");

  _gum_duk_add_properties_to_class_by_heapptr (ctx,
      duk_require_heapptr (ctx, -1), gumjs_script_values);

  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_GETTER (gumjs_script_get_file_name)
{
  gchar * name, * file_name;

  g_object_get (args->core->script, "name", &name, NULL);
  file_name = g_strconcat (name, ".js", NULL);
  duk_push_string (ctx, file_name);
  g_free (file_name);
  g_free (name);

  return 1;
}

GUMJS_DEFINE_GETTER (gumjs_script_get_source_map_data)
{
  gchar * source;
  GRegex * regex;
  GMatchInfo * match_info;

  g_object_get (args->core->script, "source", &source, NULL);

  if (source == NULL)
  {
    duk_push_null (ctx);
    return 1;
  }

  regex = g_regex_new ("//[#@][ \t]sourceMappingURL=[ \t]*"
      "data:application/json;base64,([^\\s\'\"]*)[ \t]*$", 0, 0, NULL);
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

      data_utf8 = g_strndup (data, size);
      duk_push_string (ctx, data_utf8);
      g_free (data_utf8);
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

GUMJS_DEFINE_FUNCTION (gumjs_script_pin)
{
  (void) ctx;

  _gum_duk_core_pin (args->core);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_unpin)
{
  (void) ctx;

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

GUMJS_DEFINE_CONSTRUCTOR (gumjs_weak_ref_construct)
{
  (void) ctx;
  (void) args;

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_bind)
{
  GumDukHeapPtr target;
  GumDukHeapPtr callback;
  gboolean target_is_valid;
  guint id;
  GumDukWeakRef * ref;

  _gum_duk_args_parse (args, "VF", &target, &callback);

  duk_push_heapptr (ctx, target);
  target_is_valid = !duk_is_null (ctx, -1) && duk_is_object (ctx, -1);
  if (!target_is_valid)
    _gum_duk_throw (ctx, "expected a non-primitive value");
  duk_pop (ctx);

  id = ++args->core->last_weak_ref_id;

  ref = gum_duk_weak_ref_new (id, target, callback, args->core);
  g_hash_table_insert (args->core->weak_refs, GUINT_TO_POINTER (id), ref);

  duk_push_int (ctx, id);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_unbind)
{
  guint id;
  gboolean removed;
  GumDukCore * self = args->core;

  _gum_duk_args_parse (args, "u", &id);

  removed = !g_hash_table_remove (self->weak_refs, GUINT_TO_POINTER (id));

  duk_push_boolean (ctx, removed);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_timeout)
{
  GumDukCore * self = args->core;

  (void) ctx;

  return gum_duk_core_schedule_callback (self, args, FALSE);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_interval)
{
  GumDukCore * self = args->core;

  (void) ctx;

  return gum_duk_core_schedule_callback (self, args, TRUE);
}

GUMJS_DEFINE_FUNCTION (gumjs_clear_timer)
{
  GumDukCore * self = args->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self);
  gint id;
  GumDukScheduledCallback * callback = NULL;
  GSList * cur;

  _gum_duk_args_parse (args, "i", &id);

  for (cur = self->scheduled_callbacks; cur != NULL; cur = cur->next)
  {
    GumDukScheduledCallback * cb = cur->data;
    if (cb->id == id)
    {
      callback = cb;
      self->scheduled_callbacks =
          g_slist_delete_link (self->scheduled_callbacks, cur);
      break;
    }
  }

  if (callback != NULL)
  {
    GSource * source;

    source = g_source_ref (callback->source);

    _gum_duk_core_pin (self);
    _gum_duk_scope_suspend (&scope);

    g_source_destroy (source);
    g_source_unref (source);

    _gum_duk_scope_resume (&scope);
  }

  duk_push_boolean (ctx, callback != NULL);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_gc)
{
  (void) args;

  duk_gc (ctx, 0);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_send)
{
  GumDukCore * self = args->core;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self);
  GumInterceptor * interceptor = self->interceptor->interceptor;
  gchar * message;
  GBytes * data;

  (void) ctx;

  _gum_duk_args_parse (args, "sB?", &message, &data);

  _gum_duk_scope_suspend (&scope);

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

  _gum_duk_scope_resume (&scope);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  GumDukCore * self = args->core;
  GumDukHeapPtr callback;
  GumDukExceptionSink * new_sink, * old_sink;

  (void) ctx;

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

  (void) ctx;

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
  guint start_count;

  (void) ctx;

  _gum_duk_scope_suspend (&scope);

  g_mutex_lock (&self->event_mutex);
  start_count = self->event_count;
  while (self->event_count == start_count)
    g_cond_wait (&self->event_cond, &self->event_mutex);
  g_mutex_unlock (&self->event_mutex);

  _gum_duk_scope_resume (&scope);

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
    duk_push_error_object (ctx, DUK_ERR_ERROR,
        "Use `new Int64()` to create a new instance, "
        "or use the shorthand: `int64()`");
    duk_throw (ctx);
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

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "Int64"))
    return 0;

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
    duk_push_error_object (ctx, DUK_ERR_ERROR,
        "Use `new UInt64()` to create a new instance, "
        "or use the shorthand: `uint64()`");
    duk_throw (ctx);
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

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "UInt64"))
    return 0;

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
    duk_push_error_object (ctx, DUK_ERR_ERROR,
        "Use `new NativePointer()` to create a new instance, or use one of the "
        "two shorthands: `ptr()` and `NULL`");
    duk_throw (ctx);
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
  GumDukNativePointerImpl * self;
  gboolean heap_destruct;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "NativePointer"))
    return 0;

  heap_destruct = duk_require_boolean (ctx, 1);
  if (!heap_destruct)
  {
    GumDukCore * core = args->core;

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

#define GUM_DEFINE_NATIVE_POINTER_OP_IMPL(name, op) \
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

GUM_DEFINE_NATIVE_POINTER_OP_IMPL (add, +)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (sub, -)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (and, &)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (or,  |)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (xor, ^)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (shr, >>)
GUM_DEFINE_NATIVE_POINTER_OP_IMPL (shl, <<)

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

  (void) args;

  data = duk_require_pointer (ctx, 0);
  notify = GUM_POINTER_TO_FUNCPTR (GDestroyNotify, duk_require_pointer (ctx, 1));

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

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "NativeResource"))
    return 0;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  if (self->notify != NULL)
    self->notify (self->parent.value);

  g_slice_free (GumDukNativeResource, self);

  return 0;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_function_construct)
{
  GumDukCore * core = args->core;
  GCallback fn;
  GumDukHeapPtr rtype_value, atypes_array;
  const gchar * abi_str = NULL;
  GumDukNativeFunction * func;
  GumDukNativePointer * ptr;
  ffi_type * rtype;
  duk_size_t nargs_fixed, nargs_total, length, i;
  gboolean is_variadic;
  ffi_abi abi;

  if (!duk_is_constructor_call (ctx))
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR,
        "Use `new NativeFunction()` to create a new instance");
    duk_throw (ctx);
  }

  _gum_duk_args_parse (args, "pVA|s", &fn, &rtype_value, &atypes_array,
      &abi_str);

  func = g_slice_new0 (GumDukNativeFunction);
  ptr = &func->parent;
  ptr->value = GUM_FUNCPTR_TO_POINTER (fn);
  func->fn = fn;
  func->core = core;

  if (!gum_duk_get_ffi_type (ctx, rtype_value, &rtype, &func->data))
    goto invalid_return_type;

  duk_push_heapptr (ctx, atypes_array);

  length = duk_get_length (ctx, -1);
  nargs_fixed = nargs_total = length;
  is_variadic = FALSE;

  func->atypes = g_new (ffi_type *, nargs_total);

  for (i = 0; i != nargs_total; i++)
  {
    GumDukHeapPtr atype_value;
    ffi_type ** atype;
    gboolean is_marker;

    duk_get_prop_index (ctx, -1, (duk_uarridx_t) i);
    atype_value = duk_get_heapptr (ctx, -1);

    atype = &func->atypes[is_variadic ? i - 1 : i];

    if (duk_is_string (ctx, -1))
      is_marker = strcmp (duk_require_string (ctx, -1), "...") == 0;
    else
      is_marker = FALSE;

    if (is_marker)
    {
      if (is_variadic)
        goto unexpected_marker;

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else if (!gum_duk_get_ffi_type (ctx, atype_value, atype, &func->data))
    {
      goto invalid_argument_type;
    }

    duk_pop (ctx);
  }

  duk_pop (ctx);

  if (is_variadic)
    nargs_total--;

  if (abi_str != NULL)
  {
    if (!gum_duk_get_ffi_abi (ctx, abi_str, &abi))
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
  duk_push_heapptr (ctx, core->native_function_prototype);
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
    _gum_duk_throw (ctx, "only one variadic marker may be specified");
  }
compilation_failed:
  {
    gum_duk_native_function_finalize (func);
    _gum_duk_throw (ctx, "failed to compile function call interface");
  }

  g_assert_not_reached ();
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_native_function_finalize)
{
  GumDukNativeFunction * self;

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "NativeFunction"))
    return 0;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  gum_duk_native_function_finalize (self);

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

GUMJS_DEFINE_FUNCTION (gumjs_native_function_invoke)
{
  GumDukNativeFunction * self;
  GumDukCore * core;
  gsize nargs;
  ffi_type * rtype;
  gsize rsize, ralign;
  GumFFIValue * rvalue;
  void ** avalue;
  guint8 * avalues;
  GumExceptorScope exceptor_scope;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  core = self->core;
  nargs = self->cif.nargs;
  rtype = self->cif.rtype;

  if (args->count != nargs)
    _gum_duk_throw (ctx, "bad argument count");

  rsize = MAX (rtype->size, sizeof (gsize));
  ralign = MAX (rtype->alignment, sizeof (gsize));
  rvalue = g_alloca (rsize + ralign - 1);
  rvalue = GUM_ALIGN_POINTER (GumFFIValue *, rvalue, ralign);

  if (nargs > 0)
  {
    gsize arglist_alignment, offset, i;

    avalue = g_alloca (nargs * sizeof (void *));

    arglist_alignment = self->cif.arg_types[0]->alignment;
    avalues = g_alloca (self->arglist_size + arglist_alignment - 1);
    avalues = GUM_ALIGN_POINTER (guint8 *, avalues, arglist_alignment);

    /* Prefill with zero to clear high bits of values smaller than a pointer. */
    memset (avalues, 0, self->arglist_size);

    offset = 0;
    for (i = 0; i != nargs; i++)
    {
      ffi_type * t;
      GumFFIValue * v;

      t = self->cif.arg_types[i];
      offset = GUM_ALIGN_SIZE (offset, t->alignment);
      v = (GumFFIValue *) (avalues + offset);

      if (!gum_duk_get_ffi_value (ctx, i, t, args->core, v))
        _gum_duk_throw (ctx, "invalid argument value");
      avalue[i] = v;

      offset += t->size;
    }
  }
  else
  {
    avalue = NULL;
  }

  {
    GumDukScope scope = GUM_DUK_SCOPE_INIT (core);

    _gum_duk_scope_suspend (&scope);

    if (gum_exceptor_try (core->exceptor, &exceptor_scope))
    {
      ffi_call (&self->cif, self->fn, rvalue, avalue);
    }

    _gum_duk_scope_resume (&scope);
  }

  if (gum_exceptor_catch (core->exceptor, &exceptor_scope))
  {
    _gum_duk_throw_native (ctx, &exceptor_scope.exception, core);
  }

  gum_duk_push_ffi_value (ctx, rvalue, rtype, core);
  return 1;
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
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR,
        "Use `new NativeCallback()` to create a new instance");
    duk_throw (ctx);
  }

  _gum_duk_args_parse (args, "FVA|s", &func, &rtype_value, &atypes_array,
      &abi_str);

  callback = g_slice_new0 (GumDukNativeCallback);
  ptr = &callback->parent;
  _gum_duk_protect (ctx, func);
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

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "NativeCallback"))
    return 0;

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
  if (!heap_destruct)
    _gum_duk_unprotect (callback->core->current_ctx, callback->func);

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
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cpu_context_construct)
{
  (void) ctx;
  (void) args;

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_cpu_context_finalize)
{
  GumDukCpuContext * self;

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "CpuContext"))
    return 0;

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
                                gsize * reg)
{
  gpointer value;

  _gum_duk_args_parse (args, "p~", &value);

  if (self->access == GUM_CPU_CONTEXT_READONLY)
    _gum_duk_throw (ctx, "invalid operation");

  *reg = GPOINTER_TO_SIZE (value);
}

static GumDukWeakRef *
gum_duk_weak_ref_new (guint id,
                      GumDukHeapPtr target,
                      GumDukHeapPtr callback,
                      GumDukCore * core)
{
  GumDukWeakRef * ref;

  ref = g_slice_new (GumDukWeakRef);
  ref->id = id;
  ref->target = target;
  _gum_duk_protect (core->current_ctx, callback);
  ref->callback = callback;
  ref->core = core;

  return ref;
}

static void
gum_duk_weak_ref_clear (GumDukWeakRef * ref)
{
  g_clear_pointer (&ref->target, _gum_duk_weak_ref_free);
}

static void
gum_duk_weak_ref_free (GumDukWeakRef * ref)
{
  GumDukCore * core = ref->core;
  duk_context * ctx = core->current_ctx;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);

  gum_duk_weak_ref_clear (ref);

  duk_push_heapptr (ctx, ref->callback);
  _gum_duk_scope_call (&scope, 0);
  duk_pop (ctx);

  _gum_duk_unprotect (ctx, ref->callback);

  g_slice_free (GumDukWeakRef, ref);
}

static gint
gum_duk_core_schedule_callback (GumDukCore * self,
                                const GumDukArgs * args,
                                gboolean repeat)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self);
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

  id = ++self->last_callback_id;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new ((guint) delay);

  callback = gum_scheduled_callback_new (id, func, repeat, source, self);
  g_source_set_callback (source, gum_scheduled_callback_invoke, callback,
      (GDestroyNotify) gum_scheduled_callback_free);
  gum_duk_core_add_scheduled_callback (self, callback);

  _gum_duk_scope_suspend (&scope);
  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));
  _gum_duk_scope_resume (&scope);

  duk_push_number (args->ctx, id);
  return 1;
}

static void
gum_duk_core_add_scheduled_callback (GumDukCore * self,
                                     GumDukScheduledCallback * cb)
{
  self->scheduled_callbacks = g_slist_prepend (self->scheduled_callbacks, cb);
}

static gboolean
gum_duk_core_remove_scheduled_callback (GumDukCore * self,
                                        GumDukScheduledCallback * cb)
{
  GSList * link;

  link = g_slist_find (self->scheduled_callbacks, cb);
  if (link == NULL)
    return FALSE;

  self->scheduled_callbacks =
      g_slist_delete_link (self->scheduled_callbacks, link);
  return TRUE;
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
  _gum_duk_protect (core->current_ctx, func);
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

  g_source_unref (callback->source);

  g_slice_free (GumDukScheduledCallback, callback);
}

static gboolean
gum_scheduled_callback_invoke (gpointer user_data)
{
  GumDukScheduledCallback * self = user_data;
  GumDukCore * core = self->core;
  duk_context * ctx;
  GumDukScope scope;

  ctx = _gum_duk_scope_enter (&scope, self->core);

  duk_push_heapptr (ctx, self->func);
  _gum_duk_scope_call (&scope, 0);
  duk_pop (ctx);

  if (!self->repeat)
  {
    if (gum_duk_core_remove_scheduled_callback (core, self))
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
  _gum_duk_protect (core->current_ctx, callback);
  sink->callback = callback;
  sink->core = core;

  return sink;
}

static void
gum_duk_exception_sink_free (GumDukExceptionSink * sink)
{
  _gum_duk_unprotect (sink->core->current_ctx, sink->callback);
  g_slice_free (GumDukExceptionSink, sink);
}

static void
gum_duk_exception_sink_handle_exception (GumDukExceptionSink * self)
{
  GumDukCore * core = self->core;
  duk_context * ctx = core->current_ctx;
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
  _gum_duk_protect (core->current_ctx, callback);
  sink->callback = callback;
  sink->core = core;

  return sink;
}

static void
gum_duk_message_sink_free (GumDukMessageSink * sink)
{
  _gum_duk_unprotect (sink->core->current_ctx, sink->callback);
  g_slice_free (GumDukMessageSink, sink);
}

static void
gum_duk_message_sink_handle_message (GumDukMessageSink * self,
                                     const gchar * message,
                                     GumDukScope * scope)
{
  duk_context * ctx = self->core->current_ctx;

  duk_push_heapptr (ctx, self->callback);
  duk_push_string (ctx, message);
  _gum_duk_scope_call (scope, 1);
  duk_pop (ctx);
}

static const GumFFITypeMapping gum_ffi_type_mappings[] =
{
  { "void", &ffi_type_void },
  { "pointer", &ffi_type_pointer },
  { "int", &ffi_type_sint },
  { "uint", &ffi_type_uint },
  { "long", &ffi_type_slong },
  { "ulong", &ffi_type_ulong },
  { "char", &ffi_type_schar },
  { "uchar", &ffi_type_uchar },
  { "float", &ffi_type_float },
  { "double", &ffi_type_double },
  { "int8", &ffi_type_sint8 },
  { "uint8", &ffi_type_uint8 },
  { "int16", &ffi_type_sint16 },
  { "uint16", &ffi_type_uint16 },
  { "int32", &ffi_type_sint32 },
  { "uint32", &ffi_type_uint32 },
  { "int64", &ffi_type_sint64 },
  { "uint64", &ffi_type_uint64 },
  { "bool", &ffi_type_schar }
};

static const GumFFIABIMapping gum_ffi_abi_mappings[] =
{
  { "default", FFI_DEFAULT_ABI },
#if defined (X86_WIN64)
  { "win64", FFI_WIN64 },
#elif defined (X86_ANY) && GLIB_SIZEOF_VOID_P == 8
  { "unix64", FFI_UNIX64 },
#elif defined (X86_ANY) && GLIB_SIZEOF_VOID_P == 4
  { "sysv", FFI_SYSV },
  { "stdcall", FFI_STDCALL },
  { "thiscall", FFI_THISCALL },
  { "fastcall", FFI_FASTCALL },
# if defined (X86_WIN32)
  { "mscdecl", FFI_MS_CDECL },
# endif
#elif defined (ARM)
  { "sysv", FFI_SYSV },
# if GLIB_SIZEOF_VOID_P == 4
  { "vfp", FFI_VFP },
# endif
#endif
};

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

    for (i = 0; i != G_N_ELEMENTS (gum_ffi_type_mappings); i++)
    {
      const GumFFITypeMapping * m = &gum_ffi_type_mappings[i];

      if (strcmp (m->name, type_name) == 0)
      {
        *type = m->type;
        success = TRUE;
        break;
      }
    }
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
  guint i;

  for (i = 0; i != G_N_ELEMENTS (gum_ffi_abi_mappings); i++)
  {
    const GumFFIABIMapping * m = &gum_ffi_abi_mappings[i];

    if (strcmp (name, m->name) == 0)
    {
      *abi = m->abi;
      return TRUE;
    }
  }

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
