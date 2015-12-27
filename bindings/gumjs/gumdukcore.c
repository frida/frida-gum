/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukcore.h"

#include "gumdukmacros.h"

#include <ffi.h>

typedef struct _GumDukNativeFunction GumDukNativeFunction;
typedef struct _GumDukNativeCallback GumDukNativeCallback;
typedef union _GumFFIValue GumFFIValue;
typedef struct _GumFFITypeMapping GumFFITypeMapping;
typedef struct _GumFFIABIMapping GumFFIABIMapping;

struct _GumDukWeakRef
{
  guint id;
  GumDukWeakRef * target;
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

  gpointer fn;
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

GUMJS_DECLARE_FUNCTION (gumjs_set_timeout)
GUMJS_DECLARE_FUNCTION (gumjs_set_interval)
GUMJS_DECLARE_FUNCTION (gumjs_clear_timer)
GUMJS_DECLARE_FUNCTION (gumjs_gc)
GUMJS_DECLARE_FUNCTION (gumjs_send)
GUMJS_DECLARE_FUNCTION (gumjs_set_unhandled_exception_callback)
GUMJS_DECLARE_FUNCTION (gumjs_set_incoming_message_callback)
GUMJS_DECLARE_FUNCTION (gumjs_wait_for_event)

GUMJS_DECLARE_GETTER (gumjs_script_get_file_name)
GUMJS_DECLARE_GETTER (gumjs_script_get_source_map_data)

GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_bind)
GUMJS_DECLARE_FUNCTION (gumjs_weak_ref_unbind)

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

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_function_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_function_finalize)
static void gum_duk_native_function_finalize (
    GumDukNativeFunction * func);
GUMJS_DECLARE_FUNCTION (gumjs_native_function_invoke)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_callback_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_callback_finalize)
static void gum_duk_native_callback_finalize (
    GumDukNativeCallback * func);
static void gum_duk_native_callback_invoke (ffi_cif * cif,
    void * return_value, void ** args, void * user_data);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_cpu_context_construct)
GUMJS_DECLARE_FINALIZER (gumjs_cpu_context_finalize)
static gboolean gumjs_cpu_context_set_register (GumDukCpuContext * self,
    duk_context * ctx, const GumDukArgs * args, gsize * reg);

static gboolean gum_handle_unprotect_requests_when_idle (gpointer user_data);
static void gum_handle_unprotect_requests (GumDukCore * self);

static GumDukWeakRef * gum_duk_weak_ref_new (guint id, GumDukHeapPtr target,
    GumDukHeapPtr callback, GumDukCore * core);
static void gum_duk_weak_ref_clear (GumDukWeakRef * ref);
static void gum_duk_weak_ref_free (GumDukWeakRef * ref);
static void gum_duk_weak_ref_on_weak_notify (GumDukWeakRef * self);

static int gum_duk_core_schedule_callback (GumDukCore * self,
    const GumDukArgs * args, gboolean repeat);
static void gum_duk_core_add_scheduled_callback (GumDukCore * self,
    GumDukScheduledCallback * cb);
static void gum_duk_core_remove_scheduled_callback (GumDukCore * self,
    GumDukScheduledCallback * cb);

static GumDukScheduledCallback * gum_scheduled_callback_new (guint id,
    GumDukHeapPtr func, gboolean repeat, GSource * source, GumDukCore * core);
static void gum_scheduled_callback_free (GumDukScheduledCallback * callback);
static gboolean gum_scheduled_callback_invoke (gpointer user_data);

static GumDukExceptionSink * gum_duk_exception_sink_new (GumDukHeapPtr callback,
    GumDukCore * core);
static void gum_duk_exception_sink_free (GumDukExceptionSink * sink);
static void gum_duk_exception_sink_handle_exception (
    GumDukExceptionSink * self, const gchar * exception);

static GumDukMessageSink * gum_duk_message_sink_new (GumDukHeapPtr callback,
    GumDukCore * core);
static void gum_duk_message_sink_free (GumDukMessageSink * sink);
static void gum_duk_message_sink_handle_message (GumDukMessageSink * self,
    const gchar * message);

static gboolean gumjs_ffi_type_try_get (duk_context * ctx, GumDukValue * value,
    ffi_type ** type, GSList ** data);
static gboolean gumjs_ffi_abi_try_get (duk_context * ctx, const gchar * name,
    ffi_abi * abi);
static gboolean gumjs_value_to_ffi_type (duk_context * ctx, GumDukValue * svalue,
    const ffi_type * type, GumDukCore * core, GumFFIValue * value);
static gboolean gumjs_value_from_ffi_type (duk_context * ctx,
    const GumFFIValue * value, const ffi_type * type, GumDukCore * core,
    GumDukValue ** svalue);

static const GumDukPropertyEntry gumjs_script_values[] =
{
  { "fileName", gumjs_script_get_file_name, NULL, GUMJS_RO },
  { "_sourceMapData", gumjs_script_get_source_map_data, NULL, GUMJS_RO },

  { NULL, NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_weak_ref_functions[] =
{
  { "bind", gumjs_weak_ref_bind, 0 },
  { "unbind", gumjs_weak_ref_unbind, 0 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_native_pointer_functions[] =
{
  { "isNull", gumjs_native_pointer_is_null, 0 },
  { "add", gumjs_native_pointer_add, 0 },
  { "sub", gumjs_native_pointer_sub, 0 },
  { "and", gumjs_native_pointer_and, 0 },
  { "or", gumjs_native_pointer_or, 0 },
  { "xor", gumjs_native_pointer_xor, 0 },
  { "shr", gumjs_native_pointer_shr, 0 },
  { "shl", gumjs_native_pointer_shl, 0 },
  { "compare", gumjs_native_pointer_compare, 0 },
  { "toInt32", gumjs_native_pointer_to_int32, 0 },
  { "toString", gumjs_native_pointer_to_string, 0 },
  { "toJSON", gumjs_native_pointer_to_json, 0 },
  { "toMatchPattern", gumjs_native_pointer_to_match_pattern, 0 },

  { NULL, NULL, 0 }
};

#define GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED(A, R) \
  GUMJS_DEFINE_GETTER (gumjs_cpu_context_get_##A) \
  { \
    GumDukCpuContext * self; \
    duk_push_this (ctx); \
    self = _gumjs_get_private_data (ctx, duk_get_heapptr (ctx, -1)); \
    duk_pop (ctx); \
    \
    duk_push_heapptr (ctx, _gumjs_native_pointer_new (ctx, \
        GSIZE_TO_POINTER (self->handle->R), args->core)); \
    return 1; \
  } \
  \
  GUMJS_DEFINE_SETTER (gumjs_cpu_context_set_##A) \
  { \
    GumDukCpuContext * self; \
    duk_push_this (ctx); \
    self = _gumjs_get_private_data (ctx, duk_get_heapptr (ctx, -1)); \
    duk_pop (ctx); \
    \
    gumjs_cpu_context_set_register (self, ctx, args, \
        (gsize *) &self->handle->R); \
    return 0; \
  }
#define GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR(R) \
  GUMJS_DEFINE_CPU_CONTEXT_ACCESSOR_ALIASED (R, R)

#define GUMJS_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED(A, R) \
  { G_STRINGIFY (A), gumjs_cpu_context_get_##R, gumjs_cpu_context_set_##R, \
    GUMJS_RW }
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
#endif

  { NULL, NULL, NULL, 0 }
};

void
_gum_duk_core_init (GumDukCore * self,
                    GumDukScript * script,
                    GumDukMessageEmitter message_emitter,
                    GumScriptScheduler * scheduler,
                    duk_context * ctx)
{
  g_object_get (script, "backend", &self->backend, NULL);
  g_object_unref (self->backend);

  self->script = script;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->ctx = ctx;

  g_mutex_init (&self->mutex);
  g_cond_init (&self->event_cond);

  self->unprotect_requests = NULL;
  self->unprotect_source = NULL;

  self->weak_refs = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_duk_weak_ref_free);

  self->native_resources = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) _gumjs_native_resource_free);


  duk_push_pointer (ctx, self);
  duk_put_global_string (ctx, "\xff" "core");

  duk_push_object (ctx);
  // [ newobject ]
  duk_push_string (ctx, FRIDA_VERSION);
  // [ newobject FRIDA_VERSION ]
  duk_put_prop_string (ctx, -2, "version");
  // [ newobject ]
  duk_put_global_string (ctx, "Frida");
  // [ ]

  duk_push_object (ctx);
  // [ newobject ]
  duk_push_string (ctx, "DUK");
  // [ newobject DUK ]
  duk_put_prop_string (ctx, -2, "runtime");
  // [ newobject ]
  duk_put_global_string (ctx, "Script");
  // [ ]
  _gumjs_duk_add_properties_to_class (ctx, "Script", gumjs_script_values);

  duk_push_object (ctx);
  // [ newobject ]
  duk_push_object (ctx);
  // [ newobject newproto ]
  duk_put_function_list (ctx, -1, gumjs_weak_ref_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  // [ newobject ]
  duk_put_global_string (ctx, "WeakRef");
  // [ ]

  GUMJS_ADD_GLOBAL_FUNCTION ("setTimeout", gumjs_set_timeout, 0);
  GUMJS_ADD_GLOBAL_FUNCTION ("clearTimeout", gumjs_clear_timer, 0);
  GUMJS_ADD_GLOBAL_FUNCTION ("setInterval", gumjs_set_interval, 0)
  GUMJS_ADD_GLOBAL_FUNCTION ("clearInterval", gumjs_clear_timer, 0)
  GUMJS_ADD_GLOBAL_FUNCTION ("gc", gumjs_gc, 0)
  GUMJS_ADD_GLOBAL_FUNCTION ("_send", gumjs_send, 0)
  GUMJS_ADD_GLOBAL_FUNCTION ("_setUnhandledExceptionCallback", gumjs_set_unhandled_exception_callback, 0)
  GUMJS_ADD_GLOBAL_FUNCTION ("_setIncomingMessageCallback", gumjs_set_incoming_message_callback, 0)
  GUMJS_ADD_GLOBAL_FUNCTION ("_waitForEvent", gumjs_wait_for_event, 0)

  duk_push_c_function (ctx, gumjs_native_pointer_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct newprotoobj ]
  duk_put_function_list (ctx, -1, gumjs_native_pointer_functions);
  duk_push_c_function (ctx, gumjs_native_pointer_finalize, 0);
  // [ construct newprotoobj finalize ]
  duk_set_finalizer (ctx, -2);
  // [ construct newprotoobj ]
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  duk_put_global_string (ctx, "NativePointer");
  // [ ]

  _gumjs_duk_create_subclass (ctx, "NativePointer", "NativeFunction",
      gumjs_native_function_construct, gumjs_native_function_finalize);
  duk_get_global_string (ctx, "NativeFunction");
  // [ NativeFunction ]
  duk_get_prop_string (ctx, -1, "prototype");
  // [ NativeFunction prototype ]
  duk_push_c_function (ctx, gumjs_native_function_invoke, 0);
  // [ NativeFunction prototype invoke ]
  duk_put_prop_string (ctx, -2, "invoke");
  // [ NativeFunction prototype ]
  duk_pop_2 (ctx);
  // [ ]

  _gumjs_duk_create_subclass (ctx, "NativePointer", "NativeCallback",
      gumjs_native_callback_construct, gumjs_native_callback_finalize);

  duk_push_c_function (ctx, gumjs_cpu_context_construct, 0);
  // [ construct ]
  duk_push_object (ctx);
  // [ construct newprotoobj ]
  duk_push_c_function (ctx, gumjs_cpu_context_finalize, 0);
  // [ construct newprotoobj finalize ]
  duk_set_finalizer (ctx, -2);
  // [ construct newprotoobj ]
  duk_put_prop_string (ctx, -2, "prototype");
  // [ construct ]
  duk_put_global_string (ctx, "CpuContext");
  // [ ]
  _gumjs_duk_add_properties_to_class (ctx, "CpuContext", gumjs_cpu_context_values);
}

void
_gum_duk_core_flush (GumDukCore * self)
{
  GMainContext * context;

  gum_script_scheduler_flush_by_tag (self->scheduler, self);

  GUM_DUK_CORE_LOCK (self);
  g_clear_pointer (&self->unprotect_source, g_source_destroy);
  gum_handle_unprotect_requests (self);
  GUM_DUK_CORE_UNLOCK (self);

  context = gum_script_scheduler_get_js_context (self->scheduler);
  while (g_main_context_pending (context))
    g_main_context_iteration (context, FALSE);

  GUM_DUK_CORE_LOCK (self);
  g_hash_table_remove_all (self->weak_refs);
  GUM_DUK_CORE_UNLOCK (self);
}

void
_gum_duk_core_dispose (GumDukCore * self)
{
  GUM_DUK_CORE_LOCK (self);

  g_clear_pointer (&self->native_resources, g_hash_table_unref);

  while (self->scheduled_callbacks != NULL)
  {
    GumDukScheduledCallback * cb =
        (GumDukScheduledCallback *) self->scheduled_callbacks->data;
    self->scheduled_callbacks = g_slist_delete_link (
        self->scheduled_callbacks, self->scheduled_callbacks);
    GUM_DUK_CORE_UNLOCK (self);
    g_source_destroy (cb->source);
    GUM_DUK_CORE_LOCK (self);
  }

  GUM_DUK_CORE_UNLOCK (self);

  g_clear_pointer (&self->unhandled_exception_sink,
      gum_duk_exception_sink_free);

  g_clear_pointer (&self->incoming_message_sink, gum_duk_message_sink_free);

  g_clear_pointer (&self->exceptor, g_object_unref);

  self->ctx = NULL;
}

void
_gum_duk_core_finalize (GumDukCore * self)
{
  GUM_DUK_CORE_LOCK (self);
  g_clear_pointer (&self->weak_refs, g_hash_table_unref);
  GUM_DUK_CORE_UNLOCK (self);

  g_mutex_clear (&self->mutex);
  g_cond_clear (&self->event_cond);
}

void
_gum_duk_core_emit_message (GumDukCore * self,
                            const gchar * message,
                            GBytes * data)
{
  self->message_emitter (self->script, message, data);
}

void
_gum_duk_core_post_message (GumDukCore * self,
                            const gchar * message)
{
  GUM_DUK_CORE_LOCK (self);

  if (self->incoming_message_sink != NULL)
  {
    GumDukScope scope;

    _gum_duk_scope_enter (&scope, self);

    gum_duk_message_sink_handle_message (self->incoming_message_sink,
        message);
    GUM_DUK_CORE_UNLOCK (self);

    _gum_duk_scope_leave (&scope);

    GUM_DUK_CORE_LOCK (self);
    self->event_count++;
    g_cond_broadcast (&self->event_cond);
  }

  GUM_DUK_CORE_UNLOCK (self);
}

void
_gum_duk_core_unprotect_later (GumDukCore * self,
                               GumDukHeapPtr value)
{
  if (self->ctx == NULL || value == NULL)
    return;

  GUM_DUK_CORE_LOCK (self);

  self->unprotect_requests = g_slist_prepend (self->unprotect_requests,
      (gpointer) value);
  if (self->unprotect_source == NULL)
  {
    GSource * source;

    source = g_idle_source_new ();
    g_source_set_callback (source, gum_handle_unprotect_requests_when_idle,
        self, NULL);
    g_source_attach (source,
        gum_script_scheduler_get_js_context (self->scheduler));
    g_source_unref (source);
    self->unprotect_source = source;
  }

  GUM_DUK_CORE_UNLOCK (self);
}

static gboolean
gum_handle_unprotect_requests_when_idle (gpointer user_data)
{
  GumDukCore * self = user_data;

  GUM_DUK_CORE_LOCK (self);
  gum_handle_unprotect_requests (self);
  self->unprotect_source = NULL;
  GUM_DUK_CORE_UNLOCK (self);

  return FALSE;
}

static void
gum_handle_unprotect_requests (GumDukCore * self)
{
  //duk_context * ctx = self->ctx;

  while (self->unprotect_requests != NULL)
  {
    //GumDukHeapPtr value = self->unprotect_requests->data;
    self->unprotect_requests = g_slist_delete_link (self->unprotect_requests,
        self->unprotect_requests);
    GUM_DUK_CORE_UNLOCK (self);
    //JSValueUnprotect (ctx, value);
    GUM_DUK_CORE_LOCK (self);
  }
}

void
_gum_duk_core_push_job (GumDukCore * self,
                        GumScriptJobFunc job_func,
                        gpointer data,
                        GDestroyNotify data_destroy)
{
  gum_script_scheduler_push_job_on_thread_pool (self->scheduler, job_func,
      data, data_destroy, self);
}

void
_gum_duk_scope_enter (GumDukScope * self,
                      GumDukCore * core)
{
  self->core = core;
  self->exception = NULL;
}

void
_gum_duk_scope_flush (GumDukScope * self)
{
  GumDukCore * core = self->core;

  GUM_DUK_CORE_LOCK (core);

  if (self->exception != NULL && core->unhandled_exception_sink != NULL)
  {
    gum_duk_exception_sink_handle_exception (core->unhandled_exception_sink,
        self->exception);
    self->exception = NULL;
  }

  GUM_DUK_CORE_UNLOCK (core);
}

void
_gum_duk_scope_leave (GumDukScope * self)
{
  _gum_duk_scope_flush (self);
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
      duk_push_null (ctx);
    g_free (data);

    g_free (data_encoded);
  }
  g_match_info_free (match_info);
  g_regex_unref (regex);

  g_free (source);

  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_bind)
{
  GumDukValue * target;
  GumDukHeapPtr callback;
  guint id;
  GumDukWeakRef * ref;

  if (!_gumjs_args_parse (ctx, "VF", &target, &callback))
  {
    duk_push_null (ctx);
    return 1;
  }

  switch (target->type)
  {
    case DUK_TYPE_STRING:
    case DUK_TYPE_OBJECT:
      break;
    case DUK_TYPE_UNDEFINED:
    case DUK_TYPE_NULL:
    case DUK_TYPE_BOOLEAN:
    case DUK_TYPE_NUMBER:
      goto invalid_type;
    default:
      g_assert_not_reached ();
  }

  id = ++args->core->last_weak_ref_id;

  ref = gum_duk_weak_ref_new (id, target->data._heapptr, callback, args->core);
  GUM_DUK_CORE_LOCK (args->core);
  g_hash_table_insert (args->core->weak_refs, GUINT_TO_POINTER (id), ref);
  GUM_DUK_CORE_UNLOCK (args->core);

  duk_push_int (ctx, id);
  return 1;

invalid_type:
  {
    _gumjs_throw (ctx, "expected a non-primitive value");
    return 0;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_weak_ref_unbind)
{
  guint id;
  gboolean removed;
  GumDukCore * self = args->core;

  if (!_gumjs_args_parse (ctx, "u", &id))
  {
    duk_push_null (ctx);
    return 1;
  }

  GUM_DUK_CORE_LOCK (self);
  removed = !g_hash_table_remove (self->weak_refs, GUINT_TO_POINTER (id));
  GUM_DUK_CORE_UNLOCK (self);

  duk_push_boolean (ctx, removed);
  return 1;
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
  GumDukScheduledCallback * callback = NULL;
  GSList * cur;

  if (!_gumjs_args_parse (ctx, "i", &id))
  {
    duk_push_null (ctx);
    return 1;
  }

  GUM_DUK_CORE_LOCK (self);

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

  GUM_DUK_CORE_UNLOCK (self);

  if (callback != NULL)
    g_source_destroy (callback->source);

  duk_push_boolean (ctx, callback != NULL);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_gc)
{
  duk_gc (ctx, 0);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_send)
{
  gchar * message;
  GBytes * data = NULL;

  if (!_gumjs_args_parse (ctx, "s|B?", &message, &data))
  {
    duk_push_null (ctx);
    return 1;
  }

  _gum_duk_core_emit_message (args->core, message, data);

  g_bytes_unref (data);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  GumDukCore * self = args->core;
  GumDukHeapPtr callback;
  GumDukExceptionSink * new_sink, * old_sink;

  if (!_gumjs_args_parse (ctx, "F?", &callback))
  {
    duk_push_null (ctx);
    return 1;
  }

  new_sink = (callback != NULL)
      ? gum_duk_exception_sink_new (callback, self)
      : NULL;

  GUM_DUK_CORE_LOCK (self);
  old_sink = self->unhandled_exception_sink;
  self->unhandled_exception_sink = new_sink;
  GUM_DUK_CORE_UNLOCK (self);

  if (old_sink != NULL)
    gum_duk_exception_sink_free (old_sink);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_incoming_message_callback)
{
  GumDukCore * self = args->core;
  GumDukHeapPtr callback;
  GumDukMessageSink * new_sink, * old_sink;

  if (!_gumjs_args_parse (ctx, "F?", &callback))
  {
    duk_push_null (ctx);
    return 1;
  }

  new_sink = (callback != NULL)
      ? gum_duk_message_sink_new (callback, self)
      : NULL;

  GUM_DUK_CORE_LOCK (self);
  old_sink = self->incoming_message_sink;
  self->incoming_message_sink = new_sink;
  GUM_DUK_CORE_UNLOCK (self);

  if (old_sink != NULL)
    gum_duk_message_sink_free (old_sink);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_wait_for_event)
{
  GumDukCore * self = args->core;
  guint start_count;

  GUM_DUK_CORE_LOCK (self);
  start_count = self->event_count;
  while (self->event_count == start_count)
    g_cond_wait (&self->event_cond, &self->mutex);
  GUM_DUK_CORE_UNLOCK (self);

  return 0;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_pointer_construct)
{
  gsize ptr = 0;

  if (!_gumjs_args_parse (ctx, "|p~", &ptr))
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_heapptr (ctx,
      _gumjs_native_pointer_new (ctx, GSIZE_TO_POINTER (ptr), args->core));
  return 1;
}

GUMJS_DEFINE_FINALIZER (gumjs_native_pointer_finalize)
{
  GumDukNativePointer * self = _gumjs_get_private_data (ctx, duk_require_heapptr(ctx, 0));

  g_slice_free1 (self->instance_size, self);
  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_is_null)
{
  GumDukHeapPtr this_object;
  duk_push_this (ctx);
  this_object = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  duk_push_boolean(ctx,
      _gumjs_native_pointer_value (ctx, this_object) == NULL);
  return 1;
}

#define GUM_DEFINE_NATIVE_POINTER_OP_IMPL(name, op) \
  GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
  { \
    gpointer rhs_ptr; \
    gsize lhs, rhs; \
    gpointer result; \
    GumDukHeapPtr this_object; \
    \
    if (!_gumjs_args_parse (ctx, "p~", &rhs_ptr)) \
    { \
      duk_push_null (ctx); \
      return 1; \
    } \
    \
    duk_push_this (ctx); \
    this_object = duk_require_heapptr (ctx, -1); \
    duk_pop (ctx); \
    \
    lhs = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (ctx, this_object)); \
    rhs = GPOINTER_TO_SIZE (rhs_ptr); \
    \
    result = GSIZE_TO_POINTER (lhs op rhs); \
    \
    duk_push_heapptr (ctx, _gumjs_native_pointer_new (ctx, result, args->core)); \
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
  gpointer rhs_ptr;
  gsize lhs, rhs;
  gint result;
  GumDukHeapPtr this_object;

  if (!_gumjs_args_parse (ctx, "p~", &rhs_ptr))
  {
    duk_push_null (ctx);
    return 1;
  }

  duk_push_this (ctx);
  this_object = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  lhs = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (ctx, this_object));
  rhs = GPOINTER_TO_SIZE (rhs_ptr);

  result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  duk_push_int (ctx, result);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_int32)
{
  gint32 result;
  GumDukHeapPtr this_object;

  duk_push_this (ctx);
  this_object = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  result = (gint32)
      GPOINTER_TO_SIZE (_gumjs_native_pointer_value (ctx, this_object));

  duk_push_int (ctx, result);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_string)
{
  gint radix = -1;
  gboolean radix_specified;
  gsize ptr;
  gchar str[32];
  GumDukHeapPtr this_object;

  duk_push_this (ctx);
  this_object = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  if (!_gumjs_args_parse (ctx, "|u", &radix))
  {
    duk_push_null (ctx);
    return 1;
  }
  radix_specified = radix != -1;
  if (!radix_specified)
    radix = 16;
  else if (radix != 10 && radix != 16)
    goto unsupported_radix;

  ptr = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (ctx, this_object));

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

unsupported_radix:
  {
    _gumjs_throw (ctx, "unsupported radix");
    duk_push_null (ctx);
    return 0;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_json)
{
  gsize ptr;
  gchar str[32];
  GumDukHeapPtr this_object;

  duk_push_this (ctx);
  this_object = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  ptr = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (ctx, this_object));

  sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr);

  duk_push_string (ctx, str);
  return 1;
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_match_pattern)
{
  gsize ptr;
  gchar str[24];
  GumDukHeapPtr this_object;
  gint src, dst;
  const gint num_bits = GLIB_SIZEOF_VOID_P * 8;
  const gchar nibble_to_char[] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f'
  };
  duk_push_this (ctx);
  this_object = duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  ptr = GPOINTER_TO_SIZE (_gumjs_native_pointer_value (ctx, this_object));

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

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_function_construct)
{
  GumDukHeapPtr result = NULL;
  GumDukCore * core = args->core;
  GumDukNativeFunction * func;
  GumDukNativePointer * ptr;
  GumDukValue * rtype_value;
  ffi_type * rtype;
  GumDukHeapPtr atypes_array;
  guint nargs_fixed, nargs_total, length, i;
  gboolean is_variadic;
  gchar * abi_str = NULL;
  ffi_abi abi;

  func = g_slice_new0 (GumDukNativeFunction);

  ptr = &func->parent;
  ptr->instance_size = sizeof (GumDukNativeFunction);

  func->core = core;

  if (!_gumjs_args_parse (ctx, "pVA|s", &func->fn, &rtype_value, &atypes_array,
      &abi_str))
    goto error;

  ptr->value = func->fn;

  if (!gumjs_ffi_type_try_get (ctx, rtype_value, &rtype, &func->data))
    goto error;

  if (!_gumjs_object_try_get_uint (ctx, atypes_array, "length", &length))
    goto error;

  nargs_fixed = nargs_total = length;
  is_variadic = FALSE;
  func->atypes = g_new (ffi_type *, nargs_total);
  duk_push_heapptr (ctx, atypes_array);
  for (i = 0; i != nargs_total; i++)
  {
    GumDukValue * atype_value;
    gchar * name;
    gboolean is_marker;

    duk_get_prop_index (ctx, -1, i);
    atype_value = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);

    if (atype_value == NULL)
      goto error;

    if (_gumjs_value_string_try_get (ctx, atype_value, &name))
    {
      is_marker = strcmp (name, "...") == 0;
    }
    else
    {
      is_marker = FALSE;
    }

    if (is_marker)
    {
      if (is_variadic)
        goto unexpected_marker;

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else if (!gumjs_ffi_type_try_get (ctx, atype_value,
        &func->atypes[is_variadic ? i - 1 : i], &func->data))
    {
      g_free (atype_value);
      goto error;
    }
    g_free (atype_value);
  }
  duk_pop (ctx);
  if (is_variadic)
    nargs_total--;

  if (abi_str != NULL)
  {
    if (!gumjs_ffi_abi_try_get (ctx, abi_str, &abi))
      goto error;
  }
  else
  {
    abi = FFI_DEFAULT_ABI;
  }

  if (is_variadic)
  {
    if (ffi_prep_cif_var (&func->cif, abi, nargs_fixed, nargs_total, rtype,
        func->atypes) != FFI_OK)
      goto compilation_failed;
  }
  else
  {
    if (ffi_prep_cif (&func->cif, abi, nargs_total, rtype,
        func->atypes) != FFI_OK)
      goto compilation_failed;
  }

  for (i = 0; i != nargs_total; i++)
  {
    ffi_type * t = func->atypes[i];

    func->arglist_size = GUM_ALIGN_SIZE (func->arglist_size, t->alignment);
    func->arglist_size += t->size;
  }

  duk_get_global_string (ctx, "NativeFunction");
  // [ NativeFunction ]
  duk_new (ctx, 0);
  // [ nativefuncinst ]
  result = duk_require_heapptr (ctx, -1);
  _gumjs_set_private_data (ctx, result, func);
  duk_pop (ctx);
  // []

  goto beach;

unexpected_marker:
  {
    _gumjs_throw (ctx, "only one variadic marker may be specified");
    goto error;
  }
compilation_failed:
  {
    _gumjs_throw (ctx, "failed to compile function call interface");
    goto error;
  }
error:
  {
    gum_duk_native_function_finalize (func);
    g_slice_free (GumDukNativeFunction, func);

    goto beach;
  }
beach:
  {
    g_free (abi_str);

    duk_push_heapptr (ctx, result);
    return 1;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_native_function_finalize)
{
  GumDukNativeFunction * self = _gumjs_get_private_data (ctx, duk_require_heapptr (ctx, 0));

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
  GumExceptorScope scope;
  GumDukValue * result;

  duk_push_this (ctx);
  self = _gumjs_get_private_data (ctx, duk_require_heapptr (ctx, -1));
  duk_pop (ctx);

  core = self->core;
  nargs = self->cif.nargs;
  rtype = self->cif.rtype;

  if (args->count != nargs)
    goto bad_argument_count;

  rsize = MAX (rtype->size, sizeof (gsize));
  ralign = MAX (rtype->alignment, sizeof (gsize));
  rvalue = g_alloca (rsize + ralign - 1);
  rvalue = GUM_ALIGN_POINTER (GumFFIValue *, rvalue, ralign);

  if (nargs > 0)
  {
    gsize arglist_alignment, offset;

    avalue = g_alloca (nargs * sizeof (void *));

    arglist_alignment = self->cif.arg_types[0]->alignment;
    avalues = g_alloca (self->arglist_size + arglist_alignment - 1);
    avalues = GUM_ALIGN_POINTER (guint8 *, avalues, arglist_alignment);

    /* Prefill with zero to clear high bits of values smaller than a pointer. */
    memset (avalues, 0, self->arglist_size);

    offset = 0;
    for (gsize i = 0; i != nargs; i++)
    {
      ffi_type * t;
      GumFFIValue * v;
      GumDukValue * arg_value;

      t = self->cif.arg_types[i];
      offset = GUM_ALIGN_SIZE (offset, t->alignment);
      v = (GumFFIValue *) (avalues + offset);

      arg_value = _gumjs_get_value (ctx, i);
      if (!gumjs_value_to_ffi_type (ctx, arg_value, t, args->core, v))
      {
        g_free (arg_value);
        goto error;
      }
      g_free (arg_value);
      avalue[i] = v;

      offset += t->size;
    }
  }
  else
  {
    avalue = NULL;
  }

  if (gum_exceptor_try (core->exceptor, &scope))
  {
    ffi_call (&self->cif, FFI_FN (self->fn), rvalue, avalue);
  }

  if (gum_exceptor_catch (core->exceptor, &scope))
  {
    _gumjs_throw_native (ctx, &scope.exception, core);
    goto error;
  }

  if (rtype != &ffi_type_void)
  {
    if (!gumjs_value_from_ffi_type (ctx, rvalue, rtype, core, &result))
      goto error;
  }
  else
  {
    duk_push_undefined (ctx);
    result = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }

  /* TODO: what to return!? */
  duk_push_pointer (ctx, result);
  return 1;

bad_argument_count:
  {
    _gumjs_throw (ctx, "bad argument count");
    goto error;
  }
error:
  {
    duk_push_null (ctx);
    return 1;
  }
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_callback_construct)
{
  GumDukHeapPtr result = NULL;
  GumDukCore * core = args->core;
  GumDukNativeCallback * callback;
  GumDukNativePointer * ptr;
  GumDukHeapPtr func;
  GumDukValue * rtype_value;
  ffi_type * rtype;
  GumDukHeapPtr atypes_array;
  guint nargs, i;
  gchar * abi_str = NULL;
  ffi_abi abi;

  callback = g_slice_new0 (GumDukNativeCallback);

  ptr = &callback->parent;
  ptr->instance_size = sizeof (GumDukNativeCallback);

  callback->core = core;

  if (!_gumjs_args_parse (ctx, "FVA|s", &func, &rtype_value, &atypes_array,
      &abi_str))
    goto error;

  //JSValueProtect (ctx, func);
  callback->func = func;

  if (!gumjs_ffi_type_try_get (ctx, rtype_value, &rtype, &callback->data))
  {
    g_free (rtype_value);
    goto error;
  }
  g_free (rtype_value);

  if (!_gumjs_object_try_get_uint (ctx, atypes_array, "length", &nargs))
    goto error;

  callback->atypes = g_new (ffi_type *, nargs);
  duk_push_heapptr (ctx, atypes_array);
  for (i = 0; i != nargs; i++)
  {
    GumDukValue * atype_value;

    duk_get_prop_index (ctx, -1, i);
    atype_value = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);

    if (atype_value == NULL)
      goto error;

    if (!gumjs_ffi_type_try_get (ctx, atype_value, &callback->atypes[i],
        &callback->data))
    {
      g_free (atype_value);
      goto error;
    }
    g_free (atype_value);
  }

  if (abi_str != NULL)
  {
    if (!gumjs_ffi_abi_try_get (ctx, abi_str, &abi))
      goto error;
  }
  else
  {
    abi = FFI_DEFAULT_ABI;
  }

  callback->closure = ffi_closure_alloc (sizeof (ffi_closure), &ptr->value);
  if (callback->closure == NULL)
    goto alloc_failed;

  if (ffi_prep_cif (&callback->cif, abi, nargs, rtype,
      callback->atypes) != FFI_OK)
    goto compilation_failed;

  if (ffi_prep_closure_loc (callback->closure, &callback->cif,
      gum_duk_native_callback_invoke, callback, ptr->value) != FFI_OK)
    goto prepare_failed;

  duk_get_global_string (ctx, "NativeCallback");
  // [ NativeCallback ]
  duk_new (ctx, 0);
  // [ nativecallbackinst ]
  result = duk_require_heapptr (ctx, -1);
  _gumjs_set_private_data (ctx, result, callback);
  duk_pop (ctx);
  // []

  goto beach;

alloc_failed:
  {
    _gumjs_throw (ctx, "failed to allocate closure");
    goto error;
  }
compilation_failed:
  {
    _gumjs_throw (ctx, "failed to compile function call interface");
    goto error;
  }
prepare_failed:
  {
    _gumjs_throw (ctx, "failed to prepare closure");
    goto error;
  }
error:
  {
    gum_duk_native_callback_finalize (callback);
    g_slice_free (GumDukNativeCallback, callback);

    goto beach;
  }
beach:
  {
    g_free (abi_str);

    duk_push_heapptr (ctx, result);
    return 1;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_native_callback_finalize)
{
  GumDukNativeCallback * self = _gumjs_get_private_data (ctx, duk_require_heapptr (ctx, 0));

  gum_duk_native_callback_finalize (self);
  return 0;
}

static void
gum_duk_native_callback_finalize (GumDukNativeCallback * callback)
{
  _gum_duk_core_unprotect_later (callback->core, callback->func);

  ffi_closure_free (callback->closure);

  while (callback->data != NULL)
  {
    GSList * head = callback->data;
    g_free (head->data);
    callback->data = g_slist_delete_link (callback->data, head);
  }
  g_free (callback->atypes);
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
  duk_context * ctx = core->ctx;
  ffi_type * rtype = cif->rtype;
  GumFFIValue * retval = return_value;
  GumDukValue ** argv;
  guint i;
  GumDukValue * result;

  _gum_duk_scope_enter (&scope, core);

  if (rtype != &ffi_type_void)
  {
    /*
     * Ensure:
     * - high bits of values smaller than a pointer are cleared to zero
     * - we return something predictable in case of a JS exception
     */
    retval->v_pointer = NULL;
  }

  argv = g_alloca (cif->nargs * sizeof (GumDukValue *));
  for (i = 0; i != cif->nargs; i++)
  {
    if (!gumjs_value_from_ffi_type (ctx, args[i], cif->arg_types[i], core,
        &argv[i]))
      goto beach;
  }

  duk_push_heapptr (ctx, self->func);
  for (i = 0; i != cif->nargs; i++)
  {
    GumDukValue * arg = argv[i];
    if (arg->type == DUK_TYPE_OBJECT)
      duk_push_heapptr (ctx, arg->data._heapptr);
    else if (arg->type == DUK_TYPE_STRING)
      duk_push_string (ctx, arg->data._string);
    else if (arg->type == DUK_TYPE_BOOLEAN)
      duk_push_boolean (ctx, arg->data._boolean);
    else if (arg->type == DUK_TYPE_NUMBER)
      duk_push_number (ctx, arg->data._number);
    g_free (argv[i]);
  }
  duk_call (ctx, cif->nargs);
  result = _gumjs_get_value (ctx, -1);
  duk_pop (ctx);

  if (cif->rtype != &ffi_type_void && result != NULL)
  {
    gumjs_value_to_ffi_type (ctx, result, cif->rtype, core, retval);
    g_free (result);
  }

beach:
  _gum_duk_scope_leave (&scope);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cpu_context_construct)
{
  _gumjs_throw (ctx, "invalid argument");
  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_cpu_context_finalize)
{
  GumDukCpuContext * self = _gumjs_get_private_data (ctx, duk_require_heapptr (ctx, 0));

  g_slice_free (GumDukCpuContext, self);
  return 0;
}

static gboolean
gumjs_cpu_context_set_register (GumDukCpuContext * self,
                                duk_context * ctx,
                                const GumDukArgs * args,
                                gsize * reg)
{
  gpointer value;

  if (self->access == GUM_CPU_CONTEXT_READONLY)
    goto invalid_operation;

  if (!_gumjs_args_parse (ctx, "p~", &value))
    return FALSE;

  *reg = GPOINTER_TO_SIZE (value);
  return TRUE;

invalid_operation:
  {
    _gumjs_throw (ctx, "invalid operation");
    return FALSE;
  }
}

static GumDukWeakRef *
gum_duk_weak_ref_new (guint id,
                      GumDukHeapPtr target,
                      GumDukHeapPtr callback,
                      GumDukCore * core)
{
  duk_context * ctx = core->ctx;
  GumDukWeakRef * ref;

  ref = g_slice_new (GumDukWeakRef);
  ref->id = id;
  ref->target = _gumjs_weak_ref_new (ctx, target,
      (GumDukWeakNotify) gum_duk_weak_ref_on_weak_notify, ref, NULL);
  ref->callback = callback;
  ref->core = core;

  return ref;
}

static void
gum_duk_weak_ref_clear (GumDukWeakRef * ref)
{
  g_clear_pointer (&ref->target, _gumjs_weak_ref_free);
}

static void
gum_duk_weak_ref_free (GumDukWeakRef * ref)
{
  GumDukCore * core = ref->core;
  duk_context * ctx = core->ctx;
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);

  GUM_DUK_CORE_UNLOCK (core);

  gum_duk_weak_ref_clear (ref);

  duk_push_heapptr (ctx, ref->callback);
  duk_call (ctx, 0);
  _gum_duk_scope_flush (&scope);

  g_slice_free (GumDukWeakRef, ref);

  GUM_DUK_CORE_LOCK (core);
}

static void
gum_duk_weak_ref_on_weak_notify (GumDukWeakRef * self)
{
  GumDukCore * core = self->core;

  GUM_DUK_CORE_LOCK (core);
  g_hash_table_remove (core->weak_refs, GUINT_TO_POINTER (self->id));
  GUM_DUK_CORE_UNLOCK (core);
}

static int
gum_duk_core_schedule_callback (GumDukCore * self,
                                const GumDukArgs * args,
                                gboolean repeat)
{
  GumDukHeapPtr func;
  guint delay, id;
  GSource * source;
  GumDukScheduledCallback * callback;

  if (!_gumjs_args_parse (self->ctx, "Fu", &func, &delay))
  {
    duk_push_null (self->ctx);
    return 1;
  }

  id = ++self->last_callback_id;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new (delay);

  callback = gum_scheduled_callback_new (id, func, repeat, source, self);
  g_source_set_callback (source, gum_scheduled_callback_invoke, callback,
      (GDestroyNotify) gum_scheduled_callback_free);
  gum_duk_core_add_scheduled_callback (self, callback);

  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));

  duk_push_number(args->ctx, id);
  return 1;
}

static void
gum_duk_core_add_scheduled_callback (GumDukCore * self,
                                     GumDukScheduledCallback * cb)
{
  GUM_DUK_CORE_LOCK (self);
  self->scheduled_callbacks = g_slist_prepend (self->scheduled_callbacks, cb);
  GUM_DUK_CORE_UNLOCK (self);
}

static void
gum_duk_core_remove_scheduled_callback (GumDukCore * self,
                                        GumDukScheduledCallback * cb)
{
  GUM_DUK_CORE_LOCK (self);
  self->scheduled_callbacks = g_slist_remove (self->scheduled_callbacks, cb);
  GUM_DUK_CORE_UNLOCK (self);
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
  callback->func = func;
  callback->repeat = repeat;
  callback->source = source;
  callback->core = core;

  return callback;
}

static void
gum_scheduled_callback_free (GumDukScheduledCallback * callback)
{
  g_slice_free (GumDukScheduledCallback, callback);
}

static gboolean
gum_scheduled_callback_invoke (gpointer user_data)
{
  GumDukScheduledCallback * self = user_data;
  GumDukCore * core = self->core;
  duk_context * ctx = core->ctx;
  GumDukScope scope;

  _gum_duk_scope_enter (&scope, self->core);
  duk_push_heapptr (ctx, self->func);
  duk_call (ctx, 0);
  _gum_duk_scope_leave (&scope);

  if (!self->repeat)
    gum_duk_core_remove_scheduled_callback (core, self);

  return self->repeat;
}

static GumDukExceptionSink *
gum_duk_exception_sink_new (GumDukHeapPtr callback,
                            GumDukCore * core)
{
  GumDukExceptionSink * sink;

  sink = g_slice_new (GumDukExceptionSink);
  sink->callback = callback;
  sink->core = core;

  return sink;
}

static void
gum_duk_exception_sink_free (GumDukExceptionSink * sink)
{
  g_slice_free (GumDukExceptionSink, sink);
}

static void
gum_duk_exception_sink_handle_exception (GumDukExceptionSink * self,
                                         const gchar * exception)
{
  GumDukCore * core = self->core;
  duk_context * ctx = core->ctx;
  GumDukHeapPtr callback = self->callback;

  duk_push_heapptr (ctx, callback);
  duk_push_string (ctx, exception);
  GUM_DUK_CORE_UNLOCK (core);
  duk_call (ctx, 1);
  GUM_DUK_CORE_LOCK (core);
  duk_pop (ctx);
}

static GumDukMessageSink *
gum_duk_message_sink_new (GumDukHeapPtr callback,
                          GumDukCore * core)
{
  GumDukMessageSink * sink;

  sink = g_slice_new (GumDukMessageSink);
  sink->callback = callback;
  sink->core = core;

  return sink;
}

static void
gum_duk_message_sink_free (GumDukMessageSink * sink)
{
  g_slice_free (GumDukMessageSink, sink);
}

static void
gum_duk_message_sink_handle_message (GumDukMessageSink * self,
                                     const gchar * message)
{
  GumDukCore * core = self->core;
  duk_context * ctx = core->ctx;
  GumDukHeapPtr callback = self->callback;

  GUM_DUK_CORE_UNLOCK (core);
  duk_push_heapptr (ctx, callback);
  duk_push_string (ctx, message);
  duk_call (ctx, 1);
  duk_pop (ctx);
  GUM_DUK_CORE_LOCK (core);
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
gumjs_ffi_type_try_get (duk_context * ctx,
                        GumDukValue * value,
                        ffi_type ** type,
                        GSList ** data)
{
  gboolean success = FALSE;
  gchar * name = NULL;
  guint i;

  if (_gumjs_value_string_try_get (ctx, value, &name))
  {
    for (i = 0; i != G_N_ELEMENTS (gum_ffi_type_mappings); i++)
    {
      const GumFFITypeMapping * m = &gum_ffi_type_mappings[i];
      if (strcmp (name, m->name) == 0)
      {
        *type = m->type;
        success = TRUE;
        goto beach;
      }
    }
  }
  else if (_gumjs_value_is_array (ctx, value))
  {
    GumDukHeapPtr fields_value;
    guint length;
    ffi_type ** fields, * struct_type;

    fields_value = value->data._heapptr;

    if (!_gumjs_object_try_get_uint (ctx, fields_value, "length", &length))
      return FALSE;

    fields = g_new (ffi_type *, length + 1);
    *data = g_slist_prepend (*data, fields);

    duk_push_heapptr (ctx, fields_value);
    for (i = 0; i != length; i++)
    {
      GumDukValue * field_value;

      duk_get_prop_index (ctx, -1, i);
      field_value = _gumjs_get_value (ctx, -1);
      duk_pop (ctx);
      if (field_value == NULL)
        goto beach;

      if (!gumjs_ffi_type_try_get (ctx, field_value, &fields[i], data))
      {
        g_free (field_value);
        goto beach;
      }
      g_free (field_value);
    }
    duk_pop (ctx);

    fields[length] = NULL;

    struct_type = g_new0 (ffi_type, 1);
    struct_type->type = FFI_TYPE_STRUCT;
    struct_type->elements = fields;
    *data = g_slist_prepend (*data, struct_type);

    *type = struct_type;
    success = TRUE;
    goto beach;
  }

beach:
  g_free (name);

  return success;
}

static gboolean
gumjs_ffi_abi_try_get (duk_context * ctx,
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

  _gumjs_throw (ctx, "invalid abi specified");
  return FALSE;
}

static gboolean
gumjs_value_to_ffi_type (duk_context * ctx,
                         GumDukValue * svalue,
                         const ffi_type * type,
                         GumDukCore * core,
                         GumFFIValue * value)
{
  gint i;
  guint u;
  gint64 i64;
  guint64 u64;
  gdouble n;

  if (type == &ffi_type_void)
  {
    value->v_pointer = NULL;
  }
  else if (type == &ffi_type_pointer)
  {
    if (!_gumjs_value_native_pointer_try_get (ctx, svalue, core, &value->v_pointer))
      return FALSE;
  }
  else if (type == &ffi_type_sint)
  {
    if (!_gumjs_value_int_try_get (ctx, svalue, &i))
      return FALSE;
    value->v_sint = i;
  }
  else if (type == &ffi_type_uint)
  {
    if (!_gumjs_value_uint_try_get (ctx, svalue, &u))
      return FALSE;
    value->v_uint = u;
  }
  else if (type == &ffi_type_slong)
  {
    if (!_gumjs_value_int64_try_get (ctx, svalue, &i64))
      return FALSE;
    value->v_slong = i64;
  }
  else if (type == &ffi_type_ulong)
  {
    if (!_gumjs_value_uint64_try_get (ctx, svalue, &u64))
      return FALSE;
    value->v_ulong = u64;
  }
  else if (type == &ffi_type_schar)
  {
    if (!_gumjs_value_int_try_get (ctx, svalue, &i))
      return FALSE;
    value->v_schar = i;
  }
  else if (type == &ffi_type_uchar)
  {
    if (!_gumjs_value_uint_try_get (ctx, svalue, &u))
      return FALSE;
    value->v_uchar = u;
  }
  else if (type == &ffi_type_float)
  {
    if (!_gumjs_value_number_try_get (ctx, svalue, &n))
      return FALSE;
    value->v_float = n;
  }
  else if (type == &ffi_type_double)
  {
    if (!_gumjs_value_number_try_get (ctx, svalue, &n))
      return FALSE;
    value->v_double = n;
  }
  else if (type == &ffi_type_sint8)
  {
    if (!_gumjs_value_int_try_get (ctx, svalue, &i))
      return FALSE;
    value->v_sint8 = i;
  }
  else if (type == &ffi_type_uint8)
  {
    if (!_gumjs_value_uint_try_get (ctx, svalue, &u))
      return FALSE;
    value->v_uint8 = u;
  }
  else if (type == &ffi_type_sint16)
  {
    if (!_gumjs_value_int_try_get (ctx, svalue, &i))
      return FALSE;
    value->v_sint16 = i;
  }
  else if (type == &ffi_type_uint16)
  {
    if (!_gumjs_value_uint_try_get (ctx, svalue, &u))
      return FALSE;
    value->v_uint16 = u;
  }
  else if (type == &ffi_type_sint32)
  {
    if (!_gumjs_value_int_try_get (ctx, svalue, &i))
      return FALSE;
    value->v_sint32 = i;
  }
  else if (type == &ffi_type_uint32)
  {
    if (!_gumjs_value_uint_try_get (ctx, svalue, &u))
      return FALSE;
    value->v_uint32 = u;
  }
  else if (type == &ffi_type_sint64)
  {
    if (!_gumjs_value_int64_try_get (ctx, svalue, &i64))
      return FALSE;
    value->v_sint64 = i64;
  }
  else if (type == &ffi_type_uint64)
  {
    if (!_gumjs_value_uint64_try_get (ctx, svalue, &u64))
      return FALSE;
    value->v_uint64 = u64;
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    ffi_type ** const field_types = type->elements, ** t;
    GumDukHeapPtr field_svalues;
    guint provided_length, length, i;
    guint8 * field_values;
    gsize offset;

    if (!_gumjs_value_is_array (ctx, svalue))
    {
      _gumjs_throw (ctx, "expected array with fields");
      return FALSE;
    }
    field_svalues = svalue->data._heapptr;

    if (!_gumjs_object_try_get_uint (ctx, field_svalues, "length", &provided_length))
      return FALSE;
    length = 0;
    for (t = field_types; *t != NULL; t++)
      length++;
    if (provided_length != length)
    {
      _gumjs_throw (ctx, "provided array length does not match "
          "number of fields");
      return FALSE;
    }

    field_values = (guint8 *) value;
    offset = 0;
    duk_push_heapptr (ctx, field_svalues);
    for (i = 0; i != length; i++)
    {
      const ffi_type * field_type = field_types[i];
      GumFFIValue * field_value;
      GumDukValue * field_svalue;

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);

      field_value = (GumFFIValue *) (field_values + offset);
      duk_get_prop_index (ctx, -1, i);
      field_svalue = _gumjs_get_value (ctx, -1);
      duk_pop (ctx);

      if (field_svalue == NULL)
        return FALSE;

      if (!gumjs_value_to_ffi_type (ctx, field_svalue, field_type, core,
          field_value))
      {
        g_free (field_svalue);
        return FALSE;
      }
      g_free (field_svalue);

      offset += field_type->size;
    }
    duk_pop (ctx);
  }
  else
  {
    goto unsupported_type;
  }

  return TRUE;

unsupported_type:
  {
    _gumjs_throw (ctx, "unsupported type");
    return FALSE;
  }
}

static gboolean
gumjs_value_from_ffi_type (duk_context * ctx,
                           const GumFFIValue * value,
                           const ffi_type * type,
                           GumDukCore * core,
                           GumDukValue ** svalue)
{
  if (type == &ffi_type_void)
  {
    duk_push_undefined (ctx);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_pointer)
  {
    *svalue = _gumjs_native_pointer_new (ctx, value->v_pointer, core);
  }
  else if (type == &ffi_type_sint)
  {
    duk_push_number (ctx, value->v_sint);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_uint)
  {
    duk_push_number (ctx, value->v_uint);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_slong)
  {
    duk_push_number (ctx, value->v_slong);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_ulong)
  {
    duk_push_number (ctx, value->v_ulong);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_schar)
  {
    duk_push_number (ctx, value->v_schar);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_uchar)
  {
    duk_push_number (ctx, value->v_uchar);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_float)
  {
    duk_push_number (ctx, value->v_float);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_double)
  {
    duk_push_number (ctx, value->v_double);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_sint8)
  {
    duk_push_number (ctx, value->v_sint8);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_uint8)
  {
    duk_push_number (ctx, value->v_uint8);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_sint16)
  {
    duk_push_number (ctx, value->v_sint16);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_uint16)
  {
    duk_push_number (ctx, value->v_uint16);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_sint32)
  {
    duk_push_number (ctx, value->v_sint32);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_uint32)
  {
    duk_push_number (ctx, value->v_uint32);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_sint64)
  {
    duk_push_number (ctx, value->v_sint64);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type == &ffi_type_uint64)
  {
    duk_push_number (ctx, value->v_uint64);
    *svalue = _gumjs_get_value (ctx, -1);
    duk_pop (ctx);
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    ffi_type ** const field_types = type->elements, ** t;
    guint length, i;
    GumDukValue ** field_svalues;
    const guint8 * field_values;
    gsize offset;

    length = 0;
    for (t = field_types; *t != NULL; t++)
      length++;

    field_svalues = g_alloca (length * sizeof (GumDukValue *));
    field_values = (const guint8 *) value;
    offset = 0;
    for (i = 0; i != length; i++)
    {
      const ffi_type * field_type = field_types[i];
      const GumFFIValue * field_value;

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);
      field_value = (const GumFFIValue *) (field_values + offset);

      if (!gumjs_value_from_ffi_type (ctx, field_value, field_type, core,
          &field_svalues[i]))
        goto error;

      offset += field_type->size;
    }

    /* TODO: make array
    *svalue = JSObjectMakeArray (ctx, length, field_svalues, exception);
    */
    for (i = 0; i != length; i++)
      g_free (field_svalues[i]);
    if (*svalue == NULL)
      goto error;
  }
  else
  {
    goto unsupported_type;
  }

  return TRUE;

unsupported_type:
  {
    _gumjs_throw (ctx, "unsupported type");
    goto error;
  }
error:
  {
    return FALSE;
  }
}
