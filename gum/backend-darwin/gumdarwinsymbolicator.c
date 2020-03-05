/*
 * Copyright (C) 2018-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdarwinsymbolicator.h"

#include "gum-init.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <gio/gio.h>

#define kCSNull ((CSTypeRef) { NULL, NULL })
#define kCSNow  G_GUINT64_CONSTANT (0x8000000000000000)

typedef struct _CSTypeRef CSTypeRef;
typedef struct _CSRange CSRange;
typedef uint64_t CSTime;

typedef CSTypeRef CSSymbolicatorRef;
typedef CSTypeRef CSSymbolRef;
typedef CSTypeRef CSSymbolOwnerRef;
typedef CSTypeRef CSSourceInfoRef;

typedef int (^ CSEachSymbolBlock) (CSSymbolRef symbol);

struct _CSTypeRef
{
  void * data;
  void * obj;
};

struct _GumDarwinSymbolicator
{
  GObject object;

  gchar * path;
  GumCpuType cpu_type;

  mach_port_t task;

  CSSymbolicatorRef handle;
};

enum
{
  PROP_0,
  PROP_PATH,
  PROP_CPU_TYPE,
  PROP_TASK,
};

struct _CSRange
{
  uint64_t location;
  uint64_t length;
};

static void gum_darwin_symbolicator_initable_iface_init (gpointer g_iface,
    gpointer iface_data);
static gboolean gum_darwin_symbolicator_initable_init (GInitable * initable,
    GCancellable * cancellable, GError ** error);
static void gum_darwin_symbolicator_dispose (GObject * object);
static void gum_darwin_symbolicator_finalize (GObject * object);
static void gum_darwin_symbolicator_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_symbolicator_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static cpu_type_t gum_cpu_type_to_darwin (GumCpuType cpu_type);
static GumAddress gum_cs_symbol_address (CSSymbolRef symbol);

static gboolean gum_cs_ensure_library_loaded (void);
static gpointer gum_cs_load_library (gpointer data);
static void gum_cs_unload_library (void);

G_DEFINE_TYPE_EXTENDED (GumDarwinSymbolicator,
                        gum_darwin_symbolicator,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                            gum_darwin_symbolicator_initable_iface_init))

static void * gum_cs;

#define GUM_DECLARE_CS_FUNC(N, R, A) \
    typedef R (* G_PASTE (G_PASTE (CS, N), Func)) A; \
    static G_PASTE (G_PASTE (CS, N), Func) G_PASTE (CS, N)

GUM_DECLARE_CS_FUNC (IsNull, Boolean, (CSTypeRef cs));
GUM_DECLARE_CS_FUNC (Release, void, (CSTypeRef cs));

GUM_DECLARE_CS_FUNC (SymbolicatorCreateWithPathAndArchitecture,
    CSSymbolicatorRef, (const char * path, cpu_type_t cpu_type));
GUM_DECLARE_CS_FUNC (SymbolicatorCreateWithTask, CSSymbolicatorRef,
    (task_t task));
GUM_DECLARE_CS_FUNC (SymbolicatorGetSymbolWithAddressAtTime, CSSymbolRef,
    (CSSymbolicatorRef symbolicator, mach_vm_address_t address, CSTime time));
GUM_DECLARE_CS_FUNC (SymbolicatorGetSourceInfoWithAddressAtTime,
    CSSourceInfoRef, (CSSymbolicatorRef symbolicator, mach_vm_address_t address,
    CSTime time));
GUM_DECLARE_CS_FUNC (SymbolicatorForeachSymbolAtTime, int,
    (CSSymbolicatorRef symbolicator, CSTime time, CSEachSymbolBlock block));
GUM_DECLARE_CS_FUNC (SymbolicatorForeachSymbolWithNameAtTime, int,
    (CSSymbolicatorRef symbolicator, const char * name, CSTime time,
    CSEachSymbolBlock block));

GUM_DECLARE_CS_FUNC (SymbolGetName, const char *, (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolGetRange, CSRange, (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolGetSymbolOwner, CSSymbolOwnerRef,
    (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolIsFunction, Boolean, (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolIsThumb, Boolean, (CSSymbolRef symbol));

GUM_DECLARE_CS_FUNC (SymbolOwnerGetName, const char *,
    (CSSymbolOwnerRef owner));
GUM_DECLARE_CS_FUNC (SymbolOwnerGetBaseAddress, unsigned long long,
    (CSSymbolOwnerRef owner));

GUM_DECLARE_CS_FUNC (SourceInfoGetFilename, const char *,
    (CSSourceInfoRef info));
GUM_DECLARE_CS_FUNC (SourceInfoGetLineNumber, int,
    (CSSourceInfoRef info));

#undef GUM_DECLARE_CS_FUNC

static void
gum_darwin_symbolicator_class_init (GumDarwinSymbolicatorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_darwin_symbolicator_dispose;
  object_class->finalize = gum_darwin_symbolicator_finalize;
  object_class->get_property = gum_darwin_symbolicator_get_property;
  object_class->set_property = gum_darwin_symbolicator_set_property;

  g_object_class_install_property (object_class, PROP_PATH,
      g_param_spec_string ("path", "Path", "Path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_CPU_TYPE,
      g_param_spec_uint ("cpu-type", "CpuType", "CPU type", 0, G_MAXUINT,
      GUM_CPU_INVALID, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_TASK,
      g_param_spec_uint ("task", "Task", "Mach task", 0, G_MAXUINT,
      MACH_PORT_NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_symbolicator_initable_iface_init (gpointer g_iface,
                                             gpointer iface_data)
{
  GInitableIface * iface = g_iface;

  iface->init = gum_darwin_symbolicator_initable_init;
}

static void
gum_darwin_symbolicator_init (GumDarwinSymbolicator * self)
{
}

static gboolean
gum_darwin_symbolicator_initable_init (GInitable * initable,
                                       GCancellable * cancellable,
                                       GError ** error)
{
  GumDarwinSymbolicator * self = GUM_DARWIN_SYMBOLICATOR (initable);

  if (!gum_cs_ensure_library_loaded ())
    goto not_available;

  if (self->path != NULL)
  {
    self->handle = CSSymbolicatorCreateWithPathAndArchitecture (self->path,
        gum_cpu_type_to_darwin (self->cpu_type));
    if (CSIsNull (self->handle))
      goto invalid_path;
  }
  else
  {
    self->handle = CSSymbolicatorCreateWithTask (self->task);
    if (CSIsNull (self->handle))
      goto invalid_task;
  }

  return TRUE;

not_available:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
        "CoreSymbolication not available");
    return FALSE;
  }
invalid_path:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "File not found");
    return FALSE;
  }
invalid_task:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Target process is gone");
    return FALSE;
  }
}

static void
gum_darwin_symbolicator_dispose (GObject * object)
{
  GumDarwinSymbolicator * self = GUM_DARWIN_SYMBOLICATOR (object);

  if (gum_cs_ensure_library_loaded () && !CSIsNull (self->handle))
  {
    CSRelease (self->handle);
    self->handle = kCSNull;
  }

  G_OBJECT_CLASS (gum_darwin_symbolicator_parent_class)->dispose (object);
}

static void
gum_darwin_symbolicator_finalize (GObject * object)
{
  GumDarwinSymbolicator * self = GUM_DARWIN_SYMBOLICATOR (object);

  g_free (self->path);

  G_OBJECT_CLASS (gum_darwin_symbolicator_parent_class)->finalize (object);
}

static void
gum_darwin_symbolicator_get_property (GObject * object,
                                      guint property_id,
                                      GValue * value,
                                      GParamSpec * pspec)
{
  GumDarwinSymbolicator * self = GUM_DARWIN_SYMBOLICATOR (object);

  switch (property_id)
  {
    case PROP_PATH:
      g_value_set_string (value, self->path);
      break;
    case PROP_CPU_TYPE:
      g_value_set_uint (value, self->cpu_type);
      break;
    case PROP_TASK:
      g_value_set_uint (value, self->task);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_symbolicator_set_property (GObject * object,
                                      guint property_id,
                                      const GValue * value,
                                      GParamSpec * pspec)
{
  GumDarwinSymbolicator * self = GUM_DARWIN_SYMBOLICATOR (object);

  switch (property_id)
  {
    case PROP_PATH:
      g_free (self->path);
      self->path = g_value_dup_string (value);
      break;
    case PROP_CPU_TYPE:
      self->cpu_type = g_value_get_uint (value);
      break;
    case PROP_TASK:
      self->task = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinSymbolicator *
gum_darwin_symbolicator_new_with_path (const gchar * path,
                                       GumCpuType cpu_type,
                                       GError ** error)
{
  return g_initable_new (GUM_DARWIN_TYPE_SYMBOLICATOR, NULL, error,
      "path", path,
      NULL);
}

GumDarwinSymbolicator *
gum_darwin_symbolicator_new_with_task (mach_port_t task,
                                       GError ** error)
{
  return g_initable_new (GUM_DARWIN_TYPE_SYMBOLICATOR, NULL, error,
      "task", task,
      NULL);
}

gboolean
gum_darwin_symbolicator_details_from_address (GumDarwinSymbolicator * self,
                                              GumAddress address,
                                              GumDebugSymbolDetails * details)
{
  CSSymbolRef symbol;
  CSSymbolOwnerRef owner;
  const char * name;
  CSSourceInfoRef info;

  symbol = CSSymbolicatorGetSymbolWithAddressAtTime (self->handle, address,
      kCSNow);
  if (CSIsNull (symbol))
    return FALSE;

  owner = CSSymbolGetSymbolOwner (symbol);

  details->address = address;
  strcpy (details->module_name, CSSymbolOwnerGetName (owner));
  name = CSSymbolGetName (symbol);
  if (name != NULL)
  {
    strcpy (details->symbol_name, name);
  }
  else
  {
    sprintf (details->symbol_name, "0x%lx",
        (long) ((unsigned long long) details->address -
            CSSymbolOwnerGetBaseAddress (owner)));
  }

  info = CSSymbolicatorGetSourceInfoWithAddressAtTime (self->handle,
      GPOINTER_TO_SIZE (address), kCSNow);
  if (!CSIsNull (info))
  {
    strcpy (details->file_name, CSSourceInfoGetFilename (info));
    details->line_number = CSSourceInfoGetLineNumber (info);
  }
  else
  {
    details->file_name[0] = '\0';
    details->line_number = 0;
  }

  return TRUE;
}

gchar *
gum_darwin_symbolicator_name_from_address (GumDarwinSymbolicator * self,
                                           GumAddress address)
{
  gchar * result;
  CSSymbolRef symbol;
  const char * name;

  symbol = CSSymbolicatorGetSymbolWithAddressAtTime (self->handle, address,
      kCSNow);
  if (CSIsNull (symbol))
    return NULL;

  name = CSSymbolGetName (symbol);
  if (name != NULL)
  {
    result = g_strdup (name);
  }
  else
  {
    CSSymbolOwnerRef owner;

    owner = CSSymbolGetSymbolOwner (symbol);

    result = g_strdup_printf ("0x%lx", (long) ((unsigned long long) address -
        CSSymbolOwnerGetBaseAddress (owner)));
  }

  return result;
}

GumAddress
gum_darwin_symbolicator_find_function (GumDarwinSymbolicator * self,
                                       const gchar * name)
{
  __block GumAddress result = 0;

  CSSymbolicatorForeachSymbolWithNameAtTime (self->handle, name, kCSNow,
      ^(CSSymbolRef symbol)
  {
    if (result == 0 && CSSymbolIsFunction (symbol))
      result = gum_cs_symbol_address (symbol);
    return 0;
  });

  return result;
}

GumAddress *
gum_darwin_symbolicator_find_functions_named (GumDarwinSymbolicator * self,
                                              const gchar * name,
                                              gsize * len)
{
  GArray * result;

  result = g_array_new (FALSE, FALSE, sizeof (GumAddress));

  CSSymbolicatorForeachSymbolWithNameAtTime (self->handle, name, kCSNow,
      ^(CSSymbolRef symbol)
  {
    if (CSSymbolIsFunction (symbol))
    {
      GumAddress address = gum_cs_symbol_address (symbol);
      g_array_append_val (result, address);
    }
    return 0;
  });

  *len = result->len;

  return (GumAddress *) g_array_free (result, FALSE);
}

GumAddress *
gum_darwin_symbolicator_find_functions_matching (GumDarwinSymbolicator * self,
                                                 const gchar * str,
                                                 gsize * len)
{
  GArray * result;
  GPatternSpec * pspec;

  result = g_array_new (FALSE, FALSE, sizeof (GumAddress));

  pspec = g_pattern_spec_new (str);

  CSSymbolicatorForeachSymbolAtTime (self->handle, kCSNow,
      ^(CSSymbolRef symbol)
  {
    if (CSSymbolIsFunction (symbol))
    {
      const char * name = CSSymbolGetName (symbol);
      if (name != NULL && g_pattern_match_string (pspec, name))
      {
        GumAddress address = gum_cs_symbol_address (symbol);
        g_array_append_val (result, address);
      }
    }
    return 0;
  });

  g_pattern_spec_free (pspec);

  *len = result->len;

  return (GumAddress *) g_array_free (result, FALSE);
}

static cpu_type_t
gum_cpu_type_to_darwin (GumCpuType cpu_type)
{
  switch (cpu_type)
  {
    case GUM_CPU_IA32:  return CPU_TYPE_I386;
    case GUM_CPU_AMD64: return CPU_TYPE_X86_64;
    case GUM_CPU_ARM:   return CPU_TYPE_ARM;
    case GUM_CPU_ARM64: return CPU_TYPE_ARM64;
    default:
      break;
  }

  return CPU_TYPE_ANY;
}

static GumAddress
gum_cs_symbol_address (CSSymbolRef symbol)
{
  uint64_t address;

  address = CSSymbolGetRange (symbol).location;

  if (CSSymbolIsThumb (symbol))
    address |= 1;

  if (CSSymbolIsFunction (symbol))
    address = gum_sign_code_address (address);

  return address;
}

static gboolean
gum_cs_ensure_library_loaded (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, gum_cs_load_library, NULL);

  return GPOINTER_TO_SIZE (init_once.retval);
}

static gpointer
gum_cs_load_library (gpointer data)
{
  void * cf;

  /*
   * CoreFoundation must be loaded by the main thread, so we should avoid
   * loading it. This must be done by the user of frida-gum explicitly.
   */
  cf = dlopen ("/System/Library/Frameworks/"
      "CoreFoundation.framework/CoreFoundation",
      RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
  if (cf == NULL)
    return NULL;
  dlclose (cf);

  gum_cs = dlopen ("/System/Library/PrivateFrameworks/"
      "CoreSymbolication.framework/CoreSymbolication",
      RTLD_LAZY | RTLD_GLOBAL);
  if (gum_cs == NULL)
    goto api_error;

#define GUM_TRY_ASSIGN(name) \
    G_PASTE (CS, name) = dlsym (gum_cs, G_STRINGIFY (G_PASTE (CS, name))); \
    if (G_PASTE (CS, name) == NULL) \
      goto api_error

  GUM_TRY_ASSIGN (IsNull);
  GUM_TRY_ASSIGN (Release);

  GUM_TRY_ASSIGN (SymbolicatorCreateWithPathAndArchitecture);
  GUM_TRY_ASSIGN (SymbolicatorCreateWithTask);
  GUM_TRY_ASSIGN (SymbolicatorGetSymbolWithAddressAtTime);
  GUM_TRY_ASSIGN (SymbolicatorGetSourceInfoWithAddressAtTime);
  GUM_TRY_ASSIGN (SymbolicatorForeachSymbolAtTime);
  GUM_TRY_ASSIGN (SymbolicatorForeachSymbolWithNameAtTime);

  GUM_TRY_ASSIGN (SymbolGetName);
  GUM_TRY_ASSIGN (SymbolGetRange);
  GUM_TRY_ASSIGN (SymbolGetSymbolOwner);
  GUM_TRY_ASSIGN (SymbolIsFunction);
  GUM_TRY_ASSIGN (SymbolIsThumb);

  GUM_TRY_ASSIGN (SymbolOwnerGetName);
  GUM_TRY_ASSIGN (SymbolOwnerGetBaseAddress);

  GUM_TRY_ASSIGN (SourceInfoGetFilename);
  GUM_TRY_ASSIGN (SourceInfoGetLineNumber);

#undef GUM_TRY_ASSIGN

  _gum_register_destructor (gum_cs_unload_library);

  return GSIZE_TO_POINTER (TRUE);

api_error:
  {
    if (gum_cs != NULL)
    {
      dlclose (gum_cs);
      gum_cs = NULL;
    }

    return GSIZE_TO_POINTER (FALSE);
  }
}

static void
gum_cs_unload_library (void)
{
  dlclose (gum_cs);
  gum_cs = NULL;
}
