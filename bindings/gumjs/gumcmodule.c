/*
 * Copyright (C) 2019-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcmodule.h"

#include <gio/gio.h>

#ifdef HAVE_TINYCC
static GumCModule * gum_tcc_cmodule_new (const gchar * source, GError ** error);
#endif

G_DEFINE_ABSTRACT_TYPE (GumCModule, gum_cmodule, G_TYPE_OBJECT)

static void
gum_cmodule_class_init (GumCModuleClass * klass)
{
}

static void
gum_cmodule_init (GumCModule * cmodule)
{
}

GumCModule *
gum_cmodule_new (const gchar * name,
                 const gchar * source,
                 GError ** error)
{
#ifdef HAVE_TINYCC
  if (name == NULL || strcmp (name, "tcc") == 0)
    return gum_tcc_cmodule_new (source, error);
#endif

  g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
      "Not available for the current architecture");
  return NULL;
}

const GumMemoryRange *
gum_cmodule_get_range (GumCModule * self)
{
  return GUM_CMODULE_GET_CLASS (self)->get_range (self);
}

void
gum_cmodule_add_symbol (GumCModule * self,
                        const gchar * name,
                        gconstpointer value)
{
  GUM_CMODULE_GET_CLASS (self)->add_symbol (self, name, value);
}

gboolean
gum_cmodule_link (GumCModule * self,
                  GError ** error)
{
  return GUM_CMODULE_GET_CLASS (self)->link (self, error);
}

void
gum_cmodule_enumerate_symbols (GumCModule * self,
                               GumFoundCSymbolFunc func,
                               gpointer user_data)
{
  GUM_CMODULE_GET_CLASS (self)->enumerate_symbols (self, func, user_data);
}

gpointer
gum_cmodule_find_symbol_by_name (GumCModule * self,
                                 const gchar * name)
{
  return GUM_CMODULE_GET_CLASS (self)->find_symbol_by_name (self, name);
}

void
gum_cmodule_drop_metadata (GumCModule * self)
{
  GUM_CMODULE_GET_CLASS (self)->drop_metadata (self);
}

#ifdef HAVE_TINYCC

#include <gum/gum-init.h>
#include <gum/gum.h>
#include <json-glib/json-glib.h>
#include <libtcc.h>
#include <string.h>

#define GUM_TYPE_TCC_CMODULE (gum_tcc_cmodule_get_type ())
G_DECLARE_FINAL_TYPE (GumTccCModule, gum_tcc_cmodule, GUM, TCC_CMODULE,
    GumCModule)

typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumCModuleHeader GumCModuleHeader;
typedef guint GumCModuleHeaderKind;

typedef void (* GumCModuleInitFunc) (void);
typedef void (* GumCModuleFinalizeFunc) (void);

struct _GumTccCModule
{
  GumCModule parent;

  TCCState * state;
  GumMemoryRange range;
  GumCModuleFinalizeFunc finalize;
};

struct _GumCModuleHeader
{
  const gchar * name;
  const gchar * data;
  guint size;
  GumCModuleHeaderKind kind;
};

enum _GumCModuleHeaderKind
{
  GUM_CMODULE_HEADER_TCC,
  GUM_CMODULE_HEADER_FRIDA
};

struct _GumEnumerateSymbolsContext
{
  GumFoundCSymbolFunc func;
  gpointer user_data;
};

static void gum_tcc_cmodule_finalize (GObject * object);
static const GumMemoryRange * gum_tcc_cmodule_get_range (GumCModule * cm);
static void gum_tcc_cmodule_add_symbol (GumCModule * cm, const gchar * name,
    gconstpointer value);
static gboolean gum_tcc_cmodule_link (GumCModule * cm, GError ** error);
static void gum_tcc_cmodule_enumerate_symbols (GumCModule * cm,
    GumFoundCSymbolFunc func, gpointer user_data);
static gpointer gum_tcc_cmodule_find_symbol_by_name (GumCModule * cm,
    const gchar * name);
static void gum_tcc_cmodule_drop_metadata (GumCModule * cm);
static void gum_emit_symbol (void * ctx, const char * name, const void * val);
static void gum_append_tcc_error (void * opaque, const char * msg);
static void gum_emit_symbol (void * ctx, const char * name, const void * val);
static const char * gum_cmodule_load_header (void * opaque, const char * path,
    int * len);
static void * gum_cmodule_resolve_symbol (void * opaque, const char * name);
static void gum_define_symbol_str (TCCState * state, const gchar * name,
    const gchar * value);
static const gchar * gum_undecorate_name (const gchar * name);

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8 && !defined (_MSC_VER)
extern void * __va_arg (void * ap, int arg_type, int size, int align);
#endif

G_DEFINE_TYPE (GumTccCModule, gum_tcc_cmodule, GUM_TYPE_CMODULE)

static void
gum_tcc_cmodule_class_init (GumTccCModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  GumCModuleClass * cmodule_class = GUM_CMODULE_CLASS (klass);

  object_class->finalize = gum_tcc_cmodule_finalize;

  cmodule_class->get_range = gum_tcc_cmodule_get_range;
  cmodule_class->add_symbol = gum_tcc_cmodule_add_symbol;
  cmodule_class->link = gum_tcc_cmodule_link;
  cmodule_class->enumerate_symbols = gum_tcc_cmodule_enumerate_symbols;
  cmodule_class->find_symbol_by_name = gum_tcc_cmodule_find_symbol_by_name;
  cmodule_class->drop_metadata = gum_tcc_cmodule_drop_metadata;
}

static void
gum_tcc_cmodule_init (GumTccCModule * cmodule)
{
}

#include "gumcmodule-runtime.h"

static GumCModule *
gum_tcc_cmodule_new (const gchar * source,
                     GError ** error)
{
  GumCModule * result;
  GumTccCModule * cmodule;
  TCCState * state;
  GString * error_messages;
  gchar * combined_source;

  result = g_object_new (GUM_TYPE_TCC_CMODULE, NULL);
  cmodule = GUM_TCC_CMODULE (result);

  state = tcc_new ();
  cmodule->state = state;

  error_messages = NULL;
  tcc_set_error_func (state, &error_messages, gum_append_tcc_error);

  tcc_set_cpp_load_func (state, cmodule, gum_cmodule_load_header);
  tcc_set_linker_resolve_func (state, cmodule, gum_cmodule_resolve_symbol);
  tcc_set_options (state,
      "-nostdinc "
      "-nostdlib "
      "-isystem /frida "
      "-isystem /frida/capstone"
  );

#if defined (HAVE_I386)
  tcc_define_symbol (state, "HAVE_I386", NULL);
#elif defined (HAVE_ARM)
  tcc_define_symbol (state, "HAVE_ARM", NULL);
#elif defined (HAVE_ARM64)
  tcc_define_symbol (state, "HAVE_ARM64", NULL);
#elif defined (HAVE_MIPS)
  tcc_define_symbol (state, "HAVE_MIPS", NULL);
#endif

  tcc_define_symbol (state, "TRUE", "1");
  tcc_define_symbol (state, "FALSE", "0");

  gum_define_symbol_str (state, "G_GINT16_MODIFIER", G_GINT16_MODIFIER);
  gum_define_symbol_str (state, "G_GINT32_MODIFIER", G_GINT32_MODIFIER);
  gum_define_symbol_str (state, "G_GINT64_MODIFIER", G_GINT64_MODIFIER);
  gum_define_symbol_str (state, "G_GSIZE_MODIFIER", G_GSIZE_MODIFIER);
  gum_define_symbol_str (state, "G_GSSIZE_MODIFIER", G_GSSIZE_MODIFIER);

  tcc_define_symbol (state, "GLIB_SIZEOF_VOID_P",
      G_STRINGIFY (GLIB_SIZEOF_VOID_P));

#ifdef HAVE_WINDOWS
  tcc_define_symbol (state, "extern", "__attribute__ ((dllimport))");
#endif

  tcc_set_output_type (state, TCC_OUTPUT_MEMORY);

  combined_source = g_strconcat ("#line 1 \"module.c\"\n", source, NULL);

  tcc_compile_string (state, combined_source);

  g_free (combined_source);

  tcc_set_error_func (state, NULL, NULL);

  if (error_messages != NULL)
    goto failure;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8 && !defined (_MSC_VER)
  tcc_add_symbol (state, "__va_arg", __va_arg);
#endif
#if defined (HAVE_ARM)
  tcc_add_symbol (state, "__aeabi_memmove", memmove);
  tcc_add_symbol (state, "__aeabi_memmove4", memmove);
  tcc_add_symbol (state, "__aeabi_memmove8", memmove);
  tcc_add_symbol (state, "__aeabi_memset", memset);
#endif

  return result;

failure:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Compilation failed: %s", error_messages->str);
    g_string_free (error_messages, TRUE);

    g_object_unref (result);

    return NULL;
  }
}

static void
gum_tcc_cmodule_finalize (GObject * object)
{
  GumTccCModule * cmodule = GUM_TCC_CMODULE (object);
  GumMemoryRange * r;

  r = &cmodule->range;
  if (r->base_address != 0)
  {
    if (cmodule->finalize != NULL)
      cmodule->finalize ();

    gum_cloak_remove_range (r);

    gum_memory_free (GSIZE_TO_POINTER (r->base_address), r->size);
  }

  gum_cmodule_drop_metadata (GUM_CMODULE (object));

  G_OBJECT_CLASS (gum_tcc_cmodule_parent_class)->finalize (object);
}

static const GumMemoryRange *
gum_tcc_cmodule_get_range (GumCModule * cm)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  return &self->range;
}

static void
gum_tcc_cmodule_add_symbol (GumCModule * cm,
                            const gchar * name,
                            gconstpointer value)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);
  TCCState * state = self->state;

  g_assert (state != NULL);

  tcc_add_symbol (state, name, value);
}

static gboolean
gum_tcc_cmodule_link (GumCModule * cm,
                      GError ** error)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);
  TCCState * state = self->state;
  GString * error_messages;
  gint res;
  guint size, page_size;
  gpointer base;

  g_assert (state != NULL);
  g_assert (self->range.base_address == 0);

  error_messages = NULL;
  tcc_set_error_func (state, &error_messages, gum_append_tcc_error);

  res = tcc_relocate (state, NULL);
  if (res == -1)
    goto beach;
  size = res;

  page_size = gum_query_page_size ();

  base = gum_memory_allocate (NULL, size, page_size, GUM_PAGE_RW);

  res = tcc_relocate (state, base);
  if (res == 0)
  {
    GumMemoryRange * r = &self->range;
    GumCModuleInitFunc init;

    r->base_address = GUM_ADDRESS (base);
    r->size = GUM_ALIGN_SIZE (size, page_size);

    gum_memory_mark_code (base, size);

    gum_cloak_add_range (r);

    init = GUM_POINTER_TO_FUNCPTR (GumCModuleInitFunc,
        tcc_get_symbol (state, "init"));
    if (init != NULL)
      init ();

    self->finalize = GUM_POINTER_TO_FUNCPTR (GumCModuleFinalizeFunc,
        tcc_get_symbol (self->state, "finalize"));
  }
  else
  {
    gum_memory_free (base, size);
  }

beach:
  tcc_set_error_func (state, NULL, NULL);

  if (error_messages != NULL)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Linking failed: %s", error_messages->str);
    g_string_free (error_messages, TRUE);
  }

  return res == 0;
}

static void
gum_append_tcc_error (void * opaque,
                      const char * msg)
{
  GString ** messages = opaque;

  if (*messages == NULL)
  {
    *messages = g_string_new (msg);
  }
  else
  {
    g_string_append_c (*messages, '\n');
    g_string_append (*messages, msg);
  }
}

static void
gum_tcc_cmodule_enumerate_symbols (GumCModule * cm,
                                   GumFoundCSymbolFunc func,
                                   gpointer user_data)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);
  TCCState * state = self->state;
  GumEnumerateSymbolsContext ctx;

  g_assert (state != NULL);

  ctx.func = func;
  ctx.user_data = user_data;

  tcc_list_symbols (state, &ctx, gum_emit_symbol);
}

static void
gum_emit_symbol (void * ctx,
                 const char * name,
                 const void * val)
{
  GumEnumerateSymbolsContext * sc = ctx;
  GumCSymbolDetails d;

  d.name = gum_undecorate_name (name);
  d.address = (gpointer) val;

  sc->func (&d, sc->user_data);
}

static gpointer
gum_tcc_cmodule_find_symbol_by_name (GumCModule * cm,
                                     const gchar * name)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);
  TCCState * state = self->state;

  g_assert (state != NULL);
  g_assert (self->range.base_address != 0);

  return tcc_get_symbol (state, name);
}

static void
gum_tcc_cmodule_drop_metadata (GumCModule * cm)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  g_clear_pointer (&self->state, tcc_delete);
}

static const char *
gum_cmodule_load_header (void * opaque,
                         const char * path,
                         int * len)
{
  const gchar * name;
  guint i;

  name = path;
  if (g_str_has_prefix (name, "/frida/"))
    name += 7;

  for (i = 0; i != G_N_ELEMENTS (gum_cmodule_headers); i++)
  {
    const GumCModuleHeader * h = &gum_cmodule_headers[i];
    if (strcmp (h->name, name) == 0)
    {
      *len = h->size;
      return h->data;
    }
  }

  return NULL;
}

static void *
gum_cmodule_resolve_symbol (void * opaque,
                            const char * name)
{
  return g_hash_table_lookup (gum_cmodule_get_symbols (),
      gum_undecorate_name (name));
}

static void
gum_define_symbol_str (TCCState * state,
                       const gchar * name,
                       const gchar * value)
{
  gchar * raw_value;

  raw_value = g_strconcat ("\"", value, "\"", NULL);

  tcc_define_symbol (state, name, raw_value);

  g_free (raw_value);
}

static const gchar *
gum_undecorate_name (const gchar * name)
{
#ifdef HAVE_DARWIN
  return name + 1;
#else
  return name;
#endif
}

#endif /* HAVE_TINYCC */
