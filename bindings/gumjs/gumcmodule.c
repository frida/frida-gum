/*
 * Copyright (C) 2019-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcmodule.h"

#include <gio/gio.h>
#include <gum/gum-init.h>
#include <gum/gum.h>
#include <string.h>

#ifdef HAVE_TINYCC
static GumCModule * gum_tcc_cmodule_new (const gchar * source, GError ** error);
#endif
static GumCModule * gum_gcc_cmodule_new (const gchar * source, GError ** error);

typedef struct _GumCModulePrivate GumCModulePrivate;

typedef void (* GumCModuleInitFunc) (void);
typedef void (* GumCModuleFinalizeFunc) (void);

struct _GumCModulePrivate
{
  GumMemoryRange range;
  GumCModuleFinalizeFunc finalize;
};

static void gum_cmodule_finalize (GObject * object);

static void gum_add_defines (GumCModule * cm);
static void gum_add_define_str (GumCModule * cm, const gchar * name,
    const gchar * value);

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (GumCModule, gum_cmodule, G_TYPE_OBJECT);

static void
gum_cmodule_class_init (GumCModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_cmodule_finalize;
}

static void
gum_cmodule_init (GumCModule * cmodule)
{
}

static void
gum_cmodule_finalize (GObject * object)
{
  GumCModule * self;
  GumCModulePrivate * priv;
  const GumMemoryRange * r;

  self = GUM_CMODULE (object);
  priv = gum_cmodule_get_instance_private (self);
  r = &priv->range;

  if (r->base_address != 0)
  {
    if (priv->finalize != NULL)
      priv->finalize ();

    gum_cloak_remove_range (r);

    gum_memory_free (GSIZE_TO_POINTER (r->base_address), r->size);
  }

  gum_cmodule_drop_metadata (self);

  G_OBJECT_CLASS (gum_cmodule_parent_class)->finalize (object);
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

  if (name == NULL || strcmp (name, "gcc") == 0)
    return gum_gcc_cmodule_new (source, error);

  g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
      "Not available for the current architecture");
  return NULL;
}

static void
gum_add_defines (GumCModule * cm)
{
  GumCModuleClass * cls = GUM_CMODULE_GET_CLASS (cm);

#if defined (HAVE_I386)
  cls->add_define (cm, "HAVE_I386", NULL);
#elif defined (HAVE_ARM)
  cls->add_define (cm, "HAVE_ARM", NULL);
#elif defined (HAVE_ARM64)
  cls->add_define (cm, "HAVE_ARM64", NULL);
#elif defined (HAVE_MIPS)
  cls->add_define (cm, "HAVE_MIPS", NULL);
#endif

  cls->add_define (cm, "TRUE", "1");
  cls->add_define (cm, "FALSE", "0");

  gum_add_define_str (cm, "G_GINT16_MODIFIER", G_GINT16_MODIFIER);
  gum_add_define_str (cm, "G_GINT32_MODIFIER", G_GINT32_MODIFIER);
  gum_add_define_str (cm, "G_GINT64_MODIFIER", G_GINT64_MODIFIER);
  gum_add_define_str (cm, "G_GSIZE_MODIFIER", G_GSIZE_MODIFIER);
  gum_add_define_str (cm, "G_GSSIZE_MODIFIER", G_GSSIZE_MODIFIER);

  cls->add_define (cm, "GLIB_SIZEOF_VOID_P", G_STRINGIFY (GLIB_SIZEOF_VOID_P));

#ifdef HAVE_WINDOWS
  cls->add_define (cm, "extern", "__attribute__ ((dllimport))");
#endif
}

static void
gum_add_define_str (GumCModule * cm,
                    const gchar * name,
                    const gchar * value)
{
  gchar * raw_value;

  raw_value = g_strconcat ("\"", value, "\"", NULL);

  GUM_CMODULE_GET_CLASS (cm)->add_define (cm, name, raw_value);

  g_free (raw_value);
}

const GumMemoryRange *
gum_cmodule_get_range (GumCModule * self)
{
  GumCModulePrivate * priv = gum_cmodule_get_instance_private (self);

  return &priv->range;
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
  gboolean success = FALSE;
  GumCModulePrivate * priv;
  GString * error_messages;
  gsize size, page_size;
  gpointer base;

  priv = gum_cmodule_get_instance_private (self);

  error_messages = NULL;
  if (!GUM_CMODULE_GET_CLASS (self)->link_pre (self, &size, &error_messages))
    goto beach;

  page_size = gum_query_page_size ();

  base = gum_memory_allocate (NULL, size, page_size, GUM_PAGE_RW);

  if (GUM_CMODULE_GET_CLASS (self)->link (self, base, &error_messages))
  {
    GumMemoryRange * r = &priv->range;
    GumCModuleInitFunc init;

    r->base_address = GUM_ADDRESS (base);
    r->size = GUM_ALIGN_SIZE (size, page_size);

    gum_memory_mark_code (base, size);

    gum_cloak_add_range (r);

    init = GUM_POINTER_TO_FUNCPTR (GumCModuleInitFunc,
        gum_cmodule_find_symbol_by_name (self, "init"));
    if (init != NULL)
      init ();

    priv->finalize = GUM_POINTER_TO_FUNCPTR (GumCModuleFinalizeFunc,
        gum_cmodule_find_symbol_by_name (self, "finalize"));

    success = TRUE;
  }
  else
  {
    gum_memory_free (base, size);
  }

beach:
  GUM_CMODULE_GET_CLASS (self)->link_post (self);

  if (error_messages != NULL)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Linking failed: %s", error_messages->str);
    g_string_free (error_messages, TRUE);
  }

  return success;
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

#include <json-glib/json-glib.h>
#include <libtcc.h>
#include <string.h>

#define GUM_TYPE_TCC_CMODULE (gum_tcc_cmodule_get_type ())
G_DECLARE_FINAL_TYPE (GumTccCModule, gum_tcc_cmodule, GUM, TCC_CMODULE,
    GumCModule)

typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumCModuleHeader GumCModuleHeader;
typedef guint GumCModuleHeaderKind;

struct _GumTccCModule
{
  GumCModule parent;

  TCCState * state;
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

static void gum_tcc_cmodule_add_symbol (GumCModule * cm, const gchar * name,
    gconstpointer value);
static gboolean gum_tcc_cmodule_link_pre (GumCModule * cm, gsize * size,
    GString ** error_messages);
static gboolean gum_tcc_cmodule_link (GumCModule * cm, gpointer base,
    GString ** error_messages);
static void gum_tcc_cmodule_link_post (GumCModule * cm);
static void gum_tcc_cmodule_enumerate_symbols (GumCModule * cm,
    GumFoundCSymbolFunc func, gpointer user_data);
static gpointer gum_tcc_cmodule_find_symbol_by_name (GumCModule * cm,
    const gchar * name);
static void gum_tcc_cmodule_drop_metadata (GumCModule * cm);
static void gum_tcc_cmodule_add_define (GumCModule * cm, const gchar * name,
    const gchar * value);
static void gum_emit_symbol (void * ctx, const char * name, const void * val);
static void gum_append_tcc_error (void * opaque, const char * msg);
static void gum_emit_symbol (void * ctx, const char * name, const void * val);
static const char * gum_cmodule_load_header (void * opaque, const char * path,
    int * len);
static void * gum_cmodule_resolve_symbol (void * opaque, const char * name);
static void gum_add_abi_symbols (TCCState * state);
static const gchar * gum_undecorate_name (const gchar * name);

G_DEFINE_TYPE (GumTccCModule, gum_tcc_cmodule, GUM_TYPE_CMODULE)

static void
gum_tcc_cmodule_class_init (GumTccCModuleClass * klass)
{
  GumCModuleClass * cmodule_class = GUM_CMODULE_CLASS (klass);

  cmodule_class->add_symbol = gum_tcc_cmodule_add_symbol;
  cmodule_class->link_pre = gum_tcc_cmodule_link_pre;
  cmodule_class->link = gum_tcc_cmodule_link;
  cmodule_class->link_post = gum_tcc_cmodule_link_post;
  cmodule_class->enumerate_symbols = gum_tcc_cmodule_enumerate_symbols;
  cmodule_class->find_symbol_by_name = gum_tcc_cmodule_find_symbol_by_name;
  cmodule_class->drop_metadata = gum_tcc_cmodule_drop_metadata;
  cmodule_class->add_define = gum_tcc_cmodule_add_define;
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

  gum_add_defines (result);

  tcc_set_output_type (state, TCC_OUTPUT_MEMORY);

  combined_source = g_strconcat ("#line 1 \"module.c\"\n", source, NULL);

  tcc_compile_string (state, combined_source);

  g_free (combined_source);

  tcc_set_error_func (state, NULL, NULL);

  if (error_messages != NULL)
    goto failure;

  gum_add_abi_symbols (state);

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
gum_tcc_cmodule_add_symbol (GumCModule * cm,
                            const gchar * name,
                            gconstpointer value)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  tcc_add_symbol (self->state, name, value);
}

static gboolean
gum_tcc_cmodule_link_pre (GumCModule * cm,
                          gsize * size,
                          GString ** error_messages)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);
  TCCState * state = self->state;
  int res;

  tcc_set_error_func (state, error_messages, gum_append_tcc_error);

  res = tcc_relocate (state, NULL);
  if (res == -1)
    return FALSE;

  *size = res;
  return TRUE;
}

static gboolean
gum_tcc_cmodule_link (GumCModule * cm,
                      gpointer base,
                      GString ** error_messages)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  return tcc_relocate (self->state, base) != -1;
}

static void
gum_tcc_cmodule_link_post (GumCModule * cm)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  tcc_set_error_func (self->state, NULL, NULL);
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
  GumEnumerateSymbolsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  tcc_list_symbols (self->state, &ctx, gum_emit_symbol);
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

  return tcc_get_symbol (self->state, name);
}

static void
gum_tcc_cmodule_drop_metadata (GumCModule * cm)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  g_clear_pointer (&self->state, tcc_delete);
}

static void
gum_tcc_cmodule_add_define (GumCModule * cm,
                            const gchar * name,
                            const gchar * value)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  tcc_define_symbol (self->state, name, value);
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

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8 && !defined (_MSC_VER)

extern void * __va_arg (void * ap, int arg_type, int size, int align);

static void
gum_add_abi_symbols (TCCState * state)
{
  tcc_add_symbol (state, "__va_arg", __va_arg);
}

#elif defined (HAVE_ARM)

static void gum_aeabi_memset (void * dest, size_t n, int c);

static void
gum_add_abi_symbols (TCCState * state)
{
  tcc_add_symbol (state, "__aeabi_memmove", memmove);
  tcc_add_symbol (state, "__aeabi_memmove4", memmove);
  tcc_add_symbol (state, "__aeabi_memmove8", memmove);
  tcc_add_symbol (state, "__aeabi_memset", gum_aeabi_memset);
}

static void
gum_aeabi_memset (void * dest,
                  size_t n,
                  int c)
{
  memset (dest, c, n);
}

#else

static void
gum_add_abi_symbols (TCCState * state)
{
}

#endif

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

#define GUM_TYPE_GCC_CMODULE (gum_gcc_cmodule_get_type ())
G_DECLARE_FINAL_TYPE (GumGccCModule, gum_gcc_cmodule, GUM, GCC_CMODULE,
    GumCModule)

struct _GumGccCModule
{
  GumCModule parent;
};

static void gum_gcc_cmodule_add_symbol (GumCModule * cm, const gchar * name,
    gconstpointer value);
static gboolean gum_gcc_cmodule_link_pre (GumCModule * cm, gsize * size,
    GString ** error_messages);
static gboolean gum_gcc_cmodule_link (GumCModule * cm, gpointer base,
    GString ** error_messages);
static void gum_gcc_cmodule_link_post (GumCModule * cm);
static void gum_gcc_cmodule_enumerate_symbols (GumCModule * cm,
    GumFoundCSymbolFunc func, gpointer user_data);
static gpointer gum_gcc_cmodule_find_symbol_by_name (GumCModule * cm,
    const gchar * name);
static void gum_gcc_cmodule_drop_metadata (GumCModule * cm);
static void gum_gcc_cmodule_add_define (GumCModule * cm, const gchar * name,
    const gchar * value);

G_DEFINE_TYPE (GumGccCModule, gum_gcc_cmodule, GUM_TYPE_CMODULE)

static void
gum_gcc_cmodule_class_init (GumGccCModuleClass * klass)
{
  GumCModuleClass * cmodule_class = GUM_CMODULE_CLASS (klass);

  cmodule_class->add_symbol = gum_gcc_cmodule_add_symbol;
  cmodule_class->link_pre = gum_gcc_cmodule_link_pre;
  cmodule_class->link = gum_gcc_cmodule_link;
  cmodule_class->link_post = gum_gcc_cmodule_link_post;
  cmodule_class->enumerate_symbols = gum_gcc_cmodule_enumerate_symbols;
  cmodule_class->find_symbol_by_name = gum_gcc_cmodule_find_symbol_by_name;
  cmodule_class->drop_metadata = gum_gcc_cmodule_drop_metadata;
  cmodule_class->add_define = gum_gcc_cmodule_add_define;
}

static void
gum_gcc_cmodule_init (GumGccCModule * cmodule)
{
}

static GumCModule *
gum_gcc_cmodule_new (const gchar * source,
                     GError ** error)
{
  g_assert_not_reached ();
}

static void
gum_gcc_cmodule_add_symbol (GumCModule * cm,
                            const gchar * name,
                            gconstpointer value)
{
  g_assert_not_reached ();
}

static gboolean
gum_gcc_cmodule_link_pre (GumCModule * cm,
                          gsize * size,
                          GString ** error_messages)
{
  g_assert_not_reached ();
}

static gboolean
gum_gcc_cmodule_link (GumCModule * cm,
                      gpointer base,
                      GString ** error_messages)
{
  g_assert_not_reached ();
}

static void
gum_gcc_cmodule_link_post (GumCModule * cm)
{
  g_assert_not_reached ();
}

static void
gum_gcc_cmodule_enumerate_symbols (GumCModule * cm,
                                   GumFoundCSymbolFunc func,
                                   gpointer user_data)
{
  g_assert_not_reached ();
}

static gpointer
gum_gcc_cmodule_find_symbol_by_name (GumCModule * cm,
                                     const gchar * name)
{
  g_assert_not_reached ();
}

static void
gum_gcc_cmodule_drop_metadata (GumCModule * cm)
{
  g_assert_not_reached ();
}

static void
gum_gcc_cmodule_add_define (GumCModule * cm,
                            const gchar * name,
                            const gchar * value)
{
  g_assert_not_reached ();
}
