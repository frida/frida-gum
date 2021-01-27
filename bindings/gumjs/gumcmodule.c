/*
 * Copyright (C) 2019-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcmodule.h"

#include <stdio.h>
#include <string.h>
#include <gio/gio.h>
#include <gum/gum-init.h>
#include <gum/gum.h>
#include <json-glib/json-glib.h>

#ifdef HAVE_TINYCC
static GumCModule * gum_tcc_cmodule_new (const gchar * source, GError ** error);
#endif
static GumCModule * gum_gcc_cmodule_new (const gchar * source, GError ** error);

typedef struct _GumCModulePrivate GumCModulePrivate;

typedef void (* GumCModuleInitFunc) (void);
typedef void (* GumCModuleFinalizeFunc) (void);

typedef struct _GumCModuleHeader GumCModuleHeader;
typedef guint GumCModuleHeaderKind;

struct _GumCModulePrivate
{
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
  GUM_CMODULE_HEADER_FRIDA,
  GUM_CMODULE_HEADER_TCC
};

static void gum_cmodule_finalize (GObject * object);
static void gum_cmodule_add_define_str (GumCModule * self, const gchar * name,
    const gchar * value);

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (GumCModule, gum_cmodule, G_TYPE_OBJECT);

#include "gumcmodule-runtime.h"

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
gum_cmodule_add_defines (GumCModule * self)
{
  GumCModuleClass * cls = GUM_CMODULE_GET_CLASS (self);

#if defined (HAVE_I386)
  cls->add_define (self, "HAVE_I386", NULL);
#elif defined (HAVE_ARM)
  cls->add_define (self, "HAVE_ARM", NULL);
#elif defined (HAVE_ARM64)
  cls->add_define (self, "HAVE_ARM64", NULL);
#elif defined (HAVE_MIPS)
  cls->add_define (self, "HAVE_MIPS", NULL);
#endif

  cls->add_define (self, "TRUE", "1");
  cls->add_define (self, "FALSE", "0");

  gum_cmodule_add_define_str (self, "G_GINT16_MODIFIER", G_GINT16_MODIFIER);
  gum_cmodule_add_define_str (self, "G_GINT32_MODIFIER", G_GINT32_MODIFIER);
  gum_cmodule_add_define_str (self, "G_GINT64_MODIFIER", G_GINT64_MODIFIER);
  gum_cmodule_add_define_str (self, "G_GSIZE_MODIFIER", G_GSIZE_MODIFIER);
  gum_cmodule_add_define_str (self, "G_GSSIZE_MODIFIER", G_GSSIZE_MODIFIER);

  cls->add_define (self, "GLIB_SIZEOF_VOID_P", G_STRINGIFY (GLIB_SIZEOF_VOID_P));

#ifdef HAVE_WINDOWS
  cls->add_define (self, "extern", "__attribute__ ((dllimport))");
#endif
}

static void
gum_cmodule_add_define_str (GumCModule * self,
                            const gchar * name,
                            const gchar * value)
{
  gchar * raw_value;

  raw_value = g_strconcat ("\"", value, "\"", NULL);

  GUM_CMODULE_GET_CLASS (self)->add_define (self, name, raw_value);

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

static void
gum_append_error (GString ** messages,
                  const char * msg)
{
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

#ifdef HAVE_TINYCC

#include <libtcc.h>

#define GUM_TYPE_TCC_CMODULE (gum_tcc_cmodule_get_type ())
G_DECLARE_FINAL_TYPE (GumTccCModule, gum_tcc_cmodule, GUM, TCC_CMODULE,
    GumCModule)

typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;

struct _GumTccCModule
{
  GumCModule parent;

  TCCState * state;
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

  gum_cmodule_add_defines (result);

  tcc_set_output_type (state, TCC_OUTPUT_MEMORY);

  combined_source = g_strconcat ("#line 1 \"module.c\"\n", source, NULL);

  tcc_compile_string (state, combined_source);

  g_free (combined_source);

  tcc_set_error_func (state, NULL, NULL);

  if (error_messages != NULL)
    goto propagate_error;

  gum_add_abi_symbols (state);

  return result;

propagate_error:
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

  gum_append_error (messages, msg);
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

typedef struct _GumLdsPrinter GumLdsPrinter;

struct _GumGccCModule
{
  GumCModule parent;

  gchar * workdir;
  GPtrArray * argv;
  GArray * symbols;
};

struct _GumLdsPrinter
{
  FILE * file;
  gpointer base;
};

static gboolean gum_gcc_cmodule_populate_include_dir (GumGccCModule * self,
    GError ** error);
static void gum_gcc_cmodule_add_symbol (GumCModule * cm, const gchar * name,
    gconstpointer value);
static gboolean gum_gcc_cmodule_link_pre (GumCModule * cm, gsize * size,
    GString ** error_messages);
static gboolean gum_gcc_cmodule_link (GumCModule * cm, gpointer base,
    GString ** error_messages);
static void gum_gcc_cmodule_link_post (GumCModule * cm);
static gboolean gum_gcc_cmodule_do_link (GumCModule * cm, gpointer base,
    gpointer * contents, gsize * size, GString ** error_messages);
static gboolean gum_gcc_cmodule_call_ld (GumGccCModule * self, gpointer base,
    GError ** error);
static gboolean gum_gcc_cmodule_call_objcopy (GumGccCModule * self,
    GError ** error);
static void gum_write_linker_script (FILE * file, gpointer base,
    GHashTable * api_symbols, GArray * user_symbols);
static void gum_print_lds_assignment (gpointer key, gpointer value,
    gpointer user_data);
static void gum_gcc_cmodule_enumerate_symbols (GumCModule * cm,
    GumFoundCSymbolFunc func, gpointer user_data);
static gpointer gum_gcc_cmodule_find_symbol_by_name (GumCModule * cm,
    const gchar * name);
static void gum_store_address_if_name_matches (
    const GumCSymbolDetails * details, gpointer user_data);
static void gum_gcc_cmodule_drop_metadata (GumCModule * cm);
static void gum_gcc_cmodule_add_define (GumCModule * cm, const gchar * name,
    const gchar * value);
static gboolean gum_gcc_cmodule_call_tool (GumGccCModule * self,
    const gchar * const * argv, gchar ** output, gint * exit_status,
    GError ** error);

static void gum_csymbol_details_destroy (GumCSymbolDetails * details);

static void gum_rmtree (GFile * file);

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
gum_gcc_cmodule_init (GumGccCModule * self)
{
  self->argv = g_ptr_array_new_with_free_func (g_free);
}

static GumCModule *
gum_gcc_cmodule_new (const gchar * source,
                     GError ** error)
{
  GumCModule * result;
  GumGccCModule * cmodule;
  gboolean success = FALSE;
  gchar * source_path = NULL;
  gchar * output = NULL;
  gint exit_status;

  result = g_object_new (GUM_TYPE_GCC_CMODULE, NULL);
  cmodule = GUM_GCC_CMODULE (result);

  cmodule->workdir = g_dir_make_tmp ("frida-gcc-XXXXXX", error);
  if (cmodule->workdir == NULL)
    goto beach;

  source_path = g_build_filename (cmodule->workdir, "module.c", NULL);

  if (!g_file_set_contents (source_path, source, -1, error))
    goto beach;

  if (!gum_gcc_cmodule_populate_include_dir (cmodule, error))
    goto beach;

  g_ptr_array_add (cmodule->argv, g_strdup ("gcc"));
  gum_cmodule_add_defines (result);
  g_ptr_array_add (cmodule->argv, g_strdup ("-c"));
  g_ptr_array_add (cmodule->argv, g_strdup ("-O2"));
  g_ptr_array_add (cmodule->argv, g_strdup ("-fno-pic"));
#if defined (HAVE_I386)
  g_ptr_array_add (cmodule->argv, g_strdup ("-mcmodel=large"));
#endif
  g_ptr_array_add (cmodule->argv, g_strdup ("-nostdlib"));
  g_ptr_array_add (cmodule->argv, g_strdup ("-isystem"));
  g_ptr_array_add (cmodule->argv, g_strdup ("."));
  g_ptr_array_add (cmodule->argv, g_strdup ("-isystem"));
  g_ptr_array_add (cmodule->argv, g_strdup ("capstone"));
  g_ptr_array_add (cmodule->argv, g_strdup ("module.c"));
  g_ptr_array_add (cmodule->argv, NULL);

  if (!gum_gcc_cmodule_call_tool (cmodule,
      (const gchar * const *) cmodule->argv->pdata, &output, &exit_status,
      error))
  {
    goto beach;
  }

  if (exit_status != 0)
    goto compilation_failed;

  success = TRUE;
  goto beach;

compilation_failed:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Compilation failed: %s", output);
    goto beach;
  }
beach:
  {
    g_free (output);
    g_free (source_path);
    if (!success)
      g_clear_object (&result);

    return result;
  }
}

static gboolean
gum_gcc_cmodule_populate_include_dir (GumGccCModule * self,
                                      GError ** error)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (gum_cmodule_headers); i++)
  {
    const GumCModuleHeader * h = &gum_cmodule_headers[i];
    gchar * filename, * dirname;
    gboolean written;

    if (h->kind != GUM_CMODULE_HEADER_FRIDA)
      continue;

    filename = g_build_filename (self->workdir, h->name, NULL);
    dirname = g_path_get_dirname (filename);

    g_mkdir_with_parents (dirname, 0700);
    written = g_file_set_contents (filename, h->data, h->size, error);

    g_free (dirname);
    g_free (filename);

    if (!written)
      return FALSE;
  }

  return TRUE;
}

static void
gum_gcc_cmodule_add_symbol (GumCModule * cm,
                            const gchar * name,
                            gconstpointer value)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);
  GumCSymbolDetails d;

  if (self->symbols == NULL)
  {
    self->symbols = g_array_new (FALSE, FALSE, sizeof (GumCSymbolDetails));
    g_array_set_clear_func (self->symbols,
        (GDestroyNotify) gum_csymbol_details_destroy);
  }

  d.name = g_strdup (name);
  d.address = (gpointer) value;
  g_array_append_val (self->symbols, d);
}

static gboolean
gum_gcc_cmodule_link_pre (GumCModule * cm,
                          gsize * size,
                          GString ** error_messages)
{
  gpointer contents;

  if (!gum_gcc_cmodule_do_link (cm, 0, &contents, size, error_messages))
    return FALSE;

  g_free (contents);

  return TRUE;
}

static gboolean
gum_gcc_cmodule_link (GumCModule * cm,
                      gpointer base,
                      GString ** error_messages)
{
  gpointer contents;
  gsize size;

  if (!gum_gcc_cmodule_do_link (cm, base, &contents, &size, error_messages))
    return FALSE;

  memcpy (base, contents, size);
  g_free (contents);

  return TRUE;
}

static void
gum_gcc_cmodule_link_post (GumCModule * cm)
{
}

static gboolean
gum_gcc_cmodule_do_link (GumCModule * cm,
                         gpointer base,
                         gpointer * contents,
                         gsize * size,
                         GString ** error_messages)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);
  gboolean success = FALSE;
  GError * error = NULL;
  gchar * module_path = NULL;

  if (!gum_gcc_cmodule_call_ld (self, base, &error))
    goto propagate_error;

  if (!gum_gcc_cmodule_call_objcopy (self, &error))
    goto propagate_error;

  module_path = g_build_filename (self->workdir, "module", NULL);

  if (!g_file_get_contents (module_path, (gchar **) contents, size, &error))
    goto propagate_error;

  success = TRUE;
  goto beach;

propagate_error:
  {
    gum_append_error (error_messages, error->message);
    g_error_free (error);
    goto beach;
  }
beach:
  {
    g_free (module_path);

    return success;
  }
}

static gboolean
gum_gcc_cmodule_call_ld (GumGccCModule * self,
                         gpointer base,
                         GError ** error)
{
  gboolean success = FALSE;
  gchar * linker_script_path;
  FILE * file;
  const gchar * argv[] = {
    "gcc",
    "-nostdlib",
    "-Wl,--build-id=none",
    "-Wl,--script=module.lds",
    "module.o",
    NULL
  };
  gchar * output = NULL;
  gint exit_status;

  linker_script_path = g_build_filename (self->workdir, "module.lds", NULL);

  file = fopen (linker_script_path, "w");
  if (file == NULL)
    goto fopen_failed;
  gum_write_linker_script (file, base, gum_cmodule_get_symbols (),
      self->symbols);
  fclose (file);

  if (!gum_gcc_cmodule_call_tool (self, argv, &output, &exit_status, error))
    goto beach;

  if (exit_status != 0)
    goto ld_failed;

  success = TRUE;
  goto beach;

fopen_failed:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Failed to create %s", linker_script_path);
    goto beach;
  }
ld_failed:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "ld failed: %s", output);
    goto beach;
  }
beach:
  {
    g_free (output);
    g_free (linker_script_path);

    return success;
  }
}

static gboolean
gum_gcc_cmodule_call_objcopy (GumGccCModule * self,
                              GError ** error)
{
  gboolean success = FALSE;
  const gchar * argv[] = {
    "objcopy",
    "-O", "binary",
    "--only-section=.frida",
    "a.out",
    "module",
    NULL
  };
  gchar * output;
  gint exit_status;

  if (!gum_gcc_cmodule_call_tool (self, argv, &output, &exit_status, error))
    return FALSE;

  if (exit_status != 0)
    goto objcopy_failed;

  success = TRUE;
  goto beach;

objcopy_failed:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "objcopy failed: %s", output);
    goto beach;
  }
beach:
  {
    g_free (output);

    return success;
  }
}

static void
gum_write_linker_script (FILE * file,
                         gpointer base,
                         GHashTable * api_symbols,
                         GArray * user_symbols)
{
  GumLdsPrinter printer = {
    .file = file,
    .base = base,
  };

  g_hash_table_foreach (api_symbols, gum_print_lds_assignment, &printer);

  if (user_symbols != NULL)
  {
    guint i;

    for (i = 0; i != user_symbols->len; i++)
    {
      GumCSymbolDetails * d =
          &g_array_index (user_symbols, GumCSymbolDetails, i);
      gum_print_lds_assignment ((gpointer) d->name, d->address, &printer);
    }
  }

  fprintf (printer.file,
      "SECTIONS {\n"
      "  .frida 0x%zx: {\n"
      "    *(.text*)\n"
      "    *(.data)\n"
      "    *(.bss)\n"
      "    *(COMMON)\n"
      "    *(.rodata*)\n"
      "  }\n"
      "  /DISCARD/ : { *(*) }\n"
      "}\n",
      GPOINTER_TO_SIZE (base));
}

static void
gum_print_lds_assignment (gpointer key,
                          gpointer value,
                          gpointer user_data)
{
  GumLdsPrinter * printer = user_data;

  fprintf (printer->file, "%s = 0x%zx;\n",
      (gchar *) key,
      (printer->base != NULL) ? GPOINTER_TO_SIZE (value) : 0);
}

static void
gum_gcc_cmodule_enumerate_symbols (GumCModule * cm,
                                   GumFoundCSymbolFunc func,
                                   gpointer user_data)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);
  const gchar * argv[] = { "nm", "a.out", NULL };
  gchar * output = NULL;
  gint exit_status;
  gchar * line_start;

  if (!gum_gcc_cmodule_call_tool (self, argv, &output, &exit_status, NULL))
    goto beach;

  if (exit_status != 0)
    goto beach;

  line_start = output;
  while (TRUE)
  {
    gchar * line_end;
    guint64 address;
    gchar * endptr;

    line_end = strchr (line_start, '\n');
    if (line_end == NULL)
      break;
    *line_end = '\0';

    address = g_ascii_strtoull (line_start, &endptr, 16);
    if (endptr != line_start)
    {
      GumCSymbolDetails d;

      d.address = GSIZE_TO_POINTER (address);
      d.name = endptr + 3;

      func (&d, user_data);
    }

    line_start = line_end + 1;
  }

beach:
  g_free (output);
}

static gpointer
gum_gcc_cmodule_find_symbol_by_name (GumCModule * cm,
                                     const gchar * name)
{
  GumCSymbolDetails ctx;

  ctx.name = name;
  ctx.address = NULL;
  gum_cmodule_enumerate_symbols (cm, gum_store_address_if_name_matches, &ctx);

  return ctx.address;
}

static void
gum_store_address_if_name_matches (const GumCSymbolDetails * details,
                                   gpointer user_data)
{
  GumCSymbolDetails * ctx = user_data;

  if (strcmp (details->name, ctx->name) == 0)
    ctx->address = details->address;
}

static void
gum_gcc_cmodule_drop_metadata (GumCModule * cm)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);

  if (self->workdir != NULL)
  {
    GFile * workdir_file = g_file_new_for_path (self->workdir);

    gum_rmtree (workdir_file);
    g_object_unref (workdir_file);

    g_free (self->workdir);
    self->workdir = NULL;
  }

  g_clear_pointer (&self->argv, g_ptr_array_unref);

  g_clear_pointer (&self->symbols, g_array_unref);
}

static void
gum_gcc_cmodule_add_define (GumCModule * cm,
                            const gchar * name,
                            const gchar * value)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);
  gchar * arg;

  arg = (value == NULL)
      ? g_strconcat ("-D", name, NULL)
      : g_strconcat ("-D", name, "=", value, NULL);

  g_ptr_array_add (self->argv, arg);
}

static gboolean
gum_gcc_cmodule_call_tool (GumGccCModule * self,
                           const gchar * const * argv,
                           gchar ** output,
                           gint * exit_status,
                           GError ** error)
{
  GSubprocessLauncher * launcher;
  GSubprocess * proc;

  launcher = g_subprocess_launcher_new (
      G_SUBPROCESS_FLAGS_STDOUT_PIPE |
      G_SUBPROCESS_FLAGS_STDERR_MERGE);
  g_subprocess_launcher_set_cwd (launcher, self->workdir);
  proc = g_subprocess_launcher_spawnv (launcher, argv, error);
  g_object_unref (launcher);
  if (proc == NULL)
    goto propagate_error;

  if (!g_subprocess_communicate_utf8 (proc, NULL, NULL, output, NULL, error))
    goto propagate_error;

  *exit_status = g_subprocess_get_exit_status (proc);

  g_object_unref (proc);

  return TRUE;

propagate_error:
  {
    g_clear_object (&proc);

    return FALSE;
  }
}

static void
gum_csymbol_details_destroy (GumCSymbolDetails * details)
{
  g_free ((gchar *) details->name);
}

static void
gum_rmtree (GFile * file)
{
  GFileEnumerator * enumerator;

  enumerator = g_file_enumerate_children (file, "",
      G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, NULL);
  if (enumerator != NULL)
  {
    while (TRUE)
    {
      GFileInfo * info;
      GFile * child;

      if (!g_file_enumerator_iterate (enumerator, &info, &child, NULL, NULL))
        break;
      if (child == NULL)
        break;

      if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
        gum_rmtree (child);
      else
        g_file_delete (file, NULL, NULL);
    }

    g_object_unref (enumerator);
  }

  g_file_delete (file, NULL, NULL);
}
