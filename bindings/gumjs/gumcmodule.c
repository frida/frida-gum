/*
 * Copyright (C) 2019-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcmodule.h"

#include <gio/gio.h>

struct _GumCModuleOps
{
  GumCModule * (*gum_cmodule_new) (const GumCModuleOps *, const gchar *,
      GError **);
  void (*gum_cmodule_free) (GumCModule *);
  void (*gum_cmodule_add_symbol) (GumCModule *, const gchar *, gconstpointer);
  gint (*gum_cmodule_link_pre) (GumCModule *, GString **);
  gint (*gum_cmodule_link) (GumCModule *, gpointer);
  void (*gum_cmodule_link_post) (GumCModule *);
  void (*gum_cmodule_enumerate_symbols) (GumCModule *, GumFoundCSymbolFunc,
      gpointer);
  gpointer (*gum_cmodule_find_symbol_by_name) (GumCModule *, const gchar *);
  void (*gum_cmodule_drop_metadata) (GumCModule *);
  void (*gum_cmodule_add_define) (GumCModule *, const gchar *, const gchar *);
};

typedef void (* GumCModuleInitFunc) (void);
typedef void (* GumCModuleFinalizeFunc) (void);

struct _GumCModule
{
  const GumCModuleOps* ops;
  GumMemoryRange range;
  GumCModuleFinalizeFunc finalize;
};

static void
gum_add_define_str (GumCModule * self,
                    const gchar * name,
                    const gchar * value)
{
  gchar * raw_value;

  raw_value = g_strconcat ("\"", value, "\"", NULL);

  self->ops->gum_cmodule_add_define (self, name, raw_value);

  g_free (raw_value);
}

static void
gum_add_defines (GumCModule * self)
{
#if defined (HAVE_I386)
  self->ops->gum_cmodule_add_define (self, "HAVE_I386", NULL);
#elif defined (HAVE_ARM)
  self->ops->gum_cmodule_add_define (self, "HAVE_ARM", NULL);
#elif defined (HAVE_ARM64)
  self->ops->gum_cmodule_add_define (self, "HAVE_ARM64", NULL);
#elif defined (HAVE_MIPS)
  self->ops->gum_cmodule_add_define (self, "HAVE_MIPS", NULL);
#endif

  self->ops->gum_cmodule_add_define (self, "TRUE", "1");
  self->ops->gum_cmodule_add_define (self, "FALSE", "0");

  gum_add_define_str (self, "G_GINT16_MODIFIER", G_GINT16_MODIFIER);
  gum_add_define_str (self, "G_GINT32_MODIFIER", G_GINT32_MODIFIER);
  gum_add_define_str (self, "G_GINT64_MODIFIER", G_GINT64_MODIFIER);
  gum_add_define_str (self, "G_GSIZE_MODIFIER", G_GSIZE_MODIFIER);
  gum_add_define_str (self, "G_GSSIZE_MODIFIER", G_GSSIZE_MODIFIER);

  self->ops->gum_cmodule_add_define (self, "GLIB_SIZEOF_VOID_P",
      G_STRINGIFY (GLIB_SIZEOF_VOID_P));

#ifdef HAVE_WINDOWS
  self->ops->gum_cmodule_add_define (self,
      "extern", "__attribute__ ((dllimport))");
#endif
}

#ifdef HAVE_TINYCC

#include <gum/gum-init.h>
#include <gum/gum.h>
#include <json-glib/json-glib.h>
#include <libtcc.h>

typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumCModuleHeader GumCModuleHeader;

struct _GumCModuleTcc
{
  GumCModule common;
  TCCState * state;
};

typedef struct _GumCModuleTcc GumCModuleTcc;

enum _GumCModuleHeaderKind
{
  GUM_CMODULE_HEADER_TCC,
  GUM_CMODULE_HEADER_FRIDA
};

typedef enum _GumCModuleHeaderKind GumCModuleHeaderKind;

struct _GumCModuleHeader
{
  const gchar * name;
  const gchar * data;
  guint size;
  GumCModuleHeaderKind kind;
};

struct _GumEnumerateSymbolsContext
{
  GumFoundCSymbolFunc func;
  gpointer user_data;
};

static void gum_append_tcc_error (void * opaque, const char * msg);
static void gum_emit_symbol (void * ctx, const char * name, const void * val);
static const char * gum_cmodule_load_header (void * opaque, const char * path,
    int * len);
static void * gum_cmodule_resolve_symbol (void * opaque, const char * name);
static const gchar * gum_undecorate_name (const gchar * name);

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8 && !defined (_MSC_VER)
extern void * __va_arg (void * ap, int arg_type, int size, int align);
#endif

#include "gumcmodule-runtime.h"

static GumCModule *
gum_cmodule_new_tcc (const GumCModuleOps * ops, const gchar * source,
    GError ** error)
{
  GumCModuleTcc * cmodule;
  TCCState * state;
  GString * error_messages;
  gchar * combined_source;

  cmodule = g_slice_new0 (GumCModuleTcc);
  cmodule->common.ops = ops;

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

  gum_add_defines (&cmodule->common);

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

  return (GumCModule *) cmodule;

failure:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Compilation failed: %s", error_messages->str);
    g_string_free (error_messages, TRUE);

    gum_cmodule_free (&cmodule->common);

    return NULL;
  }
}

static void
gum_cmodule_free_tcc (GumCModule * _cmodule)
{
  g_slice_free (GumCModuleTcc, (GumCModuleTcc *) _cmodule);
}

static void
gum_cmodule_add_symbol_tcc (GumCModule * _self,
                            const gchar * name,
                            gconstpointer value)
{
  GumCModuleTcc * self = (GumCModuleTcc *) _self;
  TCCState * state = self->state;

  g_assert (state != NULL);

  tcc_add_symbol (state, name, value);
}

static gint
gum_cmodule_link_pre_tcc (GumCModule * _self, GString ** error_messages)
{
  GumCModuleTcc * self = (GumCModuleTcc *) _self;
  TCCState * state = self->state;

  g_assert (state != NULL);

  tcc_set_error_func (state, error_messages, gum_append_tcc_error);

  return tcc_relocate (state, NULL);
}

static gint
gum_cmodule_link_tcc (GumCModule * _self, gpointer base)
{
  return tcc_relocate (((GumCModuleTcc *) _self)->state, base);
}

static void
gum_cmodule_link_post_tcc (GumCModule * _self)
{
  tcc_set_error_func (((GumCModuleTcc *) _self)->state, NULL, NULL);
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
gum_cmodule_enumerate_symbols_tcc (GumCModule * _self,
                                   GumFoundCSymbolFunc func,
                                   gpointer user_data)
{
  GumCModuleTcc * self = (GumCModuleTcc *) _self;
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
gum_cmodule_find_symbol_by_name_tcc (GumCModule * _self,
                                     const gchar * name)
{
  GumCModuleTcc * self = (GumCModuleTcc *) _self;
  TCCState * state = self->state;

  g_assert (state != NULL);
  g_assert (self->common.range.base_address != 0);

  return tcc_get_symbol (state, name);
}

static void
gum_cmodule_drop_metadata_tcc (GumCModule * _self)
{
  GumCModuleTcc * self = (GumCModuleTcc *) _self;

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

static void gum_cmodule_add_define_tcc (GumCModule * self,
    const gchar * name, const gchar * value)
{
  tcc_define_symbol (((GumCModuleTcc *) self)->state, name, value);
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

static const GumCModuleOps
gum_cmodule_tcc_ops = {
  .gum_cmodule_new = gum_cmodule_new_tcc,
  .gum_cmodule_free = gum_cmodule_free_tcc,
  .gum_cmodule_add_symbol = gum_cmodule_add_symbol_tcc,
  .gum_cmodule_link_pre = gum_cmodule_link_pre_tcc,
  .gum_cmodule_link = gum_cmodule_link_tcc,
  .gum_cmodule_link_post = gum_cmodule_link_post_tcc,
  .gum_cmodule_enumerate_symbols = gum_cmodule_enumerate_symbols_tcc,
  .gum_cmodule_find_symbol_by_name = gum_cmodule_find_symbol_by_name_tcc,
  .gum_cmodule_drop_metadata = gum_cmodule_drop_metadata_tcc,
  .gum_cmodule_add_define = gum_cmodule_add_define_tcc,
};

#endif /* HAVE_TINYCC */

struct _GumCModuleGcc
{
  GumCModule common;
  gchar * workdir;
  GPtrArray * argv;
};

typedef struct _GumCModuleGcc GumCModuleGcc;

static GumCModule *
gum_cmodule_new_gcc (const GumCModuleOps * ops, const gchar * source,
    GError ** error)
{
  GumCModuleGcc * cmodule;
  gchar * filename;
  gchar * dirname;
  guint i;
  gchar * standard_output;
  gchar * standard_error;
  gint exit_status;

  cmodule = g_slice_new0 (GumCModuleGcc);
  cmodule->common.ops = ops;

  cmodule->workdir = g_dir_make_tmp ("frida-gcc-XXXXXX", error);
  if (cmodule->workdir == NULL)
    goto failure;

  filename = g_build_filename (cmodule->workdir, "module.c", NULL);
  if (!g_file_set_contents (filename, source, strlen (source), error))
  {
    g_clear_pointer (&filename, g_free);
    goto failure;
  }
  g_clear_pointer (&filename, g_free);
  for (i = 0; i != G_N_ELEMENTS (gum_cmodule_headers); i++)
  {
    const GumCModuleHeader * h = &gum_cmodule_headers[i];
    if (h->kind == GUM_CMODULE_HEADER_TCC)
      continue;
    filename = g_build_filename (cmodule->workdir, h->name, NULL);
    dirname = g_path_get_dirname (filename);
    g_mkdir_with_parents (dirname, 0700);
    g_clear_pointer (&dirname, g_free);
    if (!g_file_set_contents (filename, h->data, h->size, error))
    {
      g_clear_pointer (&filename, g_free);
      goto failure;
    }
    g_clear_pointer (&filename, g_free);
  }

  cmodule->argv = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (cmodule->argv, g_strdup ("gcc"));
  gum_add_defines (&cmodule->common);
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
  if (!g_spawn_sync (cmodule->workdir, (gchar **) cmodule->argv->pdata, NULL,
      G_SPAWN_SEARCH_PATH, NULL, NULL, &standard_output, &standard_error,
      &exit_status, error))
  {
    g_ptr_array_free (cmodule->argv, TRUE);
    cmodule->argv = NULL;
    goto failure;
  }
  if (exit_status != 0)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Compilation failed: %s%s", standard_output, standard_error);
    g_ptr_array_free (cmodule->argv, TRUE);
    cmodule->argv = NULL;
    g_clear_pointer (&standard_output, g_free);
    g_clear_pointer (&standard_error, g_free);
    goto failure;
  }

  g_ptr_array_free (cmodule->argv, TRUE);
  cmodule->argv = NULL;
  g_clear_pointer (&standard_output, g_free);
  g_clear_pointer (&standard_error, g_free);

  return (GumCModule *) cmodule;

failure:
  {
    gum_cmodule_free (&cmodule->common);

    return NULL;
  }
}

static void
rmtree (GFile * file)
{
  GFileEnumerator * direnum;

  direnum = g_file_enumerate_children (file, "",
      G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, NULL);
  if (direnum != NULL)
  {
    while (TRUE)
    {
      GFile * child;
      if (!g_file_enumerator_iterate (direnum, NULL, &child, NULL, NULL))
        break;
      if (child == NULL)
        break;
      rmtree (child);
    }
    g_clear_pointer (&direnum, g_object_unref);
  }

  g_file_delete (file, NULL, NULL);
}

static void
gum_cmodule_free_gcc (GumCModule * _cmodule)
{
  g_slice_free (GumCModuleGcc, (GumCModuleGcc *) _cmodule);
}

static void
gum_cmodule_add_symbol_gcc (GumCModule * _self,
                            const gchar * name,
                            gconstpointer value)
{
  g_assert_not_reached ();
}

static gint
gum_cmodule_link_pre_gcc (GumCModule * _self, GString ** error_messages)
{
  g_assert_not_reached ();
  return -1;
}

static gint
gum_cmodule_link_gcc (GumCModule * _self, gpointer base)
{
  g_assert_not_reached ();
  return -1;
}

static void
gum_cmodule_link_post_gcc (GumCModule * _self)
{
  g_assert_not_reached ();
}

static void
gum_cmodule_enumerate_symbols_gcc (GumCModule * _self,
                                   GumFoundCSymbolFunc func,
                                   gpointer user_data)
{
  g_assert_not_reached ();
}

static gpointer
gum_cmodule_find_symbol_by_name_gcc (GumCModule * _self,
                                     const gchar * name)
{
  g_assert_not_reached ();
  return NULL;
}

static void
gum_cmodule_drop_metadata_gcc (GumCModule * _self)
{
  GumCModuleGcc * self = (GumCModuleGcc *) _self;

  if (self->workdir != NULL)
  {
    GFile * workdir_file = g_file_new_for_path (self->workdir);
    rmtree (workdir_file);
    g_clear_pointer (&workdir_file, g_object_unref);
    g_clear_pointer (&self->workdir, g_free);
  }
}

static void gum_cmodule_add_define_gcc (GumCModule * _self,
    const gchar * name, const gchar * value)
{
  GumCModuleGcc * self = (GumCModuleGcc *) _self;
  GString * arg;

  arg = g_string_new (NULL);
  if (value == NULL)
    g_string_printf (arg, "-D%s", name);
  else
    g_string_printf (arg, "-D%s=%s", name, value);
  g_ptr_array_add (self->argv, g_string_free (arg, FALSE));
}

static const GumCModuleOps
gum_cmodule_gcc_ops = {
  .gum_cmodule_new = gum_cmodule_new_gcc,
  .gum_cmodule_free = gum_cmodule_free_gcc,
  .gum_cmodule_add_symbol = gum_cmodule_add_symbol_gcc,
  .gum_cmodule_link_pre = gum_cmodule_link_pre_gcc,
  .gum_cmodule_link = gum_cmodule_link_gcc,
  .gum_cmodule_link_post = gum_cmodule_link_post_gcc,
  .gum_cmodule_enumerate_symbols = gum_cmodule_enumerate_symbols_gcc,
  .gum_cmodule_find_symbol_by_name = gum_cmodule_find_symbol_by_name_gcc,
  .gum_cmodule_drop_metadata = gum_cmodule_drop_metadata_gcc,
  .gum_cmodule_add_define = gum_cmodule_add_define_gcc,
};

const GumCModuleOps *
gum_cmodule_get_ops (const gchar * name)
{
#ifdef HAVE_TINYCC
  if (!name || strcmp (name, "tcc") == 0)
    return &gum_cmodule_tcc_ops;
#endif
  if (!name || strcmp (name, "gcc") == 0)
    return &gum_cmodule_gcc_ops;
  return NULL;
}

GumCModule *
gum_cmodule_new (const GumCModuleOps * ops,
                 const gchar * source,
                 GError ** error)
{
  if (ops == NULL) {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
        "Not available for the current architecture");
    return NULL;
  }

  return ops->gum_cmodule_new (ops, source, error);
}

void
gum_cmodule_free (GumCModule * cmodule)
{
  const GumMemoryRange * r;

  if (cmodule == NULL)
    return;

  r = &cmodule->range;
  if (r->base_address != 0)
  {
    if (cmodule->finalize != NULL)
      cmodule->finalize ();

    gum_cloak_remove_range (r);

    gum_memory_free (GSIZE_TO_POINTER (r->base_address), r->size);
  }

  gum_cmodule_drop_metadata (cmodule);

  cmodule->ops->gum_cmodule_free (cmodule);
}

const GumMemoryRange *
gum_cmodule_get_range (GumCModule * self)
{
  g_assert (self != NULL);

  return &self->range;
}

void
gum_cmodule_add_symbol (GumCModule * self,
                        const gchar * name,
                        gconstpointer value)
{
  g_assert (self != NULL);

  self->ops->gum_cmodule_add_symbol (self, name, value);
}

gboolean
gum_cmodule_link (GumCModule * self,
                  GError ** error)
{
  GString * error_messages;
  gint res;
  guint size, page_size;
  gpointer base;

  g_assert (self != NULL);
  g_assert (self->range.base_address == 0);

  error_messages = NULL;
  res = self->ops->gum_cmodule_link_pre (self, &error_messages);
  if (res == -1)
    goto beach;
  size = res;

  page_size = gum_query_page_size ();

  base = gum_memory_allocate (NULL, size, page_size, GUM_PAGE_RW);

  res = self->ops->gum_cmodule_link (self, base);
  if (res == 0)
  {
    GumMemoryRange * r = &self->range;
    GumCModuleInitFunc init;

    r->base_address = GUM_ADDRESS (base);
    r->size = GUM_ALIGN_SIZE (size, page_size);

    gum_memory_mark_code (base, size);

    gum_cloak_add_range (r);

    init = GUM_POINTER_TO_FUNCPTR (GumCModuleInitFunc,
        gum_cmodule_find_symbol_by_name (self, "init"));
    if (init != NULL)
      init ();

    self->finalize = GUM_POINTER_TO_FUNCPTR (GumCModuleFinalizeFunc,
        gum_cmodule_find_symbol_by_name (self, "finalize"));
  }
  else
  {
    gum_memory_free (base, size);
  }

beach:
  self->ops->gum_cmodule_link_post (self);

  if (error_messages != NULL)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "Linking failed: %s", error_messages->str);
    g_string_free (error_messages, TRUE);
  }

  return res == 0;
}

void
gum_cmodule_enumerate_symbols (GumCModule * self,
                               GumFoundCSymbolFunc func,
                               gpointer user_data)
{
  g_assert (self != NULL);

  self->ops->gum_cmodule_enumerate_symbols (self, func, user_data);
}

gpointer
gum_cmodule_find_symbol_by_name (GumCModule * self,
                                 const gchar * name)
{
  g_assert (self != NULL);

  return self->ops->gum_cmodule_find_symbol_by_name (self, name);
}

void
gum_cmodule_drop_metadata (GumCModule * self)
{
  g_assert (self != NULL);

  self->ops->gum_cmodule_drop_metadata (self);
}
