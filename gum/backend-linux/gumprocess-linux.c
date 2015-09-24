/*
 * Copyright (C) 2010-2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess.h"

#include "gumlinux.h"

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef HAVE_ANDROID
# include <ucontext.h>
#endif
#include <unistd.h>
#include <gio/gio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define GUM_HIJACK_SIGNAL (SIGRTMIN + 7)

#define GUM_MAPS_LINE_SIZE (1024 + PATH_MAX)

typedef struct _GumEnumerateImportsContext GumEnumerateImportsContext;
typedef struct _GumFindModuleContext GumFindModuleContext;
typedef struct _GumEnumerateModuleRangesContext GumEnumerateModuleRangesContext;
typedef struct _GumFindExportContext GumFindExportContext;

typedef struct _GumElfModule GumElfModule;
typedef struct _GumElfDependencyDetails GumElfDependencyDetails;
typedef struct _GumElfEnumerateImportsContext GumElfEnumerateImportsContext;
typedef struct _GumElfEnumerateExportsContext GumElfEnumerateExportsContext;
typedef struct _GumElfSymbolDetails GumElfSymbolDetails;

typedef gboolean (* GumElfFoundDependencyFunc) (
    const GumElfDependencyDetails * details, gpointer user_data);
typedef gboolean (* GumElfFoundSymbolFunc) (const GumElfSymbolDetails * details,
    gpointer user_data);

typedef guint GumElfSHeaderIndex;
typedef guint GumElfSHeaderType;
typedef guint GumElfSymbolType;
typedef guint GumElfSymbolBind;
#if GLIB_SIZEOF_VOID_P == 4
typedef Elf32_Ehdr GumElfEHeader;
typedef Elf32_Shdr GumElfSHeader;
typedef Elf32_Dyn GumElfDynamic;
typedef Elf32_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF32_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#else
typedef Elf64_Ehdr GumElfEHeader;
typedef Elf64_Shdr GumElfSHeader;
typedef Elf64_Dyn GumElfDynamic;
typedef Elf64_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF64_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF64_ST_TYPE(val)
#endif

struct _GumEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;

  GHashTable * dependency_exports;
  GumElfModule * current_dependency;
};

struct _GumFindModuleContext
{
  const gchar * module_name;
  GumAddress base;
  gchar * path;
};

struct _GumEnumerateModuleRangesContext
{
  const gchar * module_name;
  GumFoundRangeFunc func;
  gpointer user_data;
};

struct _GumFindExportContext
{
  GumAddress result;
  const gchar * symbol_name;
};

struct _GumElfModule
{
  gchar * path;
  gint fd;
  gsize file_size;
  gpointer data;
  GumElfEHeader * ehdr;
  gpointer address;
};

struct _GumElfDependencyDetails
{
  const gchar * name;
};

struct _GumElfEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;
};

struct _GumElfEnumerateExportsContext
{
  GumFoundExportFunc func;
  gpointer user_data;
};

struct _GumElfSymbolDetails
{
  const gchar * name;
  GumAddress address;
  GumElfSymbolType type;
  GumElfSymbolBind bind;
  GumElfSHeaderIndex section_header_index;
};

#ifndef HAVE_ANDROID
static void gum_do_modify_thread (int sig, siginfo_t * siginfo,
    void * context);
static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
#endif

static gboolean gum_emit_import (const GumImportDetails * details,
    gpointer user_data);
static gboolean gum_collect_dependency_exports (
    const GumElfDependencyDetails * details, gpointer user_data);
static gboolean gum_collect_dependency_export (const GumExportDetails * details,
    gpointer user_data);
static gboolean gum_emit_range_if_module_name_matches (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_store_base_and_path_if_name_matches (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_store_address_if_module_has_export (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_store_address_if_export_name_matches (
    const GumExportDetails * details, gpointer user_data);

static gboolean gum_module_path_equals (const gchar * path,
    const gchar * name_or_path);

static gboolean gum_elf_module_open (GumElfModule * module,
    const gchar * module_name);
static void gum_elf_module_close (GumElfModule * module);
static void gum_elf_module_enumerate_dependencies (GumElfModule * self,
    GumElfFoundDependencyFunc func, gpointer user_data);
static void gum_elf_module_enumerate_imports (GumElfModule * self,
    GumFoundImportFunc func, gpointer user_data);
static gboolean gum_emit_elf_import (const GumElfSymbolDetails * details,
    gpointer user_data);
static void gum_elf_module_enumerate_exports (GumElfModule * self,
    GumFoundExportFunc func, gpointer user_data);
static gboolean gum_emit_elf_export (const GumElfSymbolDetails * details,
    gpointer user_data);
static void gum_elf_module_enumerate_dynamic_symbols (GumElfModule * self,
    GumElfFoundSymbolFunc func, gpointer user_data);
static GumElfSHeader * gum_elf_module_find_section_header (GumElfModule * self,
    GumElfSHeaderType type);

#ifndef HAVE_ANDROID
static void gum_cpu_context_from_linux (const ucontext_t * uc,
    GumCpuContext * ctx);
static void gum_cpu_context_to_linux (const GumCpuContext * ctx,
    ucontext_t * uc);
static GumThreadState gum_thread_state_from_proc_status_character (gchar c);
#endif
static GumPageProtection gum_page_protection_from_proc_perms_string (
    const gchar * perms);

#ifndef HAVE_ANDROID
G_LOCK_DEFINE_STATIC (gum_modify_thread);
static volatile gboolean gum_modify_thread_did_load_cpu_context;
static volatile gboolean gum_modify_thread_did_modify_cpu_context;
static volatile gboolean gum_modify_thread_did_store_cpu_context;
static GumCpuContext gum_modify_thread_cpu_context;
#endif

gboolean
gum_process_is_debugger_attached (void)
{
  gboolean result;
  gchar * status, * p;
  gboolean success;

  success = g_file_get_contents ("/proc/self/status", &status, NULL, NULL);
  g_assert (success);

  p = strstr (status, "TracerPid:");
  g_assert (p != NULL);

  result = atoi (p + 10) != 0;

  g_free (status);

  return result;
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  return syscall (__NR_gettid);
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data)
{
  gboolean success = FALSE;
#ifndef HAVE_ANDROID
  struct sigaction action, old_action;

  if (thread_id == gum_process_get_current_thread_id ())
  {
    ucontext_t uc;
    volatile gboolean modified = FALSE;

    getcontext (&uc);
    if (!modified)
    {
      GumCpuContext cpu_context;

      gum_cpu_context_from_linux (&uc, &cpu_context);
      func (thread_id, &cpu_context, user_data);
      gum_cpu_context_to_linux (&cpu_context, &uc);

      modified = TRUE;
      setcontext (&uc);
    }

    success = TRUE;
  }
  else
  {
    G_LOCK (gum_modify_thread);

    gum_modify_thread_did_load_cpu_context = FALSE;
    gum_modify_thread_did_modify_cpu_context = FALSE;
    gum_modify_thread_did_store_cpu_context = FALSE;

    action.sa_sigaction = gum_do_modify_thread;
    sigemptyset (&action.sa_mask);
    action.sa_flags = SA_SIGINFO;
    sigaction (GUM_HIJACK_SIGNAL, &action, &old_action);

    if (syscall (SYS_tgkill, getpid (), thread_id, GUM_HIJACK_SIGNAL) == 0)
    {
      /* FIXME: timeout? */
      while (!gum_modify_thread_did_load_cpu_context)
        g_thread_yield ();
      func (thread_id, &gum_modify_thread_cpu_context, user_data);
      gum_modify_thread_did_modify_cpu_context = TRUE;
      while (!gum_modify_thread_did_store_cpu_context)
        g_thread_yield ();

      success = TRUE;
    }

    sigaction (GUM_HIJACK_SIGNAL, &old_action, NULL);

    G_UNLOCK (gum_modify_thread);
  }
#endif

  return success;
}

#ifndef HAVE_ANDROID
static void
gum_do_modify_thread (int sig,
                      siginfo_t * siginfo,
                      void * context)
{
  ucontext_t * uc = (ucontext_t *) context;

  gum_cpu_context_from_linux (uc, &gum_modify_thread_cpu_context);
  gum_modify_thread_did_load_cpu_context = TRUE;
  while (!gum_modify_thread_did_modify_cpu_context)
    ;
  gum_cpu_context_to_linux (&gum_modify_thread_cpu_context, uc);
  gum_modify_thread_did_store_cpu_context = TRUE;
}
#endif

void
gum_process_enumerate_threads (GumFoundThreadFunc func,
                               gpointer user_data)
{
#ifndef HAVE_ANDROID
  GDir * dir;
  const gchar * name;
  gboolean carry_on = TRUE;

  dir = g_dir_open ("/proc/self/task", 0, NULL);
  g_assert (dir != NULL);

  while (carry_on && (name = g_dir_read_name (dir)) != NULL)
  {
    gchar * path, * info = NULL;

    path = g_strconcat ("/proc/self/task/", name, "/stat", NULL);
    if (g_file_get_contents (path, &info, NULL, NULL))
    {
      gchar * state;
      GumThreadDetails details;

      state = strrchr (info, ')') + 2;

      details.id = atoi (name);
      details.state = gum_thread_state_from_proc_status_character (*state);
      if (gum_process_modify_thread (details.id, gum_store_cpu_context,
            &details.cpu_context))
      {
        carry_on = func (&details, user_data);
      }
    }

    g_free (info);
    g_free (path);
  }

  g_dir_close (dir);
#endif
}

#ifndef HAVE_ANDROID
static void
gum_store_cpu_context (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  memcpy (user_data, cpu_context, sizeof (GumCpuContext));
}
#endif

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  FILE * fp;
  const guint line_size = GUM_MAPS_LINE_SIZE;
  gchar * line, * path, * prev_path;
  gboolean carry_on = TRUE;

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  line = g_malloc (line_size);

  path = g_malloc (PATH_MAX);
  prev_path = g_malloc (PATH_MAX);
  prev_path[0] = '\0';

  while (carry_on && fgets (line, line_size, fp) != NULL)
  {
    const guint8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };
    guint8 * start, * end;
    gchar perms[5] = { 0, };
    gint n;
    gboolean readable, shared;
    gchar * name;
    GumMemoryRange range;
    GumModuleDetails details;

    n = sscanf (line, "%p-%p %4c %*x %*s %*s %s", &start, &end, perms, path);
    if (n == 3)
      continue;
    g_assert_cmpint (n, ==, 4);

    readable = perms[0] == 'r';
    shared = perms[3] == 's';
    if (!readable || shared)
      continue;
    else if (strcmp (path, prev_path) == 0)
      continue;
    else if (path[0] != '/' || g_str_has_prefix (path, "/dev/"))
      continue;
    else if (memcmp (start, elf_magic, sizeof (elf_magic)) != 0)
      continue;

    name = g_path_get_basename (path);

    range.base_address = GUM_ADDRESS (start);
    range.size = end - start;

    details.name = name;
    details.range = &range;
    details.path = path;

    carry_on = func (&details, user_data);

    g_free (name);

    strcpy (prev_path, path);
  }

  g_free (path);
  g_free (prev_path);

  g_free (line);

  fclose (fp);
}

void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  gum_linux_enumerate_ranges (getpid (), prot, func, user_data);
}

void
gum_linux_enumerate_ranges (pid_t pid,
                            GumPageProtection prot,
                            GumFoundRangeFunc func,
                            gpointer user_data)
{
  gchar * maps_path;
  FILE * fp;
  const guint line_size = GUM_MAPS_LINE_SIZE;
  gchar * line;
  gboolean carry_on = TRUE;

  maps_path = g_strdup_printf ("/proc/%d/maps", pid);

  fp = fopen (maps_path, "r");
  g_assert (fp != NULL);

  g_free (maps_path);

  line = g_malloc (line_size);

  while (carry_on && fgets (line, line_size, fp) != NULL)
  {
    GumRangeDetails details;
    GumMemoryRange range;
    GumFileMapping file;
    GumAddress end;
    gchar perms[5] = { 0, };
    guint64 inode;
    gint length, n;

    n = sscanf (line,
        "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x "
        "%4c "
        "%" G_GINT64_MODIFIER "x %*s %" G_GINT64_MODIFIER "d"
        "%n",
        &range.base_address, &end,
        perms,
        &file.offset, &inode,
        &length);
    g_assert (n == 5 || n == 6);

    range.size = end - range.base_address;

    details.file = NULL;
    if (inode != 0)
    {
      file.path = strchr (line + length, '/');
      if (file.path != NULL)
      {
        *strchr (file.path, '\n') = '\0';
        details.file = &file;
      }
    }

    details.range = &range;
    details.prot = gum_page_protection_from_proc_perms_string (perms);

    if ((details.prot & prot) == prot)
    {
      carry_on = func (&details, user_data);
    }
  }

  g_free (line);

  fclose (fp);
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  /* Not implemented */
}

void
gum_module_enumerate_imports (const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  GumElfModule module;
  GumEnumerateImportsContext ctx;

  if (!gum_elf_module_open (&module, module_name))
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.dependency_exports = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, g_free);

  gum_elf_module_enumerate_dependencies (&module,
      gum_collect_dependency_exports, &ctx);

  gum_elf_module_enumerate_imports (&module, gum_emit_import, &ctx);

  g_hash_table_unref (ctx.dependency_exports);

  gum_elf_module_close (&module);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumImportDetails d;

  d.type = details->type;
  d.name = details->name;
  d.module = g_hash_table_lookup (ctx->dependency_exports, details->name);
  d.address = 0;

  return ctx->func (&d, ctx->user_data);
}

static gboolean
gum_collect_dependency_exports (const GumElfDependencyDetails * details,
                                gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumElfModule module;

  if (!gum_elf_module_open (&module, details->name))
    return TRUE;
  ctx->current_dependency = &module;
  gum_elf_module_enumerate_exports (&module, gum_collect_dependency_export,
      ctx);
  ctx->current_dependency = NULL;
  gum_elf_module_close (&module);

  return TRUE;
}

static gboolean
gum_collect_dependency_export (const GumExportDetails * details,
                               gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumElfModule * module = ctx->current_dependency;

  g_hash_table_insert (ctx->dependency_exports, g_strdup (details->name),
      g_strdup (module->path));

  return TRUE;
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GumElfModule module;

  if (!gum_elf_module_open (&module, module_name))
    return;
  gum_elf_module_enumerate_exports (&module, func, user_data);
  gum_elf_module_close (&module);
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  GumEnumerateModuleRangesContext ctx;

  ctx.module_name = module_name;
  ctx.func = func;
  ctx.user_data = user_data;

  gum_process_enumerate_ranges (prot, gum_emit_range_if_module_name_matches,
      &ctx);
}

static gboolean
gum_emit_range_if_module_name_matches (const GumRangeDetails * details,
                                       gpointer user_data)
{
  GumEnumerateModuleRangesContext * ctx = user_data;

  if (details->file == NULL)
    return TRUE;
  else if (!gum_module_path_equals (details->file->path, ctx->module_name))
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  GumFindModuleContext ctx = { module_name, 0, NULL };
  gum_process_enumerate_modules (gum_store_base_and_path_if_name_matches, &ctx);
  g_free (ctx.path);
  return ctx.base;
}

static gboolean
gum_store_base_and_path_if_name_matches (const GumModuleDetails * details,
                                         gpointer user_data)
{
  GumFindModuleContext * ctx = user_data;

  if (!gum_module_path_equals (details->path, ctx->module_name))
    return TRUE;

  ctx->base = details->range->base_address;
  ctx->path = g_strdup (details->path);
  return FALSE;
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumFindExportContext ctx;

  ctx.result = 0;
  ctx.symbol_name = symbol_name;

  if (module_name == NULL)
  {
    gum_process_enumerate_modules (gum_store_address_if_module_has_export,
        &ctx);
  }
  else
  {
    gum_module_enumerate_exports (module_name,
        gum_store_address_if_export_name_matches, &ctx);
  }

  return ctx.result;
}

static gboolean
gum_store_address_if_module_has_export (const GumModuleDetails * details,
                                        gpointer user_data)
{
  GumFindExportContext * ctx = user_data;

  gum_module_enumerate_exports (details->path,
      gum_store_address_if_export_name_matches, &ctx);

  return ctx->result == 0;
}

static gboolean
gum_store_address_if_export_name_matches (const GumExportDetails * details,
                                          gpointer user_data)
{
  GumFindExportContext * ctx = user_data;

  if (strcmp (details->name, ctx->symbol_name) == 0)
  {
    ctx->result = details->address;
    return FALSE;
  }

  return TRUE;
}

GumCpuType
gum_linux_cpu_type_from_file (const gchar * path,
                              GError ** error)
{
  GumCpuType result = -1;
  GFile * file;
  GFileInputStream * base_stream;
  GDataInputStream * stream = NULL;
  GError * read_error;
  guint16 e_machine;

  file = g_file_new_for_path (path);

  base_stream = g_file_read (file, NULL, error);
  if (base_stream == NULL)
    goto beach;

  if (!g_seekable_seek (G_SEEKABLE (base_stream), 0x12, G_SEEK_SET, NULL,
      error))
    goto beach;

  stream = g_data_input_stream_new (G_INPUT_STREAM (base_stream));
  g_data_input_stream_set_byte_order (stream,
      G_DATA_STREAM_BYTE_ORDER_LITTLE_ENDIAN);

  read_error = NULL;
  e_machine = g_data_input_stream_read_uint16 (stream, NULL, &read_error);
  if (read_error != NULL)
  {
    g_propagate_error (error, read_error);
    goto beach;
  }

  switch (e_machine)
  {
    case 0x0003:
      result = GUM_CPU_IA32;
      break;
    case 0x003e:
      result = GUM_CPU_AMD64;
      break;
    case 0x0028:
      result = GUM_CPU_ARM;
      break;
    case 0x00b7:
      result = GUM_CPU_ARM64;
      break;
    default:
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
          "Unsupported executable");
      break;
  }

beach:
  if (stream != NULL)
    g_object_unref (stream);

  if (base_stream != NULL)
    g_object_unref (base_stream);

  g_object_unref (file);

  return result;
}

GumCpuType
gum_linux_cpu_type_from_pid (pid_t pid,
                             GError ** error)
{
  GumCpuType result = -1;
  gchar * auxv_path;
  guint8 * auxv;
  gsize auxv_size, i;

  auxv_path = g_strdup_printf ("/proc/%d/auxv", pid);

  if (!g_file_get_contents (auxv_path, (gchar **) &auxv, &auxv_size, error))
    goto beach;

#ifdef HAVE_I386
  result = GUM_CPU_AMD64;
#else
  result = GUM_CPU_ARM64;
#endif

  for (i = 0; i < auxv_size; i += 16)
  {
    if (auxv[4] != 0 || auxv[5] != 0 ||
        auxv[6] != 0 || auxv[7] != 0)
    {
#ifdef HAVE_I386
      result = GUM_CPU_IA32;
#else
      result = GUM_CPU_ARM;
#endif
      break;
    }
  }

beach:
  g_free (auxv_path);

  return result;
}

static gboolean
gum_module_path_equals (const gchar * path,
                        const gchar * name_or_path)
{
  gchar * s;

  if (name_or_path[0] == '/')
    return strcmp (name_or_path, path) == 0;

  if ((s = strrchr (path, '/')) != NULL)
    return strcmp (name_or_path, s + 1) == 0;

  return strcmp (name_or_path, path) == 0;
}

static gboolean
gum_elf_module_open (GumElfModule * module,
                     const gchar * module_name)
{
  gboolean success = FALSE;
  GumFindModuleContext m = { module_name, 0, NULL };

  module->path = NULL;
  module->fd = -1;
  module->file_size = 0;
  module->data = NULL;
  module->ehdr = NULL;
  module->address = NULL;

  gum_process_enumerate_modules (gum_store_base_and_path_if_name_matches, &m);
  if (m.base == 0)
    goto beach;
  module->path = m.path;
  module->address = GSIZE_TO_POINTER (m.base);

  module->fd = open (module->path, O_RDONLY);
  if (module->fd == -1)
    goto beach;

  module->file_size = lseek (module->fd, 0, SEEK_END);
  lseek (module->fd, 0, SEEK_SET);

  module->data = mmap (NULL, module->file_size, PROT_READ, MAP_PRIVATE,
      module->fd, 0);
  g_assert (module->data != MAP_FAILED);

  module->ehdr = module->data;
  if (module->ehdr->e_type != ET_DYN)
    goto beach;
  success = TRUE;

beach:
  if (!success)
    gum_elf_module_close (module);

  return success;
}

static void
gum_elf_module_close (GumElfModule * module)
{
  if (module->data != NULL)
    munmap (module->data, module->file_size);

  if (module->fd != -1)
    close (module->fd);

  g_free (module->path);
}

static void
gum_elf_module_enumerate_dependencies (GumElfModule * self,
                                       GumElfFoundDependencyFunc func,
                                       gpointer user_data)
{
  gpointer data = self->data;
  GumElfEHeader * ehdr = self->ehdr;
  GumElfSHeader * dyn, * strtab_header;
  const gchar * strtab;
  gboolean carry_on;
  guint i;

  dyn = gum_elf_module_find_section_header (self, SHT_DYNAMIC);
  if (dyn == NULL)
    return;
  strtab_header = data + ehdr->e_shoff + (dyn->sh_link * ehdr->e_shentsize);
  strtab = data + strtab_header->sh_offset;

  carry_on = TRUE;
  for (i = 0; i != dyn->sh_size / dyn->sh_entsize && carry_on; i++)
  {
    GumElfDynamic * entry;

    entry = data + dyn->sh_offset + (i * dyn->sh_entsize);
    if (entry->d_tag == DT_NEEDED)
    {
      GumElfDependencyDetails details;

      details.name = strtab + entry->d_un.d_val;
      carry_on = func (&details, user_data);
    }
  }
}

static void
gum_elf_module_enumerate_imports (GumElfModule * self,
                                  GumFoundImportFunc func,
                                  gpointer user_data)
{
  GumElfEnumerateImportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_dynamic_symbols (self, gum_emit_elf_import, &ctx);
}

static gboolean
gum_emit_elf_import (const GumElfSymbolDetails * details,
                     gpointer user_data)
{
  GumElfEnumerateImportsContext * ctx = user_data;

  if (details->section_header_index == SHN_UNDEF &&
      (details->type == STT_FUNC || details->type == STT_OBJECT))
  {
    GumImportDetails d;

    d.type = (details->type == STT_FUNC)
        ? GUM_EXPORT_FUNCTION
        : GUM_EXPORT_VARIABLE;
    d.name = details->name;
    d.module = NULL;
    d.address = 0;

    if (!ctx->func (&d, ctx->user_data))
      return FALSE;
  }

  return TRUE;
}

static void
gum_elf_module_enumerate_exports (GumElfModule * self,
                                  GumFoundExportFunc func,
                                  gpointer user_data)
{
  GumElfEnumerateExportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_dynamic_symbols (self, gum_emit_elf_export, &ctx);
}

static gboolean
gum_emit_elf_export (const GumElfSymbolDetails * details,
                     gpointer user_data)
{
  GumElfEnumerateExportsContext * ctx = user_data;

  if (details->section_header_index != SHN_UNDEF &&
      (details->type == STT_FUNC || details->type == STT_OBJECT) &&
      (details->bind == STB_GLOBAL || details->bind == STB_WEAK))
  {
    GumExportDetails d;

    d.type = (details->type == STT_FUNC)
        ? GUM_EXPORT_FUNCTION
        : GUM_EXPORT_VARIABLE;
    d.name = details->name;
    d.address = details->address;

    if (!ctx->func (&d, ctx->user_data))
      return FALSE;
  }

  return TRUE;
}

static void
gum_elf_module_enumerate_dynamic_symbols (GumElfModule * self,
                                          GumElfFoundSymbolFunc func,
                                          gpointer user_data)
{
  gpointer data = self->data;
  GumElfEHeader * ehdr = self->ehdr;
  GumElfSHeader * dynsym, * strtab_header;
  const gchar * strtab;
  gboolean carry_on;
  guint i;

  dynsym = gum_elf_module_find_section_header (self, SHT_DYNSYM);
  if (dynsym == NULL)
    return;
  strtab_header = data + ehdr->e_shoff + (dynsym->sh_link * ehdr->e_shentsize);
  strtab = data + strtab_header->sh_offset;

  carry_on = TRUE;
  for (i = 0; i != dynsym->sh_size / dynsym->sh_entsize && carry_on; i++)
  {
    GumElfSymbol * sym;
    GumElfSymbolDetails details;

    sym = data + dynsym->sh_offset + (i * dynsym->sh_entsize);

    details.name = strtab + sym->st_name;
    details.address = GUM_ADDRESS (self->address + sym->st_value);
    details.type = GUM_ELF_ST_TYPE (sym->st_info);
    details.bind = GUM_ELF_ST_BIND (sym->st_info);
    details.section_header_index = sym->st_shndx;

    carry_on = func (&details, user_data);
  }
}

static GumElfSHeader *
gum_elf_module_find_section_header (GumElfModule * self,
                                    GumElfSHeaderType type)
{
  GumElfEHeader * ehdr = self->ehdr;
  guint i;

  for (i = 0; i != ehdr->e_shnum; i++)
  {
    GumElfSHeader * shdr;

    shdr = self->data + ehdr->e_shoff + (i * ehdr->e_shentsize);
    if (shdr->sh_type == type)
      return shdr;
  }

  return NULL;
}

#ifndef HAVE_ANDROID

static void
gum_cpu_context_from_linux (const ucontext_t * uc,
                            GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  const greg_t * gr = uc->uc_mcontext.gregs;

  ctx->eip = gr[REG_EIP];

  ctx->edi = gr[REG_EDI];
  ctx->esi = gr[REG_ESI];
  ctx->ebp = gr[REG_EBP];
  ctx->esp = gr[REG_ESP];
  ctx->ebx = gr[REG_EBX];
  ctx->edx = gr[REG_EDX];
  ctx->ecx = gr[REG_ECX];
  ctx->eax = gr[REG_EAX];
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  const greg_t * gr = uc->uc_mcontext.gregs;

  ctx->rip = gr[REG_RIP];

  ctx->r15 = gr[REG_R15];
  ctx->r14 = gr[REG_R14];
  ctx->r13 = gr[REG_R13];
  ctx->r12 = gr[REG_R12];
  ctx->r11 = gr[REG_R11];
  ctx->r10 = gr[REG_R10];
  ctx->r9 = gr[REG_R9];
  ctx->r8 = gr[REG_R8];

  ctx->rdi = gr[REG_RDI];
  ctx->rsi = gr[REG_RSI];
  ctx->rbp = gr[REG_RBP];
  ctx->rsp = gr[REG_RSP];
  ctx->rbx = gr[REG_RBX];
  ctx->rdx = gr[REG_RDX];
  ctx->rcx = gr[REG_RCX];
  ctx->rax = gr[REG_RAX];
#else
# error FIXME
#endif
}

static void
gum_cpu_context_to_linux (const GumCpuContext * ctx,
                          ucontext_t * uc)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  greg_t * gr = uc->uc_mcontext.gregs;

  gr[REG_EIP] = ctx->eip;

  gr[REG_EDI] = ctx->edi;
  gr[REG_ESI] = ctx->esi;
  gr[REG_EBP] = ctx->ebp;
  gr[REG_ESP] = ctx->esp;
  gr[REG_EBX] = ctx->ebx;
  gr[REG_EDX] = ctx->edx;
  gr[REG_ECX] = ctx->ecx;
  gr[REG_EAX] = ctx->eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  greg_t * gr = uc->uc_mcontext.gregs;

  gr[REG_RIP] = ctx->rip;

  gr[REG_R15] = ctx->r15;
  gr[REG_R14] = ctx->r14;
  gr[REG_R13] = ctx->r13;
  gr[REG_R12] = ctx->r12;
  gr[REG_R11] = ctx->r11;
  gr[REG_R10] = ctx->r10;
  gr[REG_R9] = ctx->r9;
  gr[REG_R8] = ctx->r8;

  gr[REG_RDI] = ctx->rdi;
  gr[REG_RSI] = ctx->rsi;
  gr[REG_RBP] = ctx->rbp;
  gr[REG_RSP] = ctx->rsp;
  gr[REG_RBX] = ctx->rbx;
  gr[REG_RDX] = ctx->rdx;
  gr[REG_RCX] = ctx->rcx;
  gr[REG_RAX] = ctx->rax;
#else
# error FIXME
#endif
}

static GumThreadState
gum_thread_state_from_proc_status_character (gchar c)
{
  switch (g_ascii_toupper (c))
  {
    case 'R': return GUM_THREAD_RUNNING;
    case 'S': return GUM_THREAD_WAITING;
    case 'D': return GUM_THREAD_UNINTERRUPTIBLE;
    case 'Z': return GUM_THREAD_UNINTERRUPTIBLE;
    case 'T': return GUM_THREAD_STOPPED;
    case 'W': return GUM_THREAD_UNINTERRUPTIBLE;
    default:
      g_assert_not_reached ();
      break;
  }
}

#endif /* !HAVE_ANDROID */

static GumPageProtection
gum_page_protection_from_proc_perms_string (const gchar * perms)
{
  GumPageProtection prot = GUM_PAGE_NO_ACCESS;

  if (perms[0] == 'r')
    prot |= GUM_PAGE_READ;
  if (perms[1] == 'w')
    prot |= GUM_PAGE_WRITE;
  if (perms[2] == 'x')
    prot |= GUM_PAGE_EXECUTE;

  return prot;
}
