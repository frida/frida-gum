/*
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gum-init.h"
#include "gumqnx.h"
#include "gumqnx-priv.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/elf.h>
#include <sys/elf_dyn.h>
#include <sys/link.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <sys/states.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#define GUM_PSR_THUMB 0x20

#define GUM_HIJACK_SIGNAL (SIGRTMIN + 7)

typedef Elf32_Ehdr GumElfEHeader;
typedef Elf32_Shdr GumElfSHeader;
typedef Elf32_Phdr GumElfPHeader;
typedef Elf32_Sym GumElfSymbol;
typedef Elf32_Dyn GumElfDynEntry;
# define GUM_ELF_ST_BIND(val) ELF32_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF32_ST_TYPE(val)

typedef struct _GumFindModuleContext GumFindModuleContext;
typedef struct _GumEnumerateModuleRangesContext GumEnumerateModuleRangesContext;
typedef struct _GumResolveModuleNameContext GumResolveModuleNameContext;
typedef struct _GumDlPhdrInternal GumDlPhdrInternal;

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

struct _GumResolveModuleNameContext
{
  gchar * name;
  gchar * path;
  GumAddress base;
};

struct _GumDlPhdrInternal
{
  GumDlPhdrInternal * p_next;
  gint unknown;
  Link_map * linkmap;
};

static gchar * gum_try_init_libc_name (void);
static void gum_deinit_libc_name (void);

static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static gboolean gum_emit_range_if_module_name_matches (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_store_base_and_path_if_name_matches (
    const GumModuleDetails * details, gpointer user_data);

static gchar * gum_resolve_module_name (const gchar * name, GumAddress * base);
static gboolean gum_store_module_path_and_base_if_name_matches (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_module_path_equals (const gchar * path,
    const gchar * name_or_path);

static void gum_cpu_context_from_qnx (const debug_greg_t * gregs,
    GumCpuContext * ctx);
static void gum_cpu_context_to_qnx (const GumCpuContext * ctx,
    debug_greg_t * gregs);

static GumThreadState gum_thread_state_from_system_thread_state (int state);

static gchar * gum_libc_name;

const gchar *
gum_process_query_libc_name (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_try_init_libc_name, NULL);

  if (once.retval == NULL)
    gum_panic ("Unable to locate the libc; please file a bug");

  return once.retval;
}

static gchar *
gum_try_init_libc_name (void)
{
  Dl_info info = { NULL, };

  dladdr (dlsym (RTLD_NEXT, "__libc_start_main"), &info);

  if (info.dli_fname == NULL)
  {
    dladdr (dlsym (RTLD_NEXT, "exit"), &info);
    if (info.dli_fname == NULL)
      return NULL;
  }

  gum_libc_name = g_strdup (info.dli_fname);

  if (g_file_test (gum_libc_name, G_FILE_TEST_IS_SYMLINK))
  {
    gchar * parent_dir, * target, * canonical_name;

    parent_dir = g_path_get_dirname (gum_libc_name);
    target = g_file_read_link (gum_libc_name, NULL);

    canonical_name = g_canonicalize_filename (target, parent_dir);

    g_free (target);
    g_free (parent_dir);

    g_free (gum_libc_name);
    gum_libc_name = canonical_name;
  }

  _gum_register_destructor (gum_deinit_libc_name);

  return gum_libc_name;
}

static void
gum_deinit_libc_name (void)
{
  g_free (gum_libc_name);
}

gboolean
gum_process_is_debugger_attached (void)
{
  g_assert_not_reached ();
}

GumProcessId
gum_process_get_id (void)
{
  return getpid ();
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  return gettid ();
}

gboolean
gum_process_has_thread (GumThreadId thread_id)
{
  /* FIXME */
  return TRUE;
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data)
{
  gboolean success = FALSE;

  ThreadCtl (_NTO_TCTL_ONE_THREAD_HOLD, (void *) thread_id);
  if (vfork () == 0)
  {
    gchar as_path[PATH_MAX];
    int fd, res;
    procfs_greg gregs;
    GumCpuContext cpu_context;

    sprintf (as_path, "/proc/%d/as", getppid ());

    fd = open (as_path, O_RDWR);
    g_assert (fd != -1);

    res = devctl (fd, DCMD_PROC_CURTHREAD, &thread_id, sizeof (thread_id),
        NULL);
    g_assert (res == 0);

    res = devctl (fd, DCMD_PROC_GETGREG, &gregs, sizeof (gregs), NULL);
    g_assert (res == 0);

    gum_cpu_context_from_qnx (&gregs, &cpu_context);
    func (thread_id, &cpu_context, user_data);
    gum_cpu_context_to_qnx (&cpu_context, &gregs);

    res = devctl (fd, DCMD_PROC_SETGREG, &gregs, sizeof (gregs), NULL);
    g_assert (res == 0);

    close (fd);
    _exit (0);
  }
  ThreadCtl (_NTO_TCTL_ONE_THREAD_CONT, (void *) thread_id);

  success = TRUE;

  return success;
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  gint fd, res;
  debug_process_t info;
  debug_thread_t thread;
  gboolean carry_on = TRUE;

  fd = open ("/proc/self/as", O_RDONLY);
  g_assert (fd != -1);

  res = devctl (fd, DCMD_PROC_INFO, &info, sizeof (info), NULL);
  g_assert (res == 0);

  thread.tid = 1;
  while (carry_on &&
      (devctl (fd, DCMD_PROC_TIDSTATUS, &thread, sizeof (thread), NULL) == 0))
  {
    GumThreadDetails details;

    details.id = thread.tid;
    details.state = gum_thread_state_from_system_thread_state (thread.state);

    if (thread.state != STATE_DEAD &&
        gum_process_modify_thread (details.id, gum_store_cpu_context,
          &details.cpu_context))
    {
      carry_on = func (&details, user_data);
    }

    thread.tid++;
  }

  close (fd);
}

static void
gum_store_cpu_context (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  memcpy (user_data, cpu_context, sizeof (GumCpuContext));
}

void
gum_qnx_enumerate_ranges (pid_t pid,
                          GumPageProtection prot,
                          GumFoundRangeFunc func,
                          gpointer user_data)
{
  gchar * as_path;
  gint fd, res;
  gboolean carry_on = TRUE;
  procfs_mapinfo * mapinfos;
  gint num_mapinfos;
  procfs_debuginfo * debuginfo;
  gint i;

  as_path = g_strdup_printf ("/proc/%d/as", pid);
  fd = open (as_path, O_RDONLY);
  g_assert (fd != -1);
  g_free (as_path);

  res = devctl (fd, DCMD_PROC_PAGEDATA, 0, 0, &num_mapinfos);
  g_assert (res == 0);

  mapinfos = g_malloc (num_mapinfos * sizeof (procfs_mapinfo));
  debuginfo = g_malloc (sizeof (procfs_debuginfo) + 0x100);

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfos,
      num_mapinfos * sizeof (procfs_mapinfo), &num_mapinfos);
  g_assert (res == 0);

  for (i = 0; carry_on && i != num_mapinfos; i++)
  {
    GumRangeDetails details;
    GumMemoryRange range;
    GumFileMapping file;

    details.range = &range;
    details.file = &file;
    details.protection = _gum_page_protection_from_posix (mapinfos[i].flags);

    range.base_address = mapinfos[i].vaddr;
    range.size = mapinfos[i].size;

    debuginfo->vaddr = mapinfos[i].vaddr;
    res = devctl (fd, DCMD_PROC_MAPDEBUG, debuginfo,
        sizeof (procfs_debuginfo) + 0x100, NULL);
    g_assert (res == 0);
    file.path = debuginfo->path;
    file.offset = 0; /* TODO */
    file.size = 0; /* TODO */

    if ((details.protection & prot) == prot)
    {
      carry_on = func (&details, user_data);
    }
  }

  g_free (debuginfo);
  g_free (mapinfos);

  close (fd);
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
                               GumFoundRangeFunc func,
                               gpointer user_data)
{
  gum_qnx_enumerate_ranges (getpid (), prot, func, user_data);
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  /* Not implemented */
  g_assert_not_reached ();
}

guint
gum_thread_try_get_ranges (GumMemoryRange * ranges,
                           guint max_length)
{
  /* Not implemented */
  return 0;
}

gint
gum_thread_get_system_error (void)
{
  return errno;
}

void
gum_thread_set_system_error (gint value)
{
  errno = value;
}

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  gint fd, res;
  gboolean carry_on = TRUE;
  procfs_mapinfo * mapinfos;
  gint num_mapinfos;
  gint i;
  GumDlPhdrInternal ** handle;
  GumDlPhdrInternal * phdr;

  fd = open ("/proc/self/as", O_RDONLY);
  g_assert (fd != -1);

  res = devctl (fd, DCMD_PROC_PAGEDATA, 0, 0, &num_mapinfos);
  g_assert (res == 0);

  if (num_mapinfos == 0)
    return;

  mapinfos = g_malloc (sizeof (procfs_mapinfo) * num_mapinfos);

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfos,
      num_mapinfos * sizeof (procfs_mapinfo), &num_mapinfos);
  g_assert (res == 0);

  handle = dlopen (NULL, RTLD_NOW);

  for (i = 0; carry_on && i != num_mapinfos; i++)
  {
    GumModuleDetails details;
    GumMemoryRange range;

    details.range = &range;
    details.path = NULL;

    range.base_address = mapinfos[i].vaddr;
    range.size = mapinfos[i].size;

    for (phdr = *handle;
         phdr != NULL && phdr->linkmap != NULL;
         phdr = phdr->p_next)
    {
      Link_map * linkmap = phdr->linkmap;
      if (linkmap->l_addr == range.base_address)
      {
        if (linkmap->l_path != NULL)
          details.path = linkmap->l_path;
        break;
      }
    }

    if (details.path != NULL)
    {
      gchar * name;

      name = g_path_get_basename (details.path);
      details.name = name;

      carry_on = func (&details, user_data);

      g_free (name);
    }
  }

  g_free (mapinfos);
  close (fd);
}

gboolean
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  if (dlopen (module_name, RTLD_LAZY) == NULL)
    goto not_found;

  return TRUE;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

gboolean
gum_module_ensure_initialized (const gchar * module_name)
{
  gboolean success;
  gchar * name;
  void * module;

  success = FALSE;

  name = gum_resolve_module_name (module_name, NULL);
  if (name == NULL)
    goto beach;

  module = dlopen (name, RTLD_LAZY);
  if (module == NULL)
    goto beach;
  dlclose (module);

  success = TRUE;

beach:
  g_free (name);

  return success;
}

void
gum_module_enumerate_imports (const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  /* Not implemented */
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GumFindModuleContext ctx = { module_name, 0, NULL };
  gint fd = -1;
  gsize file_size;
  gpointer base_address = NULL;
  GumElfEHeader * ehdr;
  guint i;
  gsize dynsym_section_offset = 0, dynsym_section_size = 0;
  gsize dynsym_entry_size = 0;
  const gchar * dynsym_strtab = NULL;

  gum_process_enumerate_modules (gum_store_base_and_path_if_name_matches, &ctx);
  if (ctx.base == 0)
    goto beach;

  fd = open (ctx.path, O_RDONLY);
  if (fd == -1)
    goto beach;

  file_size = lseek (fd, 0, SEEK_END);
  lseek (fd, 0, SEEK_SET);

  base_address = mmap (NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  g_assert (base_address != MAP_FAILED);

  ehdr = base_address;
  if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC)
    goto beach;

  for (i = 0; i != ehdr->e_phnum; i++)
  {
    GumElfPHeader * phdr;

    phdr = base_address + ehdr->e_phoff + (i * ehdr->e_phentsize);
    if (phdr->p_type == PT_DYNAMIC)
    {
      guint num_symbols, dyn_symentsize;
      GumElfDynEntry * dyn_entry;

      num_symbols = 0;
      dyn_symentsize = 0;

      for (dyn_entry = base_address + phdr->p_offset;
           dyn_entry < (GumElfDynEntry *) (base_address +
               phdr->p_offset + phdr->p_filesz);
           dyn_entry++)
      {
        switch (dyn_entry->d_tag)
        {
          case DT_STRTAB:
            dynsym_strtab = (ehdr->e_type == ET_EXEC ? 0 : base_address)
                + dyn_entry->d_un.d_ptr;
            break;
          case DT_SYMTAB:
            dynsym_section_offset = dyn_entry->d_un.d_ptr;
            break;
          case DT_GNU_HASH:
          {
            guint * dyn_gnu_hash;
            guint nbuckets, symndx, bitmaskwords, buckets_vma;
            guint * gnu_buckets;
            guint maxchain, i;
            guint * dynamic_info, * gnu_chains;

            dyn_gnu_hash = (guint *) (
                (ehdr->e_type == ET_EXEC ? 0 : base_address)
                + dyn_entry->d_un.d_ptr);
            nbuckets = dyn_gnu_hash[0];
            symndx = dyn_gnu_hash[1];
            bitmaskwords = dyn_gnu_hash[2];
            buckets_vma = dyn_entry->d_un.d_ptr + 16 + bitmaskwords * 4;
            gnu_buckets = (guint *) (
                (ehdr->e_type == ET_EXEC ? 0 : base_address) + buckets_vma);
            maxchain = -1;

            for (i = 0; i != nbuckets; ++i)
            {
              if (gnu_buckets[i] != 0)
              {
                g_assert (gnu_buckets[i] >= symndx);

                if (maxchain == 0xffffffff || gnu_buckets[i] > maxchain)
                  maxchain = gnu_buckets[i];
              }
            }

            maxchain -= symndx;
            dynamic_info = (guint *) (
                (ehdr->e_type == ET_EXEC ? 0 : base_address) + buckets_vma +
                4 * (nbuckets + maxchain));
            i = 0;
            do
            {
              ++maxchain;
            }
            while ((dynamic_info[i++] & 1) == 0);

            gnu_chains = (guint *) (
                (ehdr->e_type == ET_EXEC ? 0 : base_address) + buckets_vma +
                (4 * nbuckets));
            num_symbols = symndx;

            for (i = 0; i != nbuckets; ++i)
            {
              if (gnu_buckets[i] != 0)
              {
                guint si = gnu_buckets[i];
                guint off = si - symndx;

                do
                {
                  si++;
                  num_symbols++;
                }
                while (off < maxchain && (gnu_chains[off++] & 1) == 0);
              }
            }
            break;
          }
          case DT_HASH:
          {
            guint * dyn_hash = (guint *) (
                (ehdr->e_type == ET_EXEC ? 0 : base_address) +
                dyn_entry->d_un.d_ptr);
            num_symbols = dyn_hash[1];
            break;
          }
          case DT_SYMENT:
            dyn_symentsize = dyn_entry->d_un.d_val;
            break;
        }
      }

      if (dynsym_strtab == 0 || dynsym_section_offset == 0)
        goto beach;

      dynsym_section_size = dyn_symentsize * num_symbols;
      dynsym_entry_size = dyn_symentsize;

      g_assert (dynsym_section_size % dynsym_entry_size == 0);
    }
  }

  if (dynsym_section_offset == 0)
    goto beach;

  for (i = 0; i != dynsym_section_size / dynsym_entry_size; i++)
  {
    GumElfSymbol * sym;

    sym = (ehdr->e_type == ET_EXEC ? 0 : base_address) +
        dynsym_section_offset + (i * dynsym_entry_size);
    if ((GUM_ELF_ST_BIND (sym->st_info) == STB_GLOBAL ||
         GUM_ELF_ST_BIND (sym->st_info) == STB_WEAK) &&
        sym->st_shndx != SHN_UNDEF)
    {
      GumExportDetails details;

      details.type = GUM_ELF_ST_TYPE (sym->st_info) == STT_FUNC
          ? GUM_EXPORT_FUNCTION
          : GUM_EXPORT_VARIABLE;
      details.name = dynsym_strtab + sym->st_name;
      details.address = ctx.base + sym->st_value;

      if (!func (&details, user_data))
        goto beach;
    }
  }

beach:
  if (base_address != NULL)
    munmap (base_address, file_size);

  if (fd != -1)
    close (fd);

  g_free (ctx.path);
}

void
gum_module_enumerate_symbols (const gchar * module_name,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  /* TODO: implement */
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

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  GumFindModuleContext ctx = { module_name, 0, NULL };
  gum_process_enumerate_modules (gum_store_base_and_path_if_name_matches, &ctx);
  g_free (ctx.path);
  return ctx.base;
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumAddress result;
  void * module;

  if (module_name != NULL)
  {
    gchar * name;

    name = gum_resolve_module_name (module_name, NULL);
    if (name == NULL)
      return 0;
    module = dlopen (name, RTLD_LAZY);
    g_free (name);

    if (module == NULL)
      return 0;
  }
  else
  {
    module = RTLD_DEFAULT;
  }

  result = GUM_ADDRESS (dlsym (module, symbol_name));

  if (module != RTLD_DEFAULT)
    dlclose (module);

  return result;
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

GumCpuType
gum_linux_cpu_type_from_file (const gchar * path,
                              GError ** error)
{
  GumCpuType result = -1;
  FILE * file;
  guint8 ei_data;
  guint16 e_machine;

  file = fopen (path, "rb");
  if (file == NULL)
    goto beach;

  if (fseek (file, EI_DATA, SEEK_SET) != 0)
    goto beach;
  if (fread (&ei_data, sizeof (ei_data), 1, file) != 1)
    goto beach;

  if (fseek (file, 0x12, SEEK_SET) != 0)
    goto beach;
  if (fread (&e_machine, sizeof (e_machine), 1, file) != 1)
    goto beach;

  if (ei_data == ELFDATA2LSB)
    e_machine = GUINT16_FROM_LE (e_machine);
  else if (ei_data == ELFDATA2MSB)
    e_machine = GUINT16_FROM_BE (e_machine);
  else
    goto unsupported_ei_data;

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
    case 0x0008:
      result = GUM_CPU_MIPS;
      break;
    default:
      goto unsupported_executable;
  }

  goto beach;

unsupported_ei_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "Unsupported ELF EI_DATA");
    goto beach;
  }
unsupported_executable:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "Unsupported executable");
    goto beach;
  }
beach:
  {
    if (file != NULL)
      fclose (file);

    return result;
  }
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

static gchar *
gum_resolve_module_name (const gchar * name,
                         GumAddress * base)
{
  GumResolveModuleNameContext ctx;
  struct link_map * map;

  map = dlopen (name, RTLD_LAZY | RTLD_NOLOAD);
  if (map != NULL)
  {
    ctx.name = g_file_read_link (map->l_name, NULL);
    if (ctx.name == NULL)
      ctx.name = g_strdup (map->l_name);
    dlclose (map);
  }
  else
  {
    ctx.name = g_strdup (name);
  }
  ctx.path = NULL;
  ctx.base = 0;

  gum_process_enumerate_modules (gum_store_module_path_and_base_if_name_matches,
      &ctx);

  g_free (ctx.name);

  if (base != NULL)
    *base = ctx.base;

  return ctx.path;
}

static gboolean
gum_store_module_path_and_base_if_name_matches (
    const GumModuleDetails * details,
    gpointer user_data)
{
  GumResolveModuleNameContext * ctx = user_data;

  if (gum_module_path_equals (details->path, ctx->name))
  {
    ctx->path = g_strdup (details->path);
    ctx->base = details->range->base_address;
    return FALSE;
  }

  return TRUE;
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

static void
gum_cpu_context_from_qnx (const debug_greg_t * gregs,
                          GumCpuContext * ctx)
{
#if defined (HAVE_I386)
  const X86_CPU_REGISTERS * regs = &gregs->x86;

  ctx->eip = regs->eip;

  ctx->edi = regs->edi;
  ctx->esi = regs->esi;
  ctx->ebp = regs->ebp;
  ctx->esp = regs->esp;
  ctx->ebx = regs->ebx;
  ctx->edx = regs->edx;
  ctx->ecx = regs->ecx;
  ctx->eax = regs->eax;
#elif defined (HAVE_ARM)
  const ARM_CPU_REGISTERS * regs = &gregs->arm;

  ctx->pc = regs->gpr[ARM_REG_R15];
  ctx->sp = regs->gpr[ARM_REG_R13];

  memcpy (ctx->r, regs->gpr, sizeof (ctx->r));

  ctx->lr = regs->gpr[ARM_REG_R14];
#else
# error Fix this for other architectures
#endif
}

static void
gum_cpu_context_to_qnx (const GumCpuContext * ctx,
                        debug_greg_t * gregs)
{
#if defined (HAVE_I386)
  X86_CPU_REGISTERS * regs = &gregs->x86;

  regs->eip = ctx->eip;

  regs->edi = ctx->edi;
  regs->esi = ctx->esi;
  regs->ebp = ctx->ebp;
  regs->esp = ctx->esp;
  regs->ebx = ctx->ebx;
  regs->edx = ctx->edx;
  regs->ecx = ctx->ecx;
  regs->eax = ctx->eax;
#elif defined (HAVE_ARM)
  ARM_CPU_REGISTERS * regs = &gregs->arm;

  regs->gpr[ARM_REG_R15] = ctx->pc;
  regs->gpr[ARM_REG_R13] = ctx->sp;

  memcpy (regs->gpr, ctx->r, sizeof (ctx->r));

  regs->gpr[ARM_REG_R14] = ctx->lr;
#else
# error Fix this for other architectures
#endif
}

static GumThreadState
gum_thread_state_from_system_thread_state (gint state)
{
  switch (state)
  {
    case STATE_RUNNING:
      return GUM_THREAD_RUNNING;
    case STATE_CONDVAR:
    case STATE_INTR:
    case STATE_JOIN:
    case STATE_MUTEX:
    case STATE_NET_REPLY:
    case STATE_NET_SEND:
    case STATE_READY:
    case STATE_RECEIVE:
    case STATE_REPLY:
    case STATE_NANOSLEEP:
    case STATE_SEM:
    case STATE_SEND:
    case STATE_SIGSUSPEND:
    case STATE_SIGWAITINFO:
    case STATE_STACK:
    case STATE_WAITCTX:
    case STATE_WAITPAGE:
    case STATE_WAITTHREAD:
      return GUM_THREAD_WAITING;
    case STATE_STOPPED:
      return GUM_THREAD_STOPPED;
    case STATE_DEAD:
      return GUM_THREAD_HALTED;
    default:
      g_assert_not_reached ();
      break;
  }
}

void
gum_qnx_parse_ucontext (const ucontext_t * uc,
                        GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  const X86_CPU_REGISTERS * cpu = &uc->uc_mcontext.cpu;

  ctx->eip = cpu->eip;

  ctx->edi = cpu->edi;
  ctx->esi = cpu->esi;
  ctx->ebp = cpu->ebp;
  ctx->esp = cpu->esp;
  ctx->ebx = cpu->ebx;
  ctx->edx = cpu->edx;
  ctx->ecx = cpu->ecx;
  ctx->eax = cpu->eax;
#elif defined (HAVE_ARM)
  const ARM_CPU_REGISTERS * cpu = &uc->uc_mcontext.cpu;
  guint i;

  ctx->pc = cpu->gpr[ARM_REG_PC];
  ctx->sp = cpu->gpr[ARM_REG_SP];
  ctx->cpsr = cpu->spsr;
  ctx->lr = cpu->gpr[ARM_REG_LR];

  for (i = 0; i != G_N_ELEMENTS (ctx->r); i++)
    ctx->r[i] = cpu->gpr[i];

  ctx->r8 = cpu->gpr[ARM_REG_R8];
  ctx->r9 = cpu->gpr[ARM_REG_R9];
  ctx->r10 = cpu->gpr[ARM_REG_R10];
  ctx->r11 = cpu->gpr[ARM_REG_R11];
  ctx->r12 = cpu->gpr[ARM_REG_R12];
#else
# error FIXME
#endif
}

void
gum_qnx_unparse_ucontext (const GumCpuContext * ctx,
                            ucontext_t * uc)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  X86_CPU_REGISTERS * cpu = &uc->uc_mcontext.cpu;

  cpu->eip = ctx->eip;

  cpu->edi = ctx->edi;
  cpu->esi = ctx->esi;
  cpu->ebp = ctx->ebp;
  cpu->esp = ctx->esp;
  cpu->ebx = ctx->ebx;
  cpu->edx = ctx->edx;
  cpu->ecx = ctx->ecx;
  cpu->eax = ctx->eax;
#elif defined (HAVE_ARM)
  ARM_CPU_REGISTERS * cpu = &uc->uc_mcontext.cpu;
  guint i;

  cpu->gpr[ARM_REG_PC] = ctx->pc;
  cpu->gpr[ARM_REG_SP] = ctx->sp;
  cpu->gpr[ARM_REG_LR] = ctx->lr;

  for (i = 0; i != G_N_ELEMENTS (ctx->r); i++)
    cpu->gpr[i] = ctx->r[i];

  cpu->gpr[ARM_REG_R8] = ctx->r8;
  cpu->gpr[ARM_REG_R9] = ctx->r9;
  cpu->gpr[ARM_REG_R10] = ctx->r10;
  cpu->gpr[ARM_REG_R11] = ctx->r11;
  cpu->gpr[ARM_REG_R12] = ctx->r12;

  cpu->spsr = ctx->cpsr;
  if (ctx->pc & 1)
    cpu->spsr |= GUM_PSR_THUMB;
  else
    cpu->spsr &= ~GUM_PSR_THUMB;
#else
# error FIXME
#endif
}

