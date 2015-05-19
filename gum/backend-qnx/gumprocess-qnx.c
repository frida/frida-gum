/*
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess.h"

#include "gumqnx-priv.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/elf.h>
#include <sys/link.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <sys/states.h>
#include <sys/types.h>

#define GUM_HIJACK_SIGNAL (SIGRTMIN + 7)

#if GLIB_SIZEOF_VOID_P == 4
typedef Elf32_Ehdr GumElfEHeader;
typedef Elf32_Shdr GumElfSHeader;
typedef Elf32_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF32_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#else
typedef Elf64_Ehdr GumElfEHeader;
typedef Elf64_Shdr GumElfSHeader;
typedef Elf64_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF64_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF64_ST_TYPE(val)
#endif

typedef struct _GumFindModuleContext GumFindModuleContext;
typedef struct _GumEnumerateModuleRangesContext GumEnumerateModuleRangesContext;
typedef struct _GumFindExportContext GumFindExportContext;
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

struct _GumFindExportContext
{
  GumAddress result;
  const gchar * symbol_name;
};

struct _GumDlPhdrInternal
{
    GumDlPhdrInternal * p_next;
    gint unknown;
    Link_map * linkmap;
};

static void gum_do_modify_thread (int sig, siginfo_t * siginfo,
    void * context);
static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static gboolean gum_emit_range_if_module_name_matches (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_store_base_and_path_if_name_matches (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_store_address_if_export_name_matches (
    const GumExportDetails * details, gpointer user_data);

static gboolean gum_module_path_equals (const gchar * path,
    const gchar * name_or_path);

static void gum_cpu_context_from_qnx (const debug_greg_t * gregs,
    GumCpuContext * ctx);
static void gum_cpu_context_to_qnx (const GumCpuContext * ctx,
    debug_greg_t * gregs);

static GumThreadState gum_thread_state_from_system_thread_state (int state);

G_LOCK_DEFINE_STATIC (gum_modify_thread);
static volatile gboolean gum_modify_thread_did_load_cpu_context;
static volatile gboolean gum_modify_thread_did_modify_cpu_context;
static volatile gboolean gum_modify_thread_did_store_cpu_context;
static GumCpuContext gum_modify_thread_cpu_context;

gboolean
gum_process_is_debugger_attached (void)
{
  g_assert_not_reached ();
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  return gettid ();
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data)
{
  gboolean success = FALSE;
  struct sigaction action, old_action;

  if (thread_id == gum_process_get_current_thread_id ())
  {
    procfs_greg gregs;
    int fd, res;
    volatile gboolean modified = FALSE;

    fd = open ("/proc/self/as", O_RDONLY);
    g_assert (fd != -1);

    res = devctl (fd, DCMD_PROC_CURTHREAD, &thread_id, sizeof (thread_id), NULL);
    g_assert (res == 0);

    res = devctl (fd, DCMD_PROC_GETGREG, &gregs, sizeof (gregs), NULL);
    g_assert (res == 0);

    if (!modified)
    {
      GumCpuContext cpu_context;

      gum_cpu_context_from_qnx (&gregs, &cpu_context);
      func (thread_id, &cpu_context, user_data);
      gum_cpu_context_to_qnx (&cpu_context, &gregs);

      modified = TRUE;

      res = devctl (fd, DCMD_PROC_SETGREG, &gregs, sizeof (gregs), NULL);
      /* TODO: this doesn't appear to work. not sure why. disabling the
       * assert for the moment: */
      /* g_assert (res == 0); */
    }

    close (fd);
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

    if (SignalKill (0, getpid (), thread_id, GUM_HIJACK_SIGNAL, 0, 0) != -1)
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

  return success;
}

static void
gum_do_modify_thread (int sig,
                      siginfo_t * siginfo,
                      void * context)
{
  debug_greg_t * gregs = (debug_greg_t *) context;

  gum_cpu_context_from_qnx (gregs, &gum_modify_thread_cpu_context);
  gum_modify_thread_did_load_cpu_context = TRUE;
  while (!gum_modify_thread_did_modify_cpu_context)
    ;
  gum_cpu_context_to_qnx (&gum_modify_thread_cpu_context, gregs);
  gum_modify_thread_did_store_cpu_context = TRUE;
}


void
gum_process_enumerate_threads (GumFoundThreadFunc func,
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

    if (gum_process_modify_thread (details.id, gum_store_cpu_context,
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
    details.prot = _gum_page_protection_from_posix (mapinfos[i].flags);

    range.base_address = mapinfos[i].vaddr;
    range.size = mapinfos[i].size;

    debuginfo->vaddr = mapinfos[i].vaddr;
    res = devctl (fd, DCMD_PROC_MAPDEBUG, debuginfo,
        sizeof (procfs_debuginfo) + 0x100, NULL);
    g_assert (res == 0);
    file.path = debuginfo->path;

    if ((details.prot & prot) == prot)
    {
      carry_on = func (&details, user_data);
    }
  }

  close (fd);
  g_free (mapinfos);
  g_free (debuginfo);
}

void
gum_process_enumerate_ranges (GumPageProtection prot,
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

    if (details.path)
    {
      details.name = g_path_get_basename (details.path);

      carry_on = func (&details, user_data);

      g_free (details.name);
    }
  }

  g_free (mapinfos);
  close (fd);
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
  if (ehdr->e_type != ET_DYN)
    goto beach;

  for (i = 0; i != ehdr->e_shnum; i++)
  {
    GumElfSHeader * shdr;

    shdr = base_address + ehdr->e_shoff + (i * ehdr->e_shentsize);
    if (shdr->sh_type == SHT_DYNSYM)
    {
      GumElfSHeader * strtab_shdr;

      dynsym_section_offset = shdr->sh_offset;
      dynsym_section_size = shdr->sh_size;
      dynsym_entry_size = shdr->sh_entsize;

      strtab_shdr = base_address + ehdr->e_shoff +
          (shdr->sh_link * ehdr->e_shentsize);
      dynsym_strtab = base_address + strtab_shdr->sh_offset;

      g_assert_cmpuint (dynsym_section_size % dynsym_entry_size, ==, 0);
    }
  }

  if (dynsym_section_offset == 0)
    goto beach;

  for (i = 0; i != dynsym_section_size / dynsym_entry_size; i++)
  {
    GumElfSymbol * sym;

    sym = base_address + dynsym_section_offset + (i * dynsym_entry_size);
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
  GumFindExportContext ctx;

  ctx.result = 0;
  ctx.symbol_name = symbol_name;

  gum_module_enumerate_exports (module_name,
      gum_store_address_if_export_name_matches, &ctx);

  return ctx.result;
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

static gboolean
gum_store_address_if_export_name_matches (const GumExportDetails * details,
                                          gpointer user_data)
{
  GumFindExportContext * ctx = (GumFindExportContext *) user_data;

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
  ARM_CPU_REGISTERS * regs = &gregs->arm;

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
    default:
      g_assert_not_reached ();
      break;
  }
}

