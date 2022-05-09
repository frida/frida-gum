/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "backend-elf/gumprocess-elf.h"
#include "gum-init.h"
#include "gumqnx.h"
#include "gumqnx-priv.h"

#include <devctl.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/link.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <ucontext.h>

#define GUM_QNX_MODULE_FLAG_EXECUTABLE 0x00000200

#define GUM_PSR_THUMB 0x20

typedef struct _GumQnxListHead GumQnxListHead;
typedef struct _GumQnxModuleList GumQnxModuleList;
typedef struct _GumQnxModule GumQnxModule;

struct _GumQnxListHead
{
  GumQnxListHead * next;
  GumQnxListHead * prev;
};

struct _GumQnxModuleList
{
  GumQnxListHead list;
  GumQnxModule * module;
  GumQnxListHead * root;
  guint flags;
};

struct _GumQnxModule
{
  Link_map map;
  gint ref_count;
  guint flags;
  const gchar * name;
  /* ... */
};

static gchar * gum_try_init_libc_name (void);
static void gum_deinit_libc_name (void);

static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
static void gum_enumerate_ranges_of (const gchar * device_path,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);

static gboolean gum_maybe_resolve_program_module (const gchar * name,
    gchar ** path, GumAddress * base);
static gboolean gum_module_path_equals (const gchar * path,
    const gchar * name_or_path);
static gchar * gum_resolve_path (const gchar * path);

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
  const gpointer exit_impl = dlsym (RTLD_NEXT, "exit");

  if (!gum_process_resolve_module_pointer (exit_impl, &gum_libc_name, NULL))
    return NULL;

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
  gint fd, res G_GNUC_UNUSED;
  procfs_status status;

  fd = open ("/proc/self", O_RDONLY);
  g_assert (fd != -1);

  status.tid = gettid ();
  res = devctl (fd, DCMD_PROC_TIDSTATUS, &status, sizeof (status), NULL);
  g_assert (res == 0);

  close (fd);

  return status.flags != 0;
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
  gboolean found = FALSE;
  gint fd;
  procfs_status status;

  fd = open ("/proc/self", O_RDONLY);
  g_assert (fd != -1);

  status.tid = thread_id;
  if (devctl (fd, DCMD_PROC_TIDSTATUS, &status, sizeof (status), NULL) != EOK)
    goto beach;

  found = status.tid == thread_id;

beach:
  close (fd);

  return found;
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data)
{
  gboolean success = FALSE;
  gboolean holding = FALSE;
  pid_t child;
  int status;

  if (ThreadCtl (_NTO_TCTL_ONE_THREAD_HOLD, (void *) thread_id) == -1)
    goto beach;
  holding = TRUE;

  child = vfork ();
  if (child == -1)
    goto beach;

  if (child == 0)
  {
    gchar as_path[PATH_MAX];
    int fd, res G_GNUC_UNUSED;
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

  waitpid (child, &status, 0);

  success = TRUE;

beach:
  if (holding)
    ThreadCtl (_NTO_TCTL_ONE_THREAD_CONT, (void *) thread_id);

  return success;
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  gint fd, res G_GNUC_UNUSED;
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
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  GumQnxListHead * handle;
  GumQnxListHead * cur;
  gboolean carry_on = TRUE;

  handle = dlopen (NULL, RTLD_NOW);

  for (cur = handle->next; carry_on && cur != handle; cur = cur->next)
  {
    const GumQnxModuleList * l = (GumQnxModuleList *) cur;
    const GumQnxModule * mod = l->module;
    const Link_map * map = &mod->map;
    gchar * resolved_path, * resolved_name;
    GumModuleDetails details;
    GumMemoryRange range;
    const Elf32_Ehdr * ehdr;
    const Elf32_Phdr * phdr;
    guint i;

    if ((mod->flags & GUM_QNX_MODULE_FLAG_EXECUTABLE) != 0)
    {
      resolved_path = gum_qnx_query_program_path_for_self (NULL);
      g_assert (resolved_path != NULL);
      resolved_name = g_path_get_basename (resolved_path);

      details.name = resolved_name;
      details.path = resolved_path;
    }
    else
    {
      resolved_path = gum_resolve_path (map->l_path);
      resolved_name = NULL;

      details.name = map->l_name;
      details.path = resolved_path;
    }

    details.range = &range;
    range.base_address = map->l_addr;
    range.size = 0;
    ehdr = GSIZE_TO_POINTER (map->l_addr);
    phdr = (gconstpointer) ehdr + ehdr->e_ehsize;
    for (i = 0; i != ehdr->e_phnum; i++)
    {
      const Elf32_Phdr * h = &phdr[i];
      if (h->p_type == PT_LOAD)
        range.size += h->p_memsz;
    }

    carry_on = func (&details, user_data);

    g_free (resolved_name);
    g_free (resolved_path);
  }

  dlclose (handle);
}

void
gum_qnx_enumerate_ranges (pid_t pid,
                          GumPageProtection prot,
                          GumFoundRangeFunc func,
                          gpointer user_data)
{
  gchar * as_path = g_strdup_printf ("/proc/%d/as", pid);
  gum_enumerate_ranges_of (as_path, prot, func, user_data);
  g_free (as_path);
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
                               GumFoundRangeFunc func,
                               gpointer user_data)
{
  gum_enumerate_ranges_of ("/proc/self/as", prot, func, user_data);
}

static void
gum_enumerate_ranges_of (const gchar * device_path,
                         GumPageProtection prot,
                         GumFoundRangeFunc func,
                         gpointer user_data)
{
  gint fd, res G_GNUC_UNUSED;
  gboolean carry_on = TRUE;
  gint mapinfo_count;
  procfs_mapinfo * mapinfo_entries;
  gsize mapinfo_size;
  procfs_debuginfo * debuginfo;
  const gsize debuginfo_size = sizeof (procfs_debuginfo) + 0x100;
  gint i;

  fd = open (device_path, O_RDONLY);
  if (fd == -1)
    return;

  res = devctl (fd, DCMD_PROC_PAGEDATA, 0, 0, &mapinfo_count);
  g_assert (res == 0);
  mapinfo_size = mapinfo_count * sizeof (procfs_mapinfo);
  mapinfo_entries = g_malloc (mapinfo_size);

  debuginfo = g_malloc (debuginfo_size);

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfo_entries, mapinfo_size,
      &mapinfo_count);
  g_assert (res == 0);

  for (i = 0; carry_on && i != mapinfo_count; i++)
  {
    const procfs_mapinfo * mapinfo = &mapinfo_entries[i];
    GumRangeDetails details;
    GumMemoryRange range;
    GumFileMapping file;
    gchar * path = NULL;

    details.range = &range;
    details.protection = _gum_page_protection_from_posix (mapinfo->flags);

    range.base_address = mapinfo->vaddr;
    range.size = mapinfo->size;

    debuginfo->vaddr = mapinfo->vaddr;
    res = devctl (fd, DCMD_PROC_MAPDEBUG, debuginfo, debuginfo_size, NULL);
    g_assert (res == 0);
    if (strcmp (debuginfo->path, "/dev/zero") != 0)
    {
      if (debuginfo->path[0] != '/')
      {
        path = g_strconcat ("/", debuginfo->path, NULL);
        file.path = path;
      }
      else
      {
        file.path = debuginfo->path;
      }

      file.offset = mapinfo->offset;
      file.size = mapinfo->size;

      details.file = &file;
    }
    else
    {
      details.file = NULL;
    }

    if ((details.protection & prot) == prot)
    {
      carry_on = func (&details, user_data);
    }

    g_free (path);
  }

  g_free (debuginfo);
  g_free (mapinfo_entries);

  close (fd);
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  /* Not implemented */
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
  gchar * name = NULL;
  void * module;

  success = FALSE;

  if (!_gum_process_resolve_module_name (module_name, &name, NULL))
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

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumAddress result;
  void * module;

  if (module_name != NULL)
  {
    gchar * name;

    if (!_gum_process_resolve_module_name (module_name, &name, NULL))
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

GumCpuType
gum_qnx_cpu_type_from_file (const gchar * path,
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
gum_qnx_cpu_type_from_pid (pid_t pid,
                           GError ** error)
{
  GumCpuType result = -1;
  gchar * auxv_path;
  guint8 * auxv;
  gsize auxv_size, i;

  auxv_path = g_strdup_printf ("/proc/%d/auxv", pid);

  auxv = NULL;
  if (!g_file_get_contents (auxv_path, (gchar **) &auxv, &auxv_size, NULL))
    goto not_found;

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

  goto beach;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "Process not found");
    goto beach;
  }
beach:
  {
    g_free (auxv_path);

    return result;
  }
}

gchar *
gum_qnx_query_program_path_for_self (GError ** error)
{
  gchar * program_path = NULL;
  int fd;
  struct
  {
    procfs_debuginfo info;
    char buffer[PATH_MAX];
  } name;

  fd = open ("/proc/self/as", O_RDONLY);
  if (fd == -1)
    goto failure;

  if (devctl (fd, DCMD_PROC_MAPDEBUG_BASE, &name, sizeof (name), 0) != EOK)
    goto failure;

  if (g_path_is_absolute (name.info.path))
  {
    program_path = g_strdup (name.info.path);
  }
  else
  {
    gchar * cwd = g_get_current_dir ();
    program_path = g_canonicalize_filename (name.info.path, cwd);
    g_free (cwd);
  }

  goto beach;

failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "%s", g_strerror (errno));
    goto beach;
  }
beach:
  {
    if (fd != -1)
      close (fd);

    return program_path;
  }
}

gboolean
_gum_process_resolve_module_name (const gchar * name,
                                  gchar ** path,
                                  GumAddress * base)
{
  GumQnxListHead * handle;
  const GumQnxModule * module;

  handle = dlopen (name, RTLD_LAZY | RTLD_NOLOAD);
  if (handle == NULL)
    return gum_maybe_resolve_program_module (name, path, base);

  module = ((GumQnxModuleList *) handle->next->next)->module;

  if (path != NULL)
    *path = gum_resolve_path (module->map.l_path);

  if (base != NULL)
    *base = module->map.l_addr;

  dlclose (handle);

  return TRUE;
}

static gboolean
gum_maybe_resolve_program_module (const gchar * name,
                                  gchar ** path,
                                  GumAddress * base)
{
  gchar * program_path;

  program_path = gum_qnx_query_program_path_for_self (NULL);
  g_assert (program_path != NULL);

  if (!gum_module_path_equals (program_path, name))
    goto not_the_program;

  if (path != NULL)
    *path = g_steal_pointer (&program_path);

  if (base != NULL)
  {
    GumQnxListHead * handle;
    const GumQnxModule * program;

    handle = dlopen (NULL, RTLD_NOW);

    program = ((GumQnxModuleList *) handle->next)->module;
    *base = program->map.l_addr;

    dlclose (handle);
  }

  g_free (program_path);

  return TRUE;

not_the_program:
  {
    g_free (program_path);

    return FALSE;
  }
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

static gchar *
gum_resolve_path (const gchar * path)
{
  gchar * target, * parent_dir, * canonical_path;

  target = g_file_read_link (path, NULL);
  if (target == NULL)
    return g_strdup (path);

  parent_dir = g_path_get_dirname (path);

  canonical_path = g_canonicalize_filename (target, parent_dir);

  g_free (parent_dir);
  g_free (target);

  return canonical_path;
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

  ctx->cpsr = regs->spsr;
  ctx->pc = regs->gpr[ARM_REG_R15];
  ctx->sp = regs->gpr[ARM_REG_R13];

  ctx->r8 = regs->gpr[ARM_REG_R8];
  ctx->r9 = regs->gpr[ARM_REG_R9];
  ctx->r10 = regs->gpr[ARM_REG_R10];
  ctx->r11 = regs->gpr[ARM_REG_R11];
  ctx->r12 = regs->gpr[ARM_REG_R12];

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

  regs->spsr = ctx->cpsr;
  regs->gpr[ARM_REG_R15] = ctx->pc;
  regs->gpr[ARM_REG_R13] = ctx->sp;

  regs->gpr[ARM_REG_R8] = ctx->r8;
  regs->gpr[ARM_REG_R9] = ctx->r9;
  regs->gpr[ARM_REG_R10] = ctx->r10;
  regs->gpr[ARM_REG_R11] = ctx->r11;
  regs->gpr[ARM_REG_R12] = ctx->r12;

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

