/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/elf.h>
#include <gio/gio.h>
#include <sys/link.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/states.h>
#include <sys/types.h>

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

typedef struct _GumDlIteratePhdrContext GumDlIteratePhdrContext;
typedef struct _GumFindModuleContext GumFindModuleContext;
typedef struct _GumEnumerateModuleRangesContext GumEnumerateModuleRangesContext;
typedef struct _GumFindExportContext GumFindExportContext;

struct _GumDlIteratePhdrContext
{
  GumFoundModuleFunc func;
  gpointer user_data;
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

static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static int gum_emit_dl_module (const struct dl_phdr_info * info, size_t size,
    void * data);

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

static GumPageProtection gum_page_protection_from_page_data_flags (
    const gint flags);

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
  return gettid ();
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data)
{
  g_assert_not_reached ();
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
  g_assert (res != 0);

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
  procfs_mapinfo membufs[512];
  gint num_membufs;
  gint i = 0;

  as_path = g_strdup_printf ("/proc/%d/as", pid);
  fd = open (as_path, O_RDONLY);
  g_assert (fd != -1);
  g_free (as_path);

  res = devctl (fd, DCMD_PROC_PAGEDATA, &membufs, sizeof (membufs),
      &num_membufs);
  g_assert (res != 0);

  close (fd);

  g_assert_cmpint (num_membufs, >, 512);

  while (carry_on && i < num_membufs)
  {
    GumRangeDetails details;
    GumMemoryRange range;

    range.base_address = membufs[i].vaddr;
    range.size = membufs[i].size;

    details.range = &range;
    details.prot = gum_page_protection_from_page_data_flags (membufs[i].flags);
    /* TODO: there doesn't seem to be a way to get the file mapping. */
    details.file = NULL;

    if ((details.prot & prot) == prot)
    {
      carry_on = func (&details, user_data);
    }

    i++;
  }
}

void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  gum_qnx_enumerate_ranges (getpid (), prot, func, user_data);
}

void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  GumDlIteratePhdrContext ctx = { func, user_data };

  dl_iterate_phdr (gum_emit_dl_module, &ctx);
}

static int
gum_emit_dl_module (const struct dl_phdr_info * info,
                    size_t size,
                    void * data)
{
  GumDlIteratePhdrContext * ctx = (GumDlIteratePhdrContext *) data;
  gboolean carry_on;
  GumModuleDetails details;
  GumMemoryRange range;

  range.base_address = info->dlpi_addr;
  /* TODO: we don't know the size of this file. */
  range.size = NULL;

  details.name = info->dlpi_name;
  details.range = &range;

  carry_on = ctx->func (&details, ctx->user_data);

  return carry_on ? 0 : 1;
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
  X86_CPU_REGISTERS * regs = (X86_CPU_REGISTERS *) gregs;

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
  ARM_CPU_REGISTERS * regs = (ARM_CPU_REGISTERS *) gregs;

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
  X86_CPU_REGISTERS * regs = (X86_CPU_REGISTERS *) gregs;

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
  ARM_CPU_REGISTERS * regs = (ARM_CPU_REGISTERS *) gregs;

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

static GumPageProtection
gum_page_protection_from_page_data_flags (const gint flags)
{
  GumPageProtection prot = GUM_PAGE_NO_ACCESS;

  if (flags & PROT_READ)
    prot |= GUM_PAGE_READ;
  if (flags & PROT_WRITE)
    prot |= GUM_PAGE_WRITE;
  if (flags & PROT_EXEC)
    prot |= GUM_PAGE_EXECUTE;

  return prot;
}

