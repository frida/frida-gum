/*
 * Copyright (C) 2010-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gumlinux.h"
#include "gummodulemap.h"
#include "valgrind.h"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gio/gio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#if defined (HAVE_ARM) || defined (HAVE_MIPS)
# include <asm/ptrace.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#ifndef HAVE_ANDROID
# include <link.h>
#endif

#define GUM_MAPS_LINE_SIZE (1024 + PATH_MAX)
#define GUM_PSR_THUMB 0x20

#if defined (HAVE_I386)
# define GumRegs struct user_regs_struct
#elif defined (HAVE_ARM)
# define GumRegs struct pt_regs
#elif defined (HAVE_ARM64)
# define GumRegs struct user_pt_regs
#elif defined (HAVE_MIPS)
# define GumRegs struct pt_regs
#else
# error Unsupported architecture
#endif
#ifndef PTRACE_GETREGS
# define PTRACE_GETREGS 12
#endif
#ifndef PTRACE_SETREGS
# define PTRACE_SETREGS 13
#endif
#ifndef PTRACE_GETREGSET
# define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
# define PTRACE_SETREGSET 0x4205
#endif
#ifndef NT_PRSTATUS
# define NT_PRSTATUS 1
#endif

#define GUM_TEMP_FAILURE_RETRY(expression) \
  ({ \
    gssize __result; \
    \
    do __result = (gssize) (expression); \
    while (__result == -EINTR); \
    \
    __result; \
  })

typedef struct _GumModifyThreadContext GumModifyThreadContext;
typedef guint8 GumModifyThreadAck;

typedef struct _GumEnumerateImportsContext GumEnumerateImportsContext;
typedef struct _GumDependencyExport GumDependencyExport;
typedef struct _GumEnumerateModuleRangesContext GumEnumerateModuleRangesContext;
typedef struct _GumResolveModuleNameContext GumResolveModuleNameContext;

typedef struct _GumElfModule GumElfModule;
typedef struct _GumElfDependencyDetails GumElfDependencyDetails;
typedef struct _GumElfEnumerateImportsContext GumElfEnumerateImportsContext;
typedef struct _GumElfEnumerateExportsContext GumElfEnumerateExportsContext;
typedef struct _GumElfSymbolDetails GumElfSymbolDetails;

typedef struct _GumUserDesc GumUserDesc;

typedef gboolean (* GumElfFoundDependencyFunc) (
    const GumElfDependencyDetails * details, gpointer user_data);
typedef gboolean (* GumElfFoundSymbolFunc) (const GumElfSymbolDetails * details,
    gpointer user_data);

typedef gint (* GumCloneFunc) (gpointer arg);

typedef guint GumElfSHeaderIndex;
typedef guint GumElfSHeaderType;
typedef guint GumElfSymbolType;
typedef guint GumElfSymbolBind;
#if GLIB_SIZEOF_VOID_P == 4
typedef Elf32_Ehdr GumElfEHeader;
typedef Elf32_Phdr GumElfPHeader;
typedef Elf32_Shdr GumElfSHeader;
typedef Elf32_Dyn GumElfDynamic;
typedef Elf32_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF32_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF32_ST_TYPE(val)
#else
typedef Elf64_Ehdr GumElfEHeader;
typedef Elf64_Phdr GumElfPHeader;
typedef Elf64_Shdr GumElfSHeader;
typedef Elf64_Dyn GumElfDynamic;
typedef Elf64_Sym GumElfSymbol;
# define GUM_ELF_ST_BIND(val) ELF64_ST_BIND(val)
# define GUM_ELF_ST_TYPE(val) ELF64_ST_TYPE(val)
#endif

enum _GumModifyThreadAck
{
  GUM_ACK_ATTACHED = 1,
  GUM_ACK_STOPPED,
  GUM_ACK_READ_CONTEXT,
  GUM_ACK_MODIFIED_CONTEXT,
  GUM_ACK_WROTE_CONTEXT,
  GUM_ACK_FAILED_TO_ATTACH,
  GUM_ACK_FAILED_TO_READ,
  GUM_ACK_FAILED_TO_WRITE,
  GUM_ACK_FAILED_TO_DETACH
};

struct _GumModifyThreadContext
{
  gint fd[2];
  GumThreadId thread_id;
  GumCpuContext cpu_context;
};

struct _GumEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;

  GHashTable * dependency_exports;
  GumElfModule * current_dependency;
  GumModuleMap * module_map;
};

struct _GumDependencyExport
{
  gchar * module;
  GumAddress address;
};

struct _GumEnumerateModuleRangesContext
{
  gchar * module_name;
  GumFoundRangeFunc func;
  gpointer user_data;
};

struct _GumResolveModuleNameContext
{
  gchar * name;
  gchar * path;
  GumAddress base;
};

struct _GumElfModule
{
  gchar * path;
  gint fd;
  gsize file_size;
  gpointer data;
  GumElfEHeader * ehdr;
  gpointer address;
  GumAddress preferred_address;
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

struct _GumUserDesc
{
  guint entry_number;
  guint base_addr;
  guint limit;
  guint seg_32bit : 1;
  guint contents : 2;
  guint read_exec_only : 1;
  guint limit_in_pages : 1;
  guint seg_not_present : 1;
  guint useable : 1;
};

static gint gum_do_modify_thread (gpointer data);
static gboolean gum_await_ack (gint fd, GumModifyThreadAck expected_ack);
static void gum_put_ack (gint fd, GumModifyThreadAck ack);

static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static gboolean gum_emit_import (const GumImportDetails * details,
    gpointer user_data);
static gboolean gum_collect_dependency_exports (
    const GumElfDependencyDetails * details, gpointer user_data);
static gboolean gum_collect_dependency_export (const GumExportDetails * details,
    gpointer user_data);
static GumDependencyExport * gum_dependency_export_new (const gchar * module,
    GumAddress address);
static void gum_dependency_export_free (GumDependencyExport * export);
static gboolean gum_emit_range_if_module_name_matches (
    const GumRangeDetails * details, gpointer user_data);

static gchar * gum_resolve_module_name (const gchar * name, GumAddress * base);
static gboolean gum_store_module_path_and_base_if_name_matches (
    const GumModuleDetails * details, gpointer user_data);
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
static GumAddress gum_elf_module_compute_preferred_address (
    GumElfModule * self);
static GumElfSHeader * gum_elf_module_find_section_header (GumElfModule * self,
    GumElfSHeaderType type);

static gboolean gum_thread_read_state (GumThreadId tid, GumThreadState * state);
static GumThreadState gum_thread_state_from_proc_status_character (gchar c);
static GumPageProtection gum_page_protection_from_proc_perms_string (
    const gchar * perms);

static gssize gum_get_regs (pid_t pid, GumRegs * regs);
static gssize gum_set_regs (pid_t pid, const GumRegs * regs);

static void gum_parse_regs (const GumRegs * regs, GumCpuContext * ctx);
static void gum_unparse_regs (const GumCpuContext * ctx, GumRegs * regs);

static gssize gum_libc_clone (GumCloneFunc child_func, gpointer child_stack,
    gint flags, gpointer arg, pid_t * parent_tidptr, GumUserDesc * tls,
    pid_t * child_tidptr);
static gssize gum_libc_read (gint fd, gpointer buf, gsize count);
static gssize gum_libc_write (gint fd, gconstpointer buf, gsize count);
static gssize gum_libc_ptrace (gsize request, pid_t pid, gpointer address,
    gpointer data);

#define gum_libc_syscall_3(n, a, b, c) gum_libc_syscall_4 (n, a, b, c, 0)
static gssize gum_libc_syscall_4 (gsize n, gsize a, gsize b, gsize c, gsize d);

#if defined (HAVE_MIPS)
static int getcontext (ucontext_t * ucp);
static int setcontext (const ucontext_t * ucp);
#endif

static gboolean gum_is_regset_supported = TRUE;

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

  if (thread_id == gum_process_get_current_thread_id ())
  {
#ifndef HAVE_ANDROID
    ucontext_t uc;
    volatile gboolean modified = FALSE;

    getcontext (&uc);
    if (!modified)
    {
      GumCpuContext cpu_context;

      gum_linux_parse_ucontext (&uc, &cpu_context);
      func (thread_id, &cpu_context, user_data);
      gum_linux_unparse_ucontext (&cpu_context, &uc);

      modified = TRUE;
      setcontext (&uc);
    }

    success = TRUE;
#endif
  }
  else
  {
    GumModifyThreadContext ctx;
    gint res, fd;
    gssize child;
    gpointer stack, tls;
    GumUserDesc * desc;

    res = socketpair (AF_UNIX, SOCK_STREAM, 0, ctx.fd);
    g_assert_cmpint (res, ==, 0);
    ctx.thread_id = thread_id;

    fd = ctx.fd[0];

    stack = gum_alloc_n_pages (1, GUM_PAGE_RW);
    tls = gum_alloc_n_pages (1, GUM_PAGE_RW);

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
    GumUserDesc segment;
    gint gs;

    asm volatile (
        "movw %%gs, %w0"
        : "=q" (gs)
    );

    segment.entry_number = (gs & 0xffff) >> 3;
    segment.base_addr = GPOINTER_TO_SIZE (tls);
    segment.limit = 0xfffff;
    segment.seg_32bit = 1;
    segment.contents = 0;
    segment.read_exec_only = 0;
    segment.limit_in_pages = 1;
    segment.seg_not_present = 0;
    segment.useable = 1;

    desc = &segment;
#else
    desc = tls;
#endif

    /*
     * It seems like the only reliable way to read/write the registers of
     * another thread is to use ptrace(). We used to accomplish this by
     * hi-jacking the target thread by installing a signal handler and sending a
     * real-time signal directed at the target thread, and thus relying on the
     * signal handler getting called in that thread. The signal handler would
     * then provide us with read/write access to its registers. This hack would
     * however not work if a thread was for example blocking in poll(), as the
     * signal would then just get queued and we'd end up waiting indefinitely.
     *
     * It is however not possible to ptrace() another thread when we're in the
     * same process group. This used to be supported in old kernels, but it was
     * buggy and eventually dropped. So in order to use ptrace() we will need to
     * spawn a new thread in a different process group so that it can ptrace()
     * the target thread inside our process group. This is also the solution
     * recommended by Linus:
     *
     * https://lkml.org/lkml/2006/9/1/217
     *
     * Because libc implementations don't expose an API to do this, and the
     * thread setup code is private, where the TLS part is crucial for even just
     * the syscall wrappers - due to them accessing `errno` - we cannot make any
     * libc calls in this thread. And because the libc's clone() syscall wrapper
     * typically writes to the child thread's TLS structures, which we cannot
     * portably set up correctly, we cannot use the libc clone() syscall wrapper
     * either.
     */
    child = gum_libc_clone (
        gum_do_modify_thread,
        stack + gum_query_page_size (),
        CLONE_VM | CLONE_SETTLS,
        &ctx,
        NULL,
        desc,
        NULL);
    g_assert_cmpint (child, >, 0);

    if (gum_await_ack (fd, GUM_ACK_ATTACHED))
    {
      GumThreadState state;
      gboolean still_alive;

      while ((still_alive = gum_thread_read_state (thread_id, &state)) &&
          state != GUM_THREAD_STOPPED)
      {
        g_usleep (G_USEC_PER_SEC / 100);
      }
      gum_put_ack (fd, GUM_ACK_STOPPED);

      if (still_alive)
      {
        gum_await_ack (fd, GUM_ACK_READ_CONTEXT);
        func (thread_id, &ctx.cpu_context, user_data);
        gum_put_ack (fd, GUM_ACK_MODIFIED_CONTEXT);

        success = gum_await_ack (fd, GUM_ACK_WROTE_CONTEXT);
      }
    }

    waitpid (child, NULL, __WCLONE);

    gum_free_pages (tls);
    gum_free_pages (stack);

    close (ctx.fd[0]);
    close (ctx.fd[1]);
  }

  return success;
}

static gint
gum_do_modify_thread (gpointer data)
{
  GumModifyThreadContext * ctx = data;
  gint fd;
  gssize res;
  GumRegs regs;

  fd = ctx->fd[1];

  res = gum_libc_ptrace (PTRACE_ATTACH, ctx->thread_id, NULL, NULL);
  if (res < 0)
    goto failed_to_attach;
  gum_put_ack (fd, GUM_ACK_ATTACHED);

  gum_await_ack (fd, GUM_ACK_STOPPED);
  res = gum_get_regs (ctx->thread_id, &regs);
  if (res < 0)
    goto failed_to_read;
  gum_parse_regs (&regs, &ctx->cpu_context);
  gum_put_ack (fd, GUM_ACK_READ_CONTEXT);

  gum_await_ack (fd, GUM_ACK_MODIFIED_CONTEXT);
  gum_unparse_regs (&ctx->cpu_context, &regs);
  res = gum_set_regs (ctx->thread_id, &regs);
  if (res < 0)
    goto failed_to_write;

  res = gum_libc_ptrace (PTRACE_DETACH, ctx->thread_id, NULL, NULL);
  if (res < 0)
    goto failed_to_detach;

  gum_put_ack (fd, GUM_ACK_WROTE_CONTEXT);

  goto beach;

failed_to_attach:
  {
    gum_put_ack (fd, GUM_ACK_FAILED_TO_ATTACH);
    goto beach;
  }
failed_to_read:
  {
    gum_put_ack (fd, GUM_ACK_FAILED_TO_READ);
    goto beach;
  }
failed_to_write:
  {
    gum_put_ack (fd, GUM_ACK_FAILED_TO_WRITE);
    goto beach;
  }
failed_to_detach:
  {
    gum_put_ack (fd, GUM_ACK_FAILED_TO_DETACH);
    goto beach;
  }
beach:
  {
    return 0;
  }
}

static gboolean
gum_await_ack (gint fd,
               GumModifyThreadAck expected_ack)
{
  guint8 value;
  gssize res;

  res = GUM_TEMP_FAILURE_RETRY (gum_libc_read (fd, &value, sizeof (value)));
  if (res == -1)
    return FALSE;

  return value == expected_ack;
}

static void
gum_put_ack (gint fd,
             GumModifyThreadAck ack)
{
  guint8 value;

  value = ack;
  GUM_TEMP_FAILURE_RETRY (gum_libc_write (fd, &value, sizeof (value)));
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  GDir * dir;
  const gchar * name;
  gboolean carry_on = TRUE;

  dir = g_dir_open ("/proc/self/task", 0, NULL);
  g_assert (dir != NULL);

  while (carry_on && (name = g_dir_read_name (dir)) != NULL)
  {
    GumThreadDetails details;

    details.id = atoi (name);
    if (gum_thread_read_state (details.id, &details.state))
    {
      if (gum_process_modify_thread (details.id, gum_store_cpu_context,
            &details.cpu_context))
      {
        carry_on = func (&details, user_data);
      }
    }
  }

  g_dir_close (dir);
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
  FILE * fp;
  const guint line_size = GUM_MAPS_LINE_SIZE;
  gchar * line, * path, * next_path;
  gboolean carry_on = TRUE;
  gboolean got_line = FALSE;

  fp = fopen ("/proc/self/maps", "r");
  g_assert (fp != NULL);

  line = g_malloc (line_size);

  path = g_malloc (PATH_MAX);
  next_path = g_malloc (PATH_MAX);

  do
  {
    const guint8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };
    GumModuleDetails details;
    GumMemoryRange range;
    GumAddress end;
    gchar perms[5] = { 0, };
    gint n;
    gboolean readable, shared;
    gchar * name;

    if (!got_line)
    {
      if (fgets (line, line_size, fp) == NULL)
        break;
    }
    else
    {
      got_line = FALSE;
    }

    n = sscanf (line,
        "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x "
        "%4c "
        "%*x %*s %*d "
        "%s",
        &range.base_address, &end,
        perms,
        path);
    if (n == 3)
      continue;
    g_assert_cmpint (n, ==, 4);

    readable = perms[0] == 'r';
    shared = perms[3] == 's';
    if (!readable || shared)
      continue;
    else if (path[0] != '/' || g_str_has_prefix (path, "/dev/"))
      continue;
    else if (RUNNING_ON_VALGRIND && strstr (path, "/valgrind/") != NULL)
      continue;
    else if (memcmp (GSIZE_TO_POINTER (range.base_address), elf_magic,
        sizeof (elf_magic)) != 0)
      continue;

    name = g_path_get_basename (path);

    range.size = end - range.base_address;

    details.name = name;
    details.range = &range;
    details.path = path;

    while (fgets (line, line_size, fp) != NULL)
    {
      n = sscanf (line,
          "%*x-%" G_GINT64_MODIFIER "x %*c%*c%*c%*c %*x %*s %*d %s",
          &end,
          next_path);
      if (n == 1)
      {
        continue;
      }
      else if (n == 2 && strcmp (next_path, path) == 0)
      {
        range.size = end - range.base_address;
      }
      else
      {
        got_line = TRUE;
        break;
      }
    }

    carry_on = func (&details, user_data);

    g_free (name);
  }
  while (carry_on);

  g_free (path);
  g_free (next_path);

  g_free (line);

  fclose (fp);
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
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

        if (RUNNING_ON_VALGRIND && strstr (file.path, "/valgrind/") != NULL)
          continue;
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

gboolean
gum_thread_try_get_range (GumMemoryRange * range)
{
  /* Not implemented */
  range->base_address = 0;
  range->size = 0;

  return FALSE;
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
      g_free, (GDestroyNotify) gum_dependency_export_free);
  ctx.current_dependency = NULL;
  ctx.module_map = NULL;

  gum_elf_module_enumerate_dependencies (&module,
      gum_collect_dependency_exports, &ctx);

  gum_elf_module_enumerate_imports (&module, gum_emit_import, &ctx);

  if (ctx.module_map != NULL)
    g_object_unref (ctx.module_map);
  g_hash_table_unref (ctx.dependency_exports);

  gum_elf_module_close (&module);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumImportDetails d;
  GumDependencyExport * exp;

  d.type = details->type;
  d.name = details->name;

  exp = g_hash_table_lookup (ctx->dependency_exports, details->name);
  if (exp != NULL)
  {
    d.module = exp->module;
    d.address = exp->address;
  }
  else
  {
    d.module = NULL;
    d.address = GUM_ADDRESS (dlsym (RTLD_DEFAULT, details->name));

    if (d.address != 0)
    {
      const GumModuleDetails * module;

      if (ctx->module_map == NULL)
        ctx->module_map = gum_module_map_new ();
      module = gum_module_map_find (ctx->module_map, d.address);
      if (module != NULL)
        d.module = module->path;
    }
  }

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

  g_hash_table_insert (ctx->dependency_exports,
      g_strdup (details->name),
      gum_dependency_export_new (module->path, details->address));

  return TRUE;
}

static GumDependencyExport *
gum_dependency_export_new (const gchar * module,
                           GumAddress address)
{
  GumDependencyExport * export;

  export = g_slice_new (GumDependencyExport);
  export->module = g_strdup (module);
  export->address = address;

  return export;
}

static void
gum_dependency_export_free (GumDependencyExport * export)
{
  g_free (export->module);
  g_slice_free (GumDependencyExport, export);
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

  ctx.module_name = gum_resolve_module_name (module_name, NULL);
  if (ctx.module_name == NULL)
    return;
  ctx.func = func;
  ctx.user_data = user_data;

  gum_process_enumerate_ranges (prot, gum_emit_range_if_module_name_matches,
      &ctx);

  g_free (ctx.module_name);
}

static gboolean
gum_emit_range_if_module_name_matches (const GumRangeDetails * details,
                                       gpointer user_data)
{
  GumEnumerateModuleRangesContext * ctx = user_data;

  if (details->file == NULL)
    return TRUE;
  else if (strcmp (details->file->path, ctx->module_name) != 0)
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  GumAddress base;
  gchar * canonical_name;

  canonical_name = gum_resolve_module_name (module_name, &base);
  if (canonical_name == NULL)
    return 0;
  g_free (canonical_name);

  return base;
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
    module = dlopen (name, RTLD_LAZY | RTLD_GLOBAL);
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
    case 0x0008:
      result = GUM_CPU_MIPS;
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
  GumCpuType cpu32, cpu64;

  auxv_path = g_strdup_printf ("/proc/%d/auxv", pid);

  if (!g_file_get_contents (auxv_path, (gchar **) &auxv, &auxv_size, error))
    goto beach;

#if defined (HAVE_I386)
  cpu32 = GUM_CPU_IA32;
  cpu64 = GUM_CPU_AMD64;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu32 = GUM_CPU_ARM;
  cpu64 = GUM_CPU_ARM64;
#elif defined (HAVE_MIPS)
  cpu32 = GUM_CPU_MIPS;
  cpu64 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  if (auxv[0] != AT_NULL)
  {
    result = cpu64;

    for (i = 0; i < auxv_size; i += 16)
    {
      if (auxv[4] != 0 || auxv[5] != 0 ||
          auxv[6] != 0 || auxv[7] != 0)
      {
        result = cpu32;
        break;
      }
    }
  }
  else
  {
    result = (auxv_size == 8) ? cpu32 : cpu64;
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

#if defined (HAVE_GLIBC)
  struct link_map * map;

  map = dlopen (name, RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
  if (map != NULL)
  {
    ctx.name = g_file_read_link (map->l_name, NULL);
    if (ctx.name == NULL)
      ctx.name = g_strdup (map->l_name);
    dlclose (map);
  }
  else
#endif
    ctx.name = g_strdup (name);
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
gum_store_module_path_and_base_if_name_matches (const GumModuleDetails * details,
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

static gboolean
gum_elf_module_open (GumElfModule * module,
                     const gchar * module_name)
{
  gboolean success = FALSE;
  GumAddress base;
  guint type;

  module->fd = -1;
  module->file_size = 0;
  module->data = NULL;
  module->ehdr = NULL;
  module->address = 0;
  module->path = gum_resolve_module_name (module_name, &base);
  if (module->path == NULL)
    goto beach;
  module->address = GSIZE_TO_POINTER (base);

  module->fd = open (module->path, O_RDONLY);
  if (module->fd == -1)
    goto beach;

  module->file_size = lseek (module->fd, 0, SEEK_END);
  lseek (module->fd, 0, SEEK_SET);

  module->data = mmap (NULL, module->file_size, PROT_READ, MAP_PRIVATE,
      module->fd, 0);
  g_assert (module->data != MAP_FAILED);

  module->ehdr = module->data;
  type = module->ehdr->e_type;
  if (type != ET_EXEC && type != ET_DYN)
    goto beach;
  module->preferred_address = gum_elf_module_compute_preferred_address (module);
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
    details.address =
        GUM_ADDRESS (sym->st_value - self->preferred_address + self->address);
    details.type = GUM_ELF_ST_TYPE (sym->st_info);
    details.bind = GUM_ELF_ST_BIND (sym->st_info);
    details.section_header_index = sym->st_shndx;

    carry_on = func (&details, user_data);
  }
}

static GumAddress
gum_elf_module_compute_preferred_address (GumElfModule * self)
{
  GumElfEHeader * ehdr = self->ehdr;
  guint i;

  for (i = 0; i != ehdr->e_phnum; i++)
  {
    GumElfPHeader * phdr;

    phdr = self->data + ehdr->e_phoff + (i * ehdr->e_phentsize);
    if (phdr->p_offset == 0)
      return phdr->p_vaddr;
  }

  return 0;
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

void
gum_linux_parse_ucontext (const ucontext_t * uc,
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
#elif defined (HAVE_ARM)
  const struct sigcontext * sc = &uc->uc_mcontext;

  ctx->cpsr = sc->arm_cpsr;
  ctx->pc = sc->arm_pc;
  ctx->sp = sc->arm_sp;

  ctx->r8 = sc->arm_r8;
  ctx->r9 = sc->arm_r9;
  ctx->r10 = sc->arm_r10;
  ctx->r11 = sc->arm_fp;
  ctx->r12 = sc->arm_ip;

  ctx->r[0] = sc->arm_r0;
  ctx->r[1] = sc->arm_r1;
  ctx->r[2] = sc->arm_r2;
  ctx->r[3] = sc->arm_r3;
  ctx->r[4] = sc->arm_r4;
  ctx->r[5] = sc->arm_r5;
  ctx->r[6] = sc->arm_r6;
  ctx->r[7] = sc->arm_r7;
  ctx->lr = sc->arm_lr;
#elif defined (HAVE_ARM64)
  const struct sigcontext * sc = &uc->uc_mcontext;
  gsize i;

  ctx->pc = sc->pc;
  ctx->sp = sc->sp;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    ctx->x[i] = sc->regs[i];
  ctx->fp = sc->regs[29];
  ctx->lr = sc->regs[30];
  memset (ctx->q, 0, sizeof (ctx->q));
#elif defined (HAVE_MIPS)
  const greg_t * gr = uc->uc_mcontext.gregs;

  ctx->at = (guint32) gr[1];

  ctx->v0 = (guint32) gr[2];
  ctx->v1 = (guint32) gr[3];

  ctx->a0 = (guint32) gr[4];
  ctx->a1 = (guint32) gr[5];
  ctx->a2 = (guint32) gr[6];
  ctx->a3 = (guint32) gr[7];

  ctx->t0 = (guint32) gr[8];
  ctx->t1 = (guint32) gr[9];
  ctx->t2 = (guint32) gr[10];
  ctx->t3 = (guint32) gr[11];
  ctx->t4 = (guint32) gr[12];
  ctx->t5 = (guint32) gr[13];
  ctx->t6 = (guint32) gr[14];
  ctx->t7 = (guint32) gr[15];

  ctx->s0 = (guint32) gr[16];
  ctx->s1 = (guint32) gr[17];
  ctx->s2 = (guint32) gr[18];
  ctx->s3 = (guint32) gr[19];
  ctx->s4 = (guint32) gr[20];
  ctx->s5 = (guint32) gr[21];
  ctx->s6 = (guint32) gr[22];
  ctx->s7 = (guint32) gr[23];

  ctx->t8 = (guint32) gr[24];
  ctx->t9 = (guint32) gr[25];

  ctx->k0 = (guint32) gr[26];
  ctx->k1 = (guint32) gr[27];

  ctx->gp = (guint32) gr[28];
  ctx->sp = (guint32) gr[29];
  ctx->fp = (guint32) gr[30];
  ctx->ra = (guint32) gr[31];

  ctx->hi = (guint32) uc->uc_mcontext.mdhi;
  ctx->lo = (guint32) uc->uc_mcontext.mdlo;

  ctx->pc = (guint32) uc->uc_mcontext.pc;
#else
# error FIXME
#endif
}

void
gum_linux_unparse_ucontext (const GumCpuContext * ctx,
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
#elif defined (HAVE_ARM)
  struct sigcontext * sc = &uc->uc_mcontext;

  sc->arm_cpsr = ctx->cpsr;
  if (ctx->pc & 1)
    sc->arm_cpsr |= GUM_PSR_THUMB;
  else
    sc->arm_cpsr &= ~GUM_PSR_THUMB;
  sc->arm_pc = ctx->pc & ~1;
  sc->arm_sp = ctx->sp;

  sc->arm_r8 = ctx->r8;
  sc->arm_r9 = ctx->r9;
  sc->arm_r10 = ctx->r10;
  sc->arm_fp = ctx->r11;
  sc->arm_ip = ctx->r12;

  sc->arm_r0 = ctx->r[0];
  sc->arm_r1 = ctx->r[1];
  sc->arm_r2 = ctx->r[2];
  sc->arm_r3 = ctx->r[3];
  sc->arm_r4 = ctx->r[4];
  sc->arm_r5 = ctx->r[5];
  sc->arm_r6 = ctx->r[6];
  sc->arm_r7 = ctx->r[7];
  sc->arm_lr = ctx->lr;
#elif defined (HAVE_ARM64)
  struct sigcontext * sc = &uc->uc_mcontext;
  gsize i;

  sc->pc = ctx->pc;
  sc->sp = ctx->sp;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    sc->regs[i] = ctx->x[i];
  sc->regs[29] = ctx->fp;
  sc->regs[30] = ctx->lr;
#elif defined (HAVE_MIPS)
  greg_t * gr = uc->uc_mcontext.gregs;

  gr[1] = (guint64) ctx->at;

  gr[2] = (guint64) ctx->v0;
  gr[3] = (guint64) ctx->v1;

  gr[4] = (guint64) ctx->a0;
  gr[5] = (guint64) ctx->a1;
  gr[6] = (guint64) ctx->a2;
  gr[7] = (guint64) ctx->a3;

  gr[8] = (guint64) ctx->t0;
  gr[9] = (guint64) ctx->t1;
  gr[10] = (guint64) ctx->t2;
  gr[11] = (guint64) ctx->t3;
  gr[12] = (guint64) ctx->t4;
  gr[13] = (guint64) ctx->t5;
  gr[14] = (guint64) ctx->t6;
  gr[15] = (guint64) ctx->t7;

  gr[16] = (guint64) ctx->s0;
  gr[17] = (guint64) ctx->s1;
  gr[18] = (guint64) ctx->s2;
  gr[19] = (guint64) ctx->s3;
  gr[20] = (guint64) ctx->s4;
  gr[21] = (guint64) ctx->s5;
  gr[22] = (guint64) ctx->s6;
  gr[23] = (guint64) ctx->s7;

  gr[24] = (guint64) ctx->t8;
  gr[25] = (guint64) ctx->t9;

  gr[26] = (guint64) ctx->k0;
  gr[27] = (guint64) ctx->k1;

  gr[28] = (guint64) ctx->gp;
  gr[29] = (guint64) ctx->sp;
  gr[30] = (guint64) ctx->fp;
  gr[31] = (guint64) ctx->ra;

  uc->uc_mcontext.mdhi = (guint64) ctx->hi;
  uc->uc_mcontext.mdlo = (guint64) ctx->lo;

  uc->uc_mcontext.pc = (guint64) ctx->pc;
#else
# error FIXME
#endif
}

static void
gum_parse_regs (const GumRegs * regs,
                GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  ctx->eip = regs->eip;

  ctx->edi = regs->edi;
  ctx->esi = regs->esi;
  ctx->ebp = regs->ebp;
  ctx->esp = regs->esp;
  ctx->ebx = regs->ebx;
  ctx->edx = regs->edx;
  ctx->ecx = regs->ecx;
  ctx->eax = regs->eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  ctx->rip = regs->rip;

  ctx->r15 = regs->r15;
  ctx->r14 = regs->r14;
  ctx->r13 = regs->r13;
  ctx->r12 = regs->r12;
  ctx->r11 = regs->r11;
  ctx->r10 = regs->r10;
  ctx->r9 = regs->r9;
  ctx->r8 = regs->r8;

  ctx->rdi = regs->rdi;
  ctx->rsi = regs->rsi;
  ctx->rbp = regs->rbp;
  ctx->rsp = regs->rsp;
  ctx->rbx = regs->rbx;
  ctx->rdx = regs->rdx;
  ctx->rcx = regs->rcx;
  ctx->rax = regs->rax;
#elif defined (HAVE_ARM)
  gsize i;

  ctx->cpsr = regs->ARM_cpsr;
  ctx->pc = regs->ARM_pc;
  ctx->sp = regs->ARM_sp;

  ctx->r8 = regs->uregs[8];
  ctx->r9 = regs->uregs[9];
  ctx->r10 = regs->uregs[10];
  ctx->r11 = regs->uregs[11];
  ctx->r12 = regs->uregs[12];

  for (i = 0; i != G_N_ELEMENTS (ctx->r); i++)
    ctx->r[i] = regs->uregs[i];
  ctx->lr = regs->ARM_lr;
#elif defined (HAVE_ARM64)
  gsize i;

  ctx->pc = regs->pc;
  ctx->sp = regs->sp;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    ctx->x[i] = regs->regs[i];
  ctx->fp = regs->regs[29];
  ctx->lr = regs->regs[30];
#elif defined (HAVE_MIPS)
  ctx->at = regs->regs[1];

  ctx->v0 = regs->regs[2];
  ctx->v1 = regs->regs[3];

  ctx->a0 = regs->regs[4];
  ctx->a1 = regs->regs[5];
  ctx->a2 = regs->regs[6];
  ctx->a3 = regs->regs[7];

  ctx->t0 = regs->regs[8];
  ctx->t1 = regs->regs[9];
  ctx->t2 = regs->regs[10];
  ctx->t3 = regs->regs[11];
  ctx->t4 = regs->regs[12];
  ctx->t5 = regs->regs[13];
  ctx->t6 = regs->regs[14];
  ctx->t7 = regs->regs[15];

  ctx->s0 = regs->regs[16];
  ctx->s1 = regs->regs[17];
  ctx->s2 = regs->regs[18];
  ctx->s3 = regs->regs[19];
  ctx->s4 = regs->regs[20];
  ctx->s5 = regs->regs[21];
  ctx->s6 = regs->regs[22];
  ctx->s7 = regs->regs[23];

  ctx->t8 = regs->regs[24];
  ctx->t9 = regs->regs[25];

  ctx->k0 = regs->regs[26];
  ctx->k1 = regs->regs[27];

  ctx->gp = regs->regs[28];
  ctx->sp = regs->regs[29];
  ctx->fp = regs->regs[30];

  ctx->ra = regs->regs[31];

  ctx->hi = regs->hi;
  ctx->lo = regs->lo;

  ctx->pc = regs->cp0_epc;
#else
# error Unsupported architecture
#endif
}

static void
gum_unparse_regs (const GumCpuContext * ctx,
                  GumRegs * regs)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs->eip = ctx->eip;

  regs->edi = ctx->edi;
  regs->esi = ctx->esi;
  regs->ebp = ctx->ebp;
  regs->esp = ctx->esp;
  regs->ebx = ctx->ebx;
  regs->edx = ctx->edx;
  regs->ecx = ctx->ecx;
  regs->eax = ctx->eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs->rip = ctx->rip;

  regs->r15 = ctx->r15;
  regs->r14 = ctx->r14;
  regs->r13 = ctx->r13;
  regs->r12 = ctx->r12;
  regs->r11 = ctx->r11;
  regs->r10 = ctx->r10;
  regs->r9 = ctx->r9;
  regs->r8 = ctx->r8;

  regs->rdi = ctx->rdi;
  regs->rsi = ctx->rsi;
  regs->rbp = ctx->rbp;
  regs->rsp = ctx->rsp;
  regs->rbx = ctx->rbx;
  regs->rdx = ctx->rdx;
  regs->rcx = ctx->rcx;
  regs->rax = ctx->rax;
#elif defined (HAVE_ARM)
  gsize i;

  regs->ARM_cpsr = ctx->cpsr;
  regs->ARM_pc = ctx->pc;
  regs->ARM_sp = ctx->sp;

  regs->uregs[8] = ctx->r8;
  regs->uregs[9] = ctx->r9;
  regs->uregs[10] = ctx->r10;
  regs->uregs[11] = ctx->r11;
  regs->uregs[12] = ctx->r12;

  for (i = 0; i != G_N_ELEMENTS (ctx->r); i++)
    regs->uregs[i] = ctx->r[i];
  regs->ARM_lr = ctx->lr;
#elif defined (HAVE_ARM64)
  gsize i;

  regs->pc = ctx->pc;
  regs->sp = ctx->sp;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    regs->regs[i] = ctx->x[i];
  regs->regs[29] = ctx->fp;
  regs->regs[30] = ctx->lr;
#elif defined (HAVE_MIPS)
  regs->regs[1] = ctx->at;

  regs->regs[2] = ctx->v0;
  regs->regs[3] = ctx->v1;

  regs->regs[4] = ctx->a0;
  regs->regs[5] = ctx->a1;
  regs->regs[6] = ctx->a2;
  regs->regs[7] = ctx->a3;

  regs->regs[8] = ctx->t0;
  regs->regs[9] = ctx->t1;
  regs->regs[10] = ctx->t2;
  regs->regs[11] = ctx->t3;
  regs->regs[12] = ctx->t4;
  regs->regs[13] = ctx->t5;
  regs->regs[14] = ctx->t6;
  regs->regs[15] = ctx->t7;

  regs->regs[16] = ctx->s0;
  regs->regs[17] = ctx->s1;
  regs->regs[18] = ctx->s2;
  regs->regs[19] = ctx->s3;
  regs->regs[20] = ctx->s4;
  regs->regs[21] = ctx->s5;
  regs->regs[22] = ctx->s6;
  regs->regs[23] = ctx->s7;

  regs->regs[24] = ctx->t8;
  regs->regs[25] = ctx->t9;

  regs->regs[26] = ctx->k0;
  regs->regs[27] = ctx->k1;

  regs->regs[28] = ctx->gp;
  regs->regs[29] = ctx->sp;
  regs->regs[30] = ctx->fp;

  regs->regs[31] = ctx->ra;

  regs->hi = ctx->hi;
  regs->lo = ctx->lo;

  regs->cp0_epc = ctx->pc;
#else
# error Unsupported architecture
#endif
}

static gboolean
gum_thread_read_state (GumThreadId tid,
                       GumThreadState * state)
{
  gboolean success = FALSE;
  gchar * path, * info = NULL;

  path = g_strdup_printf ("/proc/self/task/%" G_GSIZE_FORMAT "/stat", tid);
  if (g_file_get_contents (path, &info, NULL, NULL))
  {
    gchar * p;

    p = strrchr (info, ')') + 2;

    *state = gum_thread_state_from_proc_status_character (*p);
    success = TRUE;
  }

  g_free (info);
  g_free (path);

  return success;
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

static gssize
gum_get_regs (pid_t pid,
              GumRegs * regs)
{
  if (gum_is_regset_supported)
  {
    struct iovec io = {
      .iov_base = regs,
      .iov_len = sizeof (GumRegs)
    };
    gssize ret = gum_libc_ptrace (PTRACE_GETREGSET, pid,
        GSIZE_TO_POINTER (NT_PRSTATUS), &io);
    if (ret >= 0)
      return ret;
    else if (ret == -EPERM || ret == -ESRCH)
      return ret;
    else
      gum_is_regset_supported = FALSE;
  }

  return gum_libc_ptrace (PTRACE_GETREGS, pid, NULL, regs);
}

static gssize
gum_set_regs (pid_t pid,
              const GumRegs * regs)
{
  if (gum_is_regset_supported)
  {
    struct iovec io = {
      .iov_base = (void *) regs,
      .iov_len = sizeof (GumRegs)
    };
    gssize ret = gum_libc_ptrace (PTRACE_SETREGSET, pid,
        GSIZE_TO_POINTER (NT_PRSTATUS), &io);
    if (ret >= 0)
      return ret;
    else if (ret == -EPERM || ret == -ESRCH)
      return ret;
    else
      gum_is_regset_supported = FALSE;
  }

  return gum_libc_ptrace (PTRACE_SETREGS, pid, NULL, (gpointer) regs);
}

static gssize
gum_libc_clone (GumCloneFunc child_func,
                gpointer child_stack,
                gint flags,
                gpointer arg,
                pid_t * parent_tidptr,
                GumUserDesc * tls,
                pid_t * child_tidptr)
{
  gssize result;
  gpointer * child_sp = child_stack;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  *(--child_sp) = arg;
  *(--child_sp) = child_func;

  asm volatile (
      "pushl %%eax\n\t"
      "pushl %%ebx\n\t"
      "pushl %%ecx\n\t"
      "pushl %%edx\n\t"
      "pushl %%esi\n\t"
      "pushl %%edi\n\t"
      "movl %[clone_syscall], %%eax\n\t"
      "movl %[flags], %%ebx\n\t"
      "movl %[child_sp], %%ecx\n\t"
      "movl %[parent_tidptr], %%edx\n\t"
      "movl %[tls], %%esi\n\t"
      "movl %[child_tidptr], %%edi\n\t"
      "int $0x80\n\t"
      "test %%eax, %%eax\n\t"
      "jnz 1f\n\t"

      /* child: */
      "popl %%eax\n\t"
      "call *%%eax\n\t"
      "movl %%eax, %%ebx\n\t"
      "movl %[exit_syscall], %%eax\n\t"
      "int $0x80\n\t"

      /* parent: */
      "1:\n\t"
      "movl %%eax, %[result]\n\t"
      "popl %%edi\n\t"
      "popl %%esi\n\t"
      "popl %%edx\n\t"
      "popl %%ecx\n\t"
      "popl %%ebx\n\t"
      "popl %%eax\n\t"
      : [result]"=m" (result)
      : [clone_syscall]"i" (__NR_clone),
        [flags]"m" (flags),
        [child_sp]"m" (child_sp),
        [parent_tidptr]"m" (parent_tidptr),
        [tls]"m" (tls),
        [child_tidptr]"m" (child_tidptr),
        [exit_syscall]"i" (__NR_exit)
      : "esp", "cc", "memory"
  );
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  *(--child_sp) = arg;
  *(--child_sp) = child_func;

  asm volatile (
      "pushq %%rax\n\t"
      "pushq %%rdi\n\t"
      "pushq %%rsi\n\t"
      "pushq %%rdx\n\t"
      "pushq %%r10\n\t"
      "pushq %%r8\n\t"
      "pushq %%rcx\n\t"
      "pushq %%r11\n\t"
      "movq %[clone_syscall], %%rax\n\t"
      "movq %[flags], %%rdi\n\t"
      "movq %[child_sp], %%rsi\n\t"
      "movq %[parent_tidptr], %%rdx\n\t"
      "movq %[child_tidptr], %%r10\n\t"
      "movq %[tls], %%r8\n\t"
      "syscall\n\t"
      "test %%rax, %%rax\n\t"
      "jnz 1f\n\t"

      /* child: */
      "popq %%rax\n\t"
      "popq %%rdi\n\t"
      "call *%%rax\n\t"
      "movq %%rax, %%rdi\n\t"
      "movq %[exit_syscall], %%rax\n\t"
      "syscall\n\t"

      /* parent: */
      "1:\n\t"
      "movq %%rax, %[result]\n\t"
      "popq %%r11\n\t"
      "popq %%rcx\n\t"
      "popq %%r8\n\t"
      "popq %%r10\n\t"
      "popq %%rdx\n\t"
      "popq %%rsi\n\t"
      "popq %%rdi\n\t"
      "popq %%rax\n\t"
      : [result]"=g" (result)
      : [clone_syscall]"g" (__NR_clone),
        [flags]"g" (flags),
        [child_sp]"g" (child_sp),
        [parent_tidptr]"g" (parent_tidptr),
        [child_tidptr]"g" (child_tidptr),
        [tls]"g" (tls),
        [exit_syscall]"i" (__NR_exit)
      : "rax", "rdi", "rsi", "rdx", "r10", "r8", "rcx", "r11", "rsp", "cc",
        "memory"
  );
#elif defined (HAVE_ARM)
  *(--child_sp) = child_func;
  *(--child_sp) = arg;

  const gpointer args[] = {
    GSIZE_TO_POINTER (flags),
    child_sp,
    parent_tidptr,
    tls,
    child_tidptr
  };
  const gpointer * next_args = args + G_N_ELEMENTS (args);

  asm volatile (
      "push {r0, r1, r2, r3, r4, r7}\n\t"
      "mov r7, %[clone_syscall]\n\t"
      "ldmdb %[next_args]!, {r0, r1, r2, r3, r4}\n\t"
      "swi 0x0\n\t"
      "cmp r0, #0\n\t"
      "bne 1f\n\t"

      /* child: */
      "pop {r0, r1}\n\t"
      "blx r1\n\t"
      "mov r7, %[exit_syscall]\n\t"
      "swi 0x0\n\t"

      /* parent: */
      "1:\n\t"
      "mov %[result], r0\n\t"
      "pop {r0, r1, r2, r3, r4, r7}\n\t"
      : [next_args]"+r" (next_args),
        [result]"=r" (result)
      : [clone_syscall]"i" (__NR_clone),
        [exit_syscall]"i" (__NR_exit)
      : "r0", "r1", "r2", "r3", "r4", "r7", "sp", "cc", "memory"
  );
#elif defined (HAVE_ARM64)
  *(--child_sp) = child_func;
  *(--child_sp) = arg;

  asm volatile (
      "stp x0, x1, [sp, #-16]!\n\t"
      "stp x2, x3, [sp, #-16]!\n\t"
      "stp x4, x8, [sp, #-16]!\n\t"
      "mov x8, %x[clone_syscall]\n\t"
      "mov x0, %x[flags]\n\t"
      "mov x1, %x[child_sp]\n\t"
      "mov x2, %x[parent_tidptr]\n\t"
      "mov x3, %x[tls]\n\t"
      "mov x4, %x[child_tidptr]\n\t"
      "svc 0x0\n\t"
      "cbnz x0, 1f\n\t"

      /* child: */
      "ldp x0, x1, [sp], #16\n\t"
      "blr x1\n\t"
      "mov x8, %x[exit_syscall]\n\t"
      "svc 0x0\n\t"

      /* parent: */
      "1:\n\t"
      "mov %x[result], x0\n\t"
      "ldp x4, x8, [sp], #16\n\t"
      "ldp x2, x3, [sp], #16\n\t"
      "ldp x0, x1, [sp], #16\n\t"
      : [result]"=r" (result)
      : [clone_syscall]"i" (__NR_clone),
        [flags]"r" ((gsize) flags),
        [child_sp]"r" (child_sp),
        [parent_tidptr]"r" (parent_tidptr),
        [tls]"r" (tls),
        [child_tidptr]"r" (child_tidptr),
        [exit_syscall]"i" (__NR_exit)
      : "x0", "x1", "x2", "x3", "x4", "x8", "sp", "memory"
  );
#endif

  return result;
}

static gssize
gum_libc_read (gint fd,
               gpointer buf,
               gsize count)
{
  return gum_libc_syscall_3 (__NR_read, fd, GPOINTER_TO_SIZE (buf), count);
}

static gssize
gum_libc_write (gint fd,
                gconstpointer buf,
                gsize count)
{
  return gum_libc_syscall_3 (__NR_write, fd, GPOINTER_TO_SIZE (buf), count);
}

static gssize
gum_libc_ptrace (gsize request,
                 pid_t pid,
                 gpointer address,
                 gpointer data)
{
  return gum_libc_syscall_4 (__NR_ptrace, request, pid,
      GPOINTER_TO_SIZE (address), GPOINTER_TO_SIZE (data));
}

static gssize
gum_libc_syscall_4 (gsize n,
                    gsize a,
                    gsize b,
                    gsize c,
                    gsize d)
{
  gsize result;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  asm volatile (
      "pushl %%eax\n\t"
      "pushl %%ebx\n\t"
      "pushl %%ecx\n\t"
      "pushl %%edx\n\t"
      "pushl %%esi\n\t"
      "movl %[n], %%eax\n\t"
      "movl %[a], %%ebx\n\t"
      "movl %[b], %%ecx\n\t"
      "movl %[c], %%edx\n\t"
      "movl %[d], %%esi\n\t"
      "int $0x80\n\t"
      "movl %%eax, %[result]\n\t"
      "popl %%esi\n\t"
      "popl %%edx\n\t"
      "popl %%ecx\n\t"
      "popl %%ebx\n\t"
      "popl %%eax\n\t"
      : [result]"=r" (result)
      : [n]"g" (n),
        [a]"g" (a),
        [b]"g" (b),
        [c]"g" (c),
        [d]"g" (d)
      : "eax", "ecx", "edx", "esi", "esp", "memory"
  );
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  asm volatile (
      "pushq %%rax\n\t"
      "pushq %%rdi\n\t"
      "pushq %%rsi\n\t"
      "pushq %%rdx\n\t"
      "pushq %%r10\n\t"
      "pushq %%rcx\n\t"
      "pushq %%r11\n\t"
      "movq %[n], %%rax\n\t"
      "movq %[a], %%rdi\n\t"
      "movq %[b], %%rsi\n\t"
      "movq %[c], %%rdx\n\t"
      "movq %[d], %%r10\n\t"
      "syscall\n\t"
      "movq %%rax, %[result]\n\t"
      "popq %%r11\n\t"
      "popq %%rcx\n\t"
      "popq %%r10\n\t"
      "popq %%rdx\n\t"
      "popq %%rsi\n\t"
      "popq %%rdi\n\t"
      "popq %%rax\n\t"
      : [result]"=r" (result)
      : [n]"g" (n),
        [a]"g" (a),
        [b]"g" (b),
        [c]"g" (c),
        [d]"g" (d)
      : "rax", "rdi", "rsi", "rdx", "r10", "rcx", "r11", "rsp", "memory"
  );
#elif defined (HAVE_ARM)
  const gsize args[] = { a, b, c, d, n };
  const gsize * next_args = args + G_N_ELEMENTS (args);

  asm volatile (
      "push {r0, r1, r2, r3, r7}\n\t"
      "ldmdb %[next_args]!, {r0, r1, r2, r3, r7}\n\t"
      "swi 0x0\n\t"
      "mov %[result], r0\n\t"
      "pop {r0, r1, r2, r3, r7}\n\t"
      : [next_args]"+r" (next_args),
        [result]"=r" (result)
      :
      : "r0", "r1", "r2", "r3", "r7", "sp", "memory"
  );
#elif defined (HAVE_ARM64)
  asm volatile (
      "stp x0, x1, [sp, #-16]!\n\t"
      "stp x2, x3, [sp, #-16]!\n\t"
      "stp x4, x8, [sp, #-16]!\n\t"
      "mov x8, %x[n]\n\t"
      "mov x0, %x[a]\n\t"
      "mov x1, %x[b]\n\t"
      "mov x2, %x[c]\n\t"
      "mov x3, %x[d]\n\t"
      "svc 0x0\n\t"
      "mov %x[result], x0\n\t"
      "ldp x4, x8, [sp], #16\n\t"
      "ldp x2, x3, [sp], #16\n\t"
      "ldp x0, x1, [sp], #16\n\t"
      : [result]"=r" (result)
      : [n]"i" (n),
        [a]"r" (a),
        [b]"r" (b),
        [c]"r" (c),
        [d]"r" (d)
      : "x0", "x1", "x2", "x3", "x4", "x8", "sp", "memory"
  );
#endif

  return result;
}

#if defined (HAVE_MIPS)
static int
getcontext (ucontext_t * ucp)
{
   g_assert_not_reached ();
}

static int
setcontext (const ucontext_t * ucp)
{
  g_assert_not_reached ();
}
#endif
