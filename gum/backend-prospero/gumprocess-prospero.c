/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-prospero.h"

#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>

#define GUM_UCONTEXT_SIZE 1216
#define GUM_SYS_PTRACE 26
#define GUM_DEBUGGER_AUTHID 0x4800000000010003

#define GUM_PROC_THREAD_LIST_OFFSET 0x10
#define GUM_THREAD_LINK_OFFSET      0x10
#define GUM_THREAD_ID_OFFSET        0x9c
#define GUM_THREAD_NAME_OFFSET      0x294
#define GUM_MAX_THREAD_NAME         20

typedef struct _GumProsperoUcontext GumProsperoUcontext;
typedef struct _GumFindThreadContext GumFindThreadContext;

struct _GumProsperoUcontext
{
  guint64 reserved_a[9];
  guint64 rsp;
  guint64 rip;
  guint64 reserved_b[5];
  guint64 rbx;
  guint64 rbp;
  guint64 reserved_c[2];
  guint64 r12;
  guint64 r13;
  guint64 r14;
  guint64 r15;
};

struct _GumFindThreadContext
{
  GumThreadId id;
  GumThreadDetails * details;
};

static gboolean gum_store_matching_thread (const GumThreadDetails * details,
    gpointer user_data);
static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static void gum_parse_ucontext (const ucontext_t * uc, GumCpuContext * ctx);
static void gum_unparse_ucontext (const GumCpuContext * ctx, ucontext_t * uc);

int
_gum_prospero_ptrace (int request,
                      pid_t pid,
                      caddr_t addr,
                      int data)
{
  int result;
  pid_t self = getpid ();
  guint64 saved_authid;
  guint8 saved_caps[16], all_caps[16];

  saved_authid = kernel_get_ucred_authid (self);
  kernel_get_ucred_caps (self, saved_caps);

  memset (all_caps, 0xff, sizeof (all_caps));
  kernel_set_ucred_authid (self, GUM_DEBUGGER_AUTHID);
  kernel_set_ucred_caps (self, all_caps);

  result = syscall (GUM_SYS_PTRACE, request, pid, addr, data);

  kernel_set_ucred_authid (self, saved_authid);
  kernel_set_ucred_caps (self, saved_caps);

  return result;
}

gboolean
_gum_prospero_modify_current_thread (GumThreadId thread_id,
                                     GumModifyThreadFunc func,
                                     gpointer user_data)
{
  guint8 storage[GUM_UCONTEXT_SIZE] __attribute__ ((aligned (16)));
  ucontext_t * uc = (ucontext_t *) storage;
  volatile gboolean modified = FALSE;

  getcontext (uc);
  if (!modified)
  {
    GumCpuContext cpu_context;

    gum_parse_ucontext (uc, &cpu_context);
    func (thread_id, &cpu_context, user_data);
    gum_unparse_ucontext (&cpu_context, uc);

    modified = TRUE;
    setcontext (uc);
  }

  return TRUE;
}

GumThreadDetails *
_gum_prospero_find_thread_by_id (GumThreadId thread_id,
                                 GumThreadFlags flags)
{
  GumFindThreadContext ctx = { thread_id, NULL };

  _gum_prospero_enumerate_threads (gum_store_matching_thread, &ctx, flags);

  return ctx.details;
}

static gboolean
gum_store_matching_thread (const GumThreadDetails * details,
                           gpointer user_data)
{
  GumFindThreadContext * ctx = user_data;

  if (details->id != ctx->id)
    return TRUE;

  ctx->details = gum_thread_details_copy (details);

  return FALSE;
}

void
_gum_prospero_enumerate_threads (GumFoundThreadFunc func,
                                 gpointer user_data,
                                 GumThreadFlags flags)
{
  intptr_t proc, td;

  proc = kernel_get_proc (getpid ());

  for (td = kernel_getlong (proc + GUM_PROC_THREAD_LIST_OFFSET);
      td != 0;
      td = kernel_getlong (td + GUM_THREAD_LINK_OFFSET))
  {
    GumThreadDetails thread = { 0, };
    gchar name[GUM_MAX_THREAD_NAME];

    thread.id = kernel_getint (td + GUM_THREAD_ID_OFFSET);

    if ((flags & GUM_THREAD_FLAGS_NAME) != 0)
    {
      kernel_copyout (td + GUM_THREAD_NAME_OFFSET, name, sizeof (name));
      if (name[0] != '\0')
      {
        thread.name = name;
        thread.flags |= GUM_THREAD_FLAGS_NAME;
      }
    }

    if ((flags & GUM_THREAD_FLAGS_CPU_CONTEXT) != 0)
    {
      if (!gum_process_modify_thread (thread.id, gum_store_cpu_context,
            &thread.cpu_context, GUM_MODIFY_THREAD_FLAGS_ABORT_SAFELY))
        continue;
      thread.flags |= GUM_THREAD_FLAGS_CPU_CONTEXT;
    }

    if (!func (&thread, user_data))
      break;
  }
}

static void
gum_store_cpu_context (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  memcpy (user_data, cpu_context, sizeof (GumCpuContext));
}

static void
gum_parse_ucontext (const ucontext_t * uc,
                    GumCpuContext * ctx)
{
  const GumProsperoUcontext * mc = (const GumProsperoUcontext *) uc;

  ctx->rip = mc->rip;
  ctx->rsp = mc->rsp;
  ctx->rbp = mc->rbp;
  ctx->rbx = mc->rbx;
  ctx->r12 = mc->r12;
  ctx->r13 = mc->r13;
  ctx->r14 = mc->r14;
  ctx->r15 = mc->r15;

  ctx->rax = 0;
  ctx->rcx = 0;
  ctx->rdx = 0;
  ctx->rsi = 0;
  ctx->rdi = 0;
  ctx->r8 = 0;
  ctx->r9 = 0;
  ctx->r10 = 0;
  ctx->r11 = 0;

  ctx->xmm = NULL;
}

static void
gum_unparse_ucontext (const GumCpuContext * ctx,
                      ucontext_t * uc)
{
  GumProsperoUcontext * mc = (GumProsperoUcontext *) uc;

  mc->rip = ctx->rip;
  mc->rsp = ctx->rsp;
  mc->rbp = ctx->rbp;
  mc->rbx = ctx->rbx;
  mc->r12 = ctx->r12;
  mc->r13 = ctx->r13;
  mc->r14 = ctx->r14;
  mc->r15 = ctx->r15;
}
