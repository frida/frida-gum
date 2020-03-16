/*
 * Copyright (C) 2015-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumexceptorbackend.h"

#include "guminterceptor.h"
#ifdef HAVE_DARWIN
# include "backend-darwin/gumdarwin.h"
#endif
#ifdef HAVE_LINUX
# include "backend-linux/gumlinux.h"
#endif
#ifdef HAVE_QNX
# include "backend-qnx/gumqnx.h"
#endif

#include <capstone.h>
#include <signal.h>
#include <stdlib.h>
#ifdef HAVE_QNX
# include <sys/debug.h>
# include <unix.h>
#endif

struct _GumExceptorBackend
{
  GObject parent;

  gboolean disposed;

  GumExceptionHandler handler;
  gpointer handler_data;

  struct sigaction ** old_handlers;
  gint num_old_handlers;

  GumInterceptor * interceptor;
};

static void gum_exceptor_backend_dispose (GObject * object);

static void gum_exceptor_backend_attach (GumExceptorBackend * self);
static void gum_exceptor_backend_detach (GumExceptorBackend * self);
static void gum_exceptor_backend_detach_handler (GumExceptorBackend * self,
    int sig);
static sig_t gum_exceptor_backend_replacement_signal (int sig, sig_t handler);
static int gum_exceptor_backend_replacement_sigaction (int sig,
    const struct sigaction * act, struct sigaction * oact);
static void gum_exceptor_backend_on_signal (int sig, siginfo_t * siginfo,
    void * context);
static void gum_exceptor_backend_abort (GumExceptorBackend * self,
    GumExceptionDetails * details);

static gboolean gum_is_signal_handler_chainable (sig_t handler);

static gpointer gum_resolve_symbol (const gchar * symbol_name,
    const gchar ** module_candidates);
static gpointer gum_try_resolve_symbol (const gchar * symbol_name,
    const gchar ** module_candidates);

static void gum_parse_context (gconstpointer context,
    GumCpuContext * ctx);
static void gum_unparse_context (const GumCpuContext * ctx,
    gpointer context);

static GumMemoryOperation gum_infer_memory_operation (gconstpointer address,
    GumCpuContext * context);
static cs_insn * gum_disassemble_instruction_at (gconstpointer address,
    GumCpuContext * context);
#if defined (HAVE_I386)
static GumMemoryOperation gum_infer_x86_memory_operation (cs_insn * insn);
#elif defined (HAVE_ARM)
static GumMemoryOperation gum_infer_arm_memory_operation (cs_insn * insn);
#elif defined (HAVE_ARM64)
static GumMemoryOperation gum_infer_arm64_memory_operation (
    cs_insn * insn);
#endif

G_DEFINE_TYPE (GumExceptorBackend, gum_exceptor_backend, G_TYPE_OBJECT)

static GumExceptorBackend * the_backend = NULL;

static sighandler_t (* gum_original_signal) (int signum, sighandler_t handler);
static int (* gum_original_sigaction) (int signum, const struct sigaction * act,
    struct sigaction * oldact);

void
_gum_exceptor_backend_prepare_to_fork (void)
{
}

void
_gum_exceptor_backend_recover_from_fork_in_parent (void)
{
}

void
_gum_exceptor_backend_recover_from_fork_in_child (void)
{
}

static void
gum_exceptor_backend_class_init (GumExceptorBackendClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  const gchar * libc;
  gchar * libdir, * pthread;
  const gchar * module_candidates[3];

  object_class->dispose = gum_exceptor_backend_dispose;

  libc = gum_process_query_libc_name ();

#ifdef HAVE_ANDROID
  libdir = NULL;
  pthread = NULL;

  module_candidates[0] = libc;
  module_candidates[1] = NULL;

  gum_original_signal = gum_try_resolve_symbol ("signal", module_candidates);
  if (gum_original_signal == NULL)
    gum_original_signal = gum_resolve_symbol ("bsd_signal", module_candidates);
#else
  libdir = g_path_get_dirname (libc);
  pthread = g_build_filename (libdir, "libpthread.so.0", NULL);

  module_candidates[0] = pthread;
  module_candidates[1] = libc;
  module_candidates[2] = NULL;

  gum_original_signal = gum_resolve_symbol ("signal", module_candidates);
#endif

  gum_original_sigaction = gum_resolve_symbol ("sigaction", module_candidates);

  g_free (pthread);
  g_free (libdir);
}

static void
gum_exceptor_backend_init (GumExceptorBackend * self)
{
  self->interceptor = gum_interceptor_obtain ();

  the_backend = self;
}

static void
gum_exceptor_backend_dispose (GObject * object)
{
  GumExceptorBackend * self = GUM_EXCEPTOR_BACKEND (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    gum_exceptor_backend_detach (self);

    g_object_unref (self->interceptor);
    self->interceptor = NULL;

    the_backend = NULL;
  }

  G_OBJECT_CLASS (gum_exceptor_backend_parent_class)->dispose (object);
}

GumExceptorBackend *
gum_exceptor_backend_new (GumExceptionHandler handler,
                          gpointer user_data)
{
  GumExceptorBackend * backend;

  backend = g_object_new (GUM_TYPE_EXCEPTOR_BACKEND, NULL);
  backend->handler = handler;
  backend->handler_data = user_data;

  gum_exceptor_backend_attach (backend);

  return backend;
}

static void
gum_exceptor_backend_attach (GumExceptorBackend * self)
{
  GumInterceptor * interceptor = self->interceptor;
  const gint handled_signals[] = {
    SIGABRT,
    SIGSEGV,
    SIGBUS,
    SIGILL,
    SIGFPE,
    SIGTRAP,
    SIGSYS,
  };
  gint highest, i;
  struct sigaction action;

  highest = 0;
  for (i = 0; i != G_N_ELEMENTS (handled_signals); i++)
    highest = MAX (handled_signals[i], highest);
  g_assert (highest > 0);
  self->num_old_handlers = highest + 1;
  self->old_handlers = g_new0 (struct sigaction *, self->num_old_handlers);

  action.sa_sigaction = gum_exceptor_backend_on_signal;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_SIGINFO | SA_NODEFER;
  for (i = 0; i != G_N_ELEMENTS (handled_signals); i++)
  {
    gint sig = handled_signals[i];
    struct sigaction * old_handler;

    old_handler = g_slice_new0 (struct sigaction);
    self->old_handlers[sig] = old_handler;
    gum_original_sigaction (sig, &action, old_handler);
  }

  gum_interceptor_begin_transaction (interceptor);

  gum_interceptor_replace (interceptor, gum_original_signal,
      gum_exceptor_backend_replacement_signal, self);
  gum_interceptor_replace (interceptor, gum_original_sigaction,
      gum_exceptor_backend_replacement_sigaction, self);

  gum_interceptor_end_transaction (interceptor);
}

static void
gum_exceptor_backend_detach (GumExceptorBackend * self)
{
  GumInterceptor * interceptor = self->interceptor;
  gint i;

  gum_interceptor_begin_transaction (interceptor);

  gum_interceptor_revert (interceptor, gum_original_signal);
  gum_interceptor_revert (interceptor, gum_original_sigaction);

  gum_interceptor_end_transaction (interceptor);

  for (i = 0; i != self->num_old_handlers; i++)
    gum_exceptor_backend_detach_handler (self, i);
  g_free (self->old_handlers);
  self->old_handlers = NULL;
  self->num_old_handlers = 0;
}

static void
gum_exceptor_backend_detach_handler (GumExceptorBackend * self,
                                     int sig)
{
  struct sigaction * old_handler;

  old_handler = self->old_handlers[sig];
  if (old_handler == NULL)
    return;

  self->old_handlers[sig] = NULL;
  gum_original_sigaction (sig, old_handler, NULL);
  g_slice_free (struct sigaction, old_handler);
}

static struct sigaction *
gum_exceptor_backend_get_old_handler (GumExceptorBackend * self,
                                      gint sig)
{
  if (sig < 0 || sig >= self->num_old_handlers)
    return NULL;

  return self->old_handlers[sig];
}

static sig_t
gum_exceptor_backend_replacement_signal (int sig,
                                         sig_t handler)
{
  GumExceptorBackend * self;
  GumInvocationContext * ctx;
  struct sigaction * old_handler;
  sig_t result;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_data (ctx));

  old_handler = gum_exceptor_backend_get_old_handler (self, sig);
  if (old_handler == NULL)
    return gum_original_signal (sig, handler);

  result = ((old_handler->sa_flags & SA_SIGINFO) == 0)
      ? old_handler->sa_handler
      : SIG_DFL;

  old_handler->sa_handler = handler;
  old_handler->sa_flags &= ~SA_SIGINFO;

  return result;
}

static int
gum_exceptor_backend_replacement_sigaction (int sig,
                                            const struct sigaction * act,
                                            struct sigaction * oact)
{
  GumExceptorBackend * self;
  GumInvocationContext * ctx;
  struct sigaction * old_handler;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_data (ctx));

  old_handler = gum_exceptor_backend_get_old_handler (self, sig);
  if (old_handler == NULL)
    return gum_original_sigaction (sig, act, oact);

  if (oact != NULL)
    *oact = *old_handler;
  if (act != NULL)
    *old_handler = *act;

  return 0;
}

static void
gum_exceptor_backend_on_signal (int sig,
                                siginfo_t * siginfo,
                                void * context)
{
  GumExceptorBackend * self = the_backend;
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;
  struct sigaction * action;

  action = self->old_handlers[sig];

  ed.thread_id = gum_process_get_current_thread_id ();

  switch (sig)
  {
    case SIGABRT:
      ed.type = GUM_EXCEPTION_ABORT;
      break;
    case SIGSEGV:
    case SIGBUS:
      ed.type = GUM_EXCEPTION_ACCESS_VIOLATION;
      break;
    case SIGILL:
      ed.type = GUM_EXCEPTION_ILLEGAL_INSTRUCTION;
      break;
    case SIGFPE:
      ed.type = GUM_EXCEPTION_ARITHMETIC;
      break;
    case SIGTRAP:
      ed.type = GUM_EXCEPTION_BREAKPOINT;
      break;
    default:
      ed.type = GUM_EXCEPTION_SYSTEM;
      break;
  }

  gum_parse_context (context, cpu_context);
  ed.native_context = context;

#if defined (HAVE_I386)
  ed.address = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  ed.address = GSIZE_TO_POINTER (cpu_context->pc);
#elif defined (HAVE_MIPS)
  ed.address = GSIZE_TO_POINTER (cpu_context->pc);
#else
# error Unsupported architecture
#endif

  switch (sig)
  {
    case SIGSEGV:
    case SIGBUS:
      if (siginfo->si_addr == ed.address)
        md->operation = GUM_MEMOP_EXECUTE;
      else
        md->operation = gum_infer_memory_operation (ed.address, cpu_context);
      md->address = siginfo->si_addr;
      break;
    default:
      md->operation = GUM_MEMOP_INVALID;
      md->address = NULL;
      break;
  }

  if (action == NULL)
    gum_exceptor_backend_abort (self, &ed);

  if (self->handler (&ed, self->handler_data))
  {
    gum_unparse_context (cpu_context, context);
    return;
  }

  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    void (* old_sigaction) (int, siginfo_t *, void *) = action->sa_sigaction;

    if (old_sigaction != NULL)
      old_sigaction (sig, siginfo, context);
    else
      goto panic;
  }
  else
  {
    void (* old_handler) (int) = action->sa_handler;

    if (gum_is_signal_handler_chainable (old_handler))
      old_handler (sig);
    else if (action->sa_handler != SIG_IGN)
      goto panic;
  }

  if (sig == SIGABRT)
    goto panic;

  return;

panic:
  gum_exceptor_backend_detach_handler (self, sig);
}

static void
gum_exceptor_backend_abort (GumExceptorBackend * self,
                            GumExceptionDetails * details)
{
  /* TODO: should we create a backtrace and log it? */
  abort ();
}

static gboolean
gum_is_signal_handler_chainable (sig_t handler)
{
  return handler != SIG_DFL && handler != SIG_IGN && handler != SIG_ERR;
}

static gpointer
gum_resolve_symbol (const gchar * symbol_name,
                    const gchar ** module_candidates)
{
  gpointer result;

  result = gum_try_resolve_symbol (symbol_name, module_candidates);
  if (result == NULL)
    goto panic;

  return result;

panic:
  {
    g_critical ("Unable to locate %s(); please file a bug", symbol_name);
    g_abort ();
  }
}

static gpointer
gum_try_resolve_symbol (const gchar * symbol_name,
                        const gchar ** module_candidates)
{
  const gchar ** cur, * module_name;

  for (cur = module_candidates; (module_name = *cur) != NULL; cur++)
  {
    GumAddress address;

    address = gum_module_find_export_by_name (module_name, symbol_name);
    if (address != 0)
      return GSIZE_TO_POINTER (address);
  }

  return NULL;
}

#if defined (HAVE_DARWIN)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_darwin_parse_native_thread_state (&uc->uc_mcontext->__ss, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_darwin_unparse_native_thread_state (ctx, &uc->uc_mcontext->__ss);
}

#elif defined (HAVE_LINUX)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_linux_parse_ucontext (uc, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_linux_unparse_ucontext (ctx, uc);
}

#elif defined (HAVE_QNX)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_qnx_parse_ucontext (uc, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_qnx_unparse_ucontext (ctx, uc);
}

#endif

static GumMemoryOperation
gum_infer_memory_operation (gconstpointer address,
                            GumCpuContext * context)
{
  GumMemoryOperation op;
  cs_insn * insn;

  insn = gum_disassemble_instruction_at (address, context);
  if (insn == NULL)
    return GUM_MEMOP_READ;

#if defined (HAVE_I386)
  op = gum_infer_x86_memory_operation (insn);
#elif defined (HAVE_ARM)
  op = gum_infer_arm_memory_operation (insn);
#elif defined (HAVE_ARM64)
  op = gum_infer_arm64_memory_operation (insn);
#else
  op = GUM_MEMOP_READ;
#endif

  cs_free (insn, 1);

  return op;
}

static cs_insn *
gum_disassemble_instruction_at (gconstpointer address,
                                GumCpuContext * context)
{
  cs_insn * insn = NULL;
  csh capstone;
  cs_err err;

#if defined (HAVE_I386)
  err = cs_open (CS_ARCH_X86, GUM_CPU_MODE, &capstone);
#elif defined (HAVE_ARM)
  if (context->cpsr & ARM_GRP_THUMB)
    err = cs_open (CS_ARCH_ARM, CS_MODE_THUMB, &capstone);
  else
    err = cs_open (CS_ARCH_ARM, CS_MODE_ARM, &capstone);
#elif defined (HAVE_ARM64)
  err = cs_open (CS_ARCH_ARM64, GUM_DEFAULT_CS_ENDIAN, &capstone);
#else
  return NULL;
#endif

  if (err != CS_ERR_OK)
    return NULL;

  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  cs_disasm (capstone, address, 16, GPOINTER_TO_SIZE (address), 1, &insn);
  cs_close (&capstone);

  return insn;
}

#if defined (HAVE_I386)

static GumMemoryOperation
gum_infer_x86_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case X86_INS_CLI:
    case X86_INS_STI:
    case X86_INS_CLC:
    case X86_INS_STC:
    case X86_INS_CLAC:
    case X86_INS_CLGI:
    case X86_INS_CLTS:
    case X86_INS_CLWB:
    case X86_INS_STAC:
    case X86_INS_STGI:
    case X86_INS_CPUID:
    case X86_INS_MOVNTQ:
    case X86_INS_MOVNTDQA:
    case X86_INS_MOVNTDQ:
    case X86_INS_MOVNTI:
    case X86_INS_MOVNTPD:
    case X86_INS_MOVNTPS:
    case X86_INS_MOVNTSD:
    case X86_INS_MOVNTSS:
    case X86_INS_VMOVNTDQA:
    case X86_INS_VMOVNTDQ:
    case X86_INS_VMOVNTPD:
    case X86_INS_VMOVNTPS:
    case X86_INS_MOVSS:
    case X86_INS_MOV:
    case X86_INS_MOVAPS:
    case X86_INS_MOVAPD:
    case X86_INS_MOVZX:
    case X86_INS_MOVUPS:
    case X86_INS_MOVABS:
    case X86_INS_MOVHPD:
    case X86_INS_MOVHPS:
    case X86_INS_MOVLPD:
    case X86_INS_MOVLPS:
    case X86_INS_MOVBE:
    case X86_INS_MOVSB:
    case X86_INS_MOVSD:
    case X86_INS_MOVSQ:
    case X86_INS_MOVSX:
    case X86_INS_MOVSXD:
    case X86_INS_MOVSW:
    case X86_INS_MOVD:
    case X86_INS_MOVQ:
    case X86_INS_MOVDQ2Q:
    case X86_INS_RDRAND:
    case X86_INS_RDSEED:
    case X86_INS_RDMSR:
    case X86_INS_RDPMC:
    case X86_INS_RDTSC:
    case X86_INS_RDTSCP:
    case X86_INS_CRC32:
    case X86_INS_SHA1MSG1:
    case X86_INS_SHA1MSG2:
    case X86_INS_SHA1NEXTE:
    case X86_INS_SHA1RNDS4:
    case X86_INS_SHA256MSG1:
    case X86_INS_SHA256MSG2:
    case X86_INS_SHA256RNDS2:
    case X86_INS_AESDECLAST:
    case X86_INS_AESDEC:
    case X86_INS_AESENCLAST:
    case X86_INS_AESENC:
    case X86_INS_AESIMC:
    case X86_INS_AESKEYGENASSIST:
    case X86_INS_PACKSSDW:
    case X86_INS_PACKSSWB:
    case X86_INS_PACKUSWB:
    case X86_INS_XCHG:
    case X86_INS_CLD:
    case X86_INS_STD:
      switch (insn->detail->x86.operands[0].type)
      {
        case X86_OP_MEM:
          return GUM_MEMOP_WRITE;
        case X86_OP_REG:
          if (insn->detail->x86.operands[1].type == X86_OP_MEM)
            return GUM_MEMOP_READ;
        default:
          return GUM_MEMOP_READ;
      }
    default:
      return GUM_MEMOP_READ;
  }
}

#elif defined (HAVE_ARM)

static GumMemoryOperation
gum_infer_arm_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM_INS_STREX:
    case ARM_INS_STREXB:
    case ARM_INS_STREXD:
    case ARM_INS_STREXH:
    case ARM_INS_STR:
    case ARM_INS_STRB:
    case ARM_INS_STRD:
    case ARM_INS_STRBT:
    case ARM_INS_STRH:
    case ARM_INS_STRHT:
    case ARM_INS_STRT:
      return GUM_MEMOP_WRITE;
    default:
      return GUM_MEMOP_READ;
  }
}

#elif defined (HAVE_ARM64)

static GumMemoryOperation
gum_infer_arm64_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM64_INS_STRB:
    case ARM64_INS_STURB:
    case ARM64_INS_STUR:
    case ARM64_INS_STR:
    case ARM64_INS_STP:
    case ARM64_INS_STNP:
    case ARM64_INS_STXR:
    case ARM64_INS_STXRH:
    case ARM64_INS_STLXRH:
    case ARM64_INS_STXRB:
      return GUM_MEMOP_WRITE;
    default:
      return GUM_MEMOP_READ;
  }
}

#endif
