#include "gumprocess.h"
#include "gumdefs.h"

extern void gum_process_call_function_stub (GumCpuContext * cpu_context,
    gpointer user_data, GumProcessRunOnThreadFunc callback);

gboolean
gum_process_is_run_on_thread_supported ()
{
  return TRUE;
}

void
gum_process_modify_thread_to_call_function (GumThreadId thread_id,
                                            GumCpuContext * cpu_context,
                                            gpointer user_data)
{
  GumProcessRunOnThreadContext * ctx = (GumProcessRunOnThreadContext *) user_data;

  ctx->cached_context = *cpu_context;

  cpu_context->pc = (guint64) gum_process_call_function_stub;
  cpu_context->x[0] = (guint64) &ctx->cached_context;
  cpu_context->x[1] = (guint64) ctx->user_data;
  cpu_context->x[2] = (guint64) ctx->callback;
  cpu_context->sp -= 0x80;
  cpu_context->sp &= ~0xf;
}

void
gum_process_call_with_full_context (GumCpuContext * cpu_context,
                                    GumProcessFullContextFunc callback,
                                    gpointer user_data)
{
  GumFullCpuContext full_context;
  full_context.regs = *cpu_context;
  callback (&full_context, user_data);
}
