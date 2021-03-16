#include "gumprocess.h"
#include "gumdefs.h"

gboolean
gum_process_is_run_on_thread_supported ()
{
  return FALSE;
}

void
gum_process_modify_thread_to_call_function (GumThreadId thread_id,
                                            GumCpuContext * cpu_context,
                                            gpointer user_data)
{

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
