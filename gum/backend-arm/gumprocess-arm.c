#include "gumprocess.h"
#include "gumdefs.h"

static void gum_process_save_neon (GumArmNeonRegs * regs);
static void gum_process_restore_neon (GumArmNeonRegs * regs);

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

  cpu_context->pc = (guint32) ctx->callback;
  cpu_context->r[0] = (guint32) &ctx->cached_context;
  cpu_context->r[1] = (guint32) ctx->user_data;
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

  gum_process_save_neon (&full_context.neon);

  callback (&full_context, user_data);

  gum_process_restore_neon (&full_context.neon);

  if ((cpu_context->cpsr & GUM_PSR_T_BIT) != 0 )
    cpu_context->pc++;
}

static void
gum_process_save_neon (GumArmNeonRegs * regs)
{
  register void * r0 asm ("r0") = regs;
  GumCpuFeatures features = gum_query_cpu_features();

  if ((features & GUM_CPU_VFP3) != 0)
  {
    /* mov r1, sp */
    /* mov sp, r0 */
    /* add sp, $0x100 */
    /* vpush {q0-q15} */
    /* mov sp, r1 */
    asm volatile (
      ".byte 0x69, 0x46\n\t"
      ".byte 0x85, 0x46\n\t"
      ".byte 0x40, 0xb0\n\t"
      ".byte 0x2d, 0xed, 0x40, 0x0b\n\t"
      ".byte 0x8d, 0x46\n\t"
      :
      : "r" (r0)
      : "r1", "cc", "memory"
    );
  }
  else if ((features & GUM_CPU_VFP2) != 0)
  {
    /* mov r1, sp */
    /* mov sp, r0 */
    /* add sp, $0x80 */
    /* vpush {q0-q7} */
    /* mov sp, r1 */
    asm volatile (
      ".byte 0x69, 0x46\n\t"
      ".byte 0x85, 0x46\n\t"
      ".byte 0x40, 0xb0\n\t"
      ".byte 0x2d, 0xed, 0x20, 0x0b\n\t"
      ".byte 0x8d, 0x46\n\t"
      :
      : "r" (r0)
      : "r1", "cc", "memory"
    );
  }
}

static void
gum_process_restore_neon (GumArmNeonRegs * regs)
{
  register void * r0 asm ("r0") = regs;
  GumCpuFeatures features = gum_query_cpu_features();

  if ((features & GUM_CPU_VFP3) != 0)
  {
    /* mov r1, sp */
    /* mov sp, r0 */
    /* vpop {q0-q15} */
    /* mov sp, r1 */
    asm volatile (
      ".byte 0x69, 0x46\n\t"
      ".byte 0x85, 0x46\n\t"
      ".byte 0xbd, 0xec, 0x40, 0x0b\n\t"
      ".byte 0x8d, 0x46\n\t"
      :
      : "r" (r0)
      : "r1", "cc", "memory"
    );
  }
  else if ((features & GUM_CPU_VFP2) != 0)
  {
    /* mov r1, sp */
    /* mov sp, r0 */
    /* vpop {q0-q7} */
    /* mov sp, r1 */
    asm volatile (
      ".byte 0x69, 0x46\n\t"
      ".byte 0x85, 0x46\n\t"
      ".byte 0xbd, 0xec, 0x20, 0x0b\n\t"
      ".byte 0x8d, 0x46\n\t"
      :
      : "r" (r0)
      : "r1", "cc", "memory"
    );
  }
}
