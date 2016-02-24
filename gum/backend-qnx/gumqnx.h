/*
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QNX_H__
#define __GUM_QNX_H__

#include "gumprocess.h"

#include <sys/debug.h>

G_BEGIN_DECLS

GUM_API void gum_qnx_enumerate_ranges (pid_t pid, GumPageProtection prot,
    GumFoundRangeFunc func, gpointer user_data);

GUM_API void gum_qnx_parse_ucontext (const ucontext_t * uc,
    GumCpuContext * ctx);
GUM_API void gum_qnx_unparse_ucontext (const GumCpuContext * ctx,
    ucontext_t * uc);

G_END_DECLS

#endif
