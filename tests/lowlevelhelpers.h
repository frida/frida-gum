/*
 * Copyright (C) 2008-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __LOWLEVEL_HELPERS_H__
#define __LOWLEVEL_HELPERS_H__

#include <gum/gumdefs.h>

G_BEGIN_DECLS

typedef struct _UnsupportedFunction UnsupportedFunction;

typedef void (GUM_THUNK * ClobberTestFunc) (gpointer data);
typedef gpointer (* ProxyFunc) (GString * str);
typedef ProxyFunc TargetFunc;

struct _UnsupportedFunction
{
  const gchar * insn_name;
  guint code_len;
  guint code_offset;
  guint8 code[16];
};

extern ClobberTestFunc clobber_test_function;

void lowlevel_helpers_init (void);
void lowlevel_helpers_deinit (void);

void fill_cpu_context_with_magic_values (GumCpuContext * ctx);
void assert_cpu_contexts_are_equal (GumCpuContext * input,
    GumCpuContext * output);

void invoke_clobber_test_function_with_cpu_context (const GumCpuContext * input,
    GumCpuContext * output);
void invoke_clobber_test_function_with_carry_set (gsize * flags_input,
    gsize * flags_output);

UnsupportedFunction * unsupported_function_list_new (guint * count);
void unsupported_function_list_free (UnsupportedFunction * functions);

#ifdef HAVE_I386
ProxyFunc proxy_func_new_relative_with_target (TargetFunc target_func);
ProxyFunc proxy_func_new_absolute_indirect_with_target (TargetFunc target_func);
ProxyFunc proxy_func_new_two_jumps_with_target (TargetFunc target_func);
ProxyFunc proxy_func_new_early_call_with_target (TargetFunc target_func);
void proxy_func_free (ProxyFunc proxy_func);
#endif

G_END_DECLS

#endif
