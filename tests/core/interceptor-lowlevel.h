/*
 * Copyright (C) 2008 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef __INTERCEPTOR_LOWLEVEL_H__
#define __INTERCEPTOR_LOWLEVEL_H__

#include <gum/gumdefs.h>

typedef struct _UnsupportedFunction UnsupportedFunction;

typedef gpointer (* ProxyFunc) (GString * str);
typedef ProxyFunc TargetFunc;

struct _UnsupportedFunction
{
  const gchar * insn_name;
  guint code_len;
  guint8 code[16];
};

void invoke_clobber_test_function_with_cpu_context (const GumCpuContext * input,
    GumCpuContext * output);
void invoke_clobber_test_function_with_carry_set (gsize * flags_input,
    gsize * flags_output);

gpointer clobber_test_function (gpointer data);

UnsupportedFunction * unsupported_function_list_new (guint * count);
void unsupported_function_list_free (UnsupportedFunction * functions);

ProxyFunc proxy_func_new_relative_with_target (TargetFunc target_func);
ProxyFunc proxy_func_new_absolute_indirect_with_target (TargetFunc target_func);
ProxyFunc proxy_func_new_two_jumps_with_target (TargetFunc target_func);
ProxyFunc proxy_func_new_early_call_with_target (TargetFunc target_func);
void proxy_func_free (ProxyFunc proxy_func);

#endif

