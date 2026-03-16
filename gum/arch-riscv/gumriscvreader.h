/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2025 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_RISCV_READER_H__
#define __GUM_RISCV_READER_H__

#include "gumdefs.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL gboolean gum_riscv_reader_try_get_relative_jump_info (
    gconstpointer address, GumAddress * target, gsize * size);
gpointer gum_riscv_reader_try_get_relative_jump_target (gconstpointer address);

G_END_DECLS

#endif