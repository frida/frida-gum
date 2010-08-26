/*
 * Copyright (C) 2009 Ole André Vadla Ravnås <ole.andre.ravnas@tandberg.com>
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

#ifndef __GUM_X86_READER_H__
#define __GUM_X86_READER_H__

#include "gumdefs.h"

G_BEGIN_DECLS

gpointer gum_x86_reader_try_get_relative_call_target (gconstpointer address);
gpointer gum_x86_reader_try_get_relative_jump_target (gconstpointer address);
gpointer gum_x86_reader_try_get_indirect_jump_target (gconstpointer address);

G_END_DECLS

#endif
