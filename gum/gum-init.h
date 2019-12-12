/*
 * Copyright (C) 2014-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INIT_H__
#define __GUM_INIT_H__

#include <capstone.h>
#include <gum/gumdefs.h>

typedef void (* GumDestructorFunc) (void);

G_BEGIN_DECLS

G_GNUC_INTERNAL void _gum_register_early_destructor (
    GumDestructorFunc destructor);
G_GNUC_INTERNAL void _gum_register_destructor (GumDestructorFunc destructor);

G_END_DECLS

#endif
