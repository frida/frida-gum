/*
 * Copyright (C) 2010-2019 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SPINLOCK_H__
#define __GUM_SPINLOCK_H__

#include <glib.h>

#define GUM_SPINLOCK_INIT { { 0, } }

G_BEGIN_DECLS

typedef struct _GumSpinlock GumSpinlock;

struct _GumSpinlock
{
  gpointer data[8];
};

void gum_spinlock_init (GumSpinlock * spinlock);

void gum_spinlock_acquire (GumSpinlock * spinlock);
void gum_spinlock_release (GumSpinlock * spinlock);

G_END_DECLS

#endif
