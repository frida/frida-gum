/*
 * Copyright (C) 2025 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_SYSTEM_TAP_H__
#define __GUM_SYSTEM_TAP_H__

#include "gummodule.h"

G_BEGIN_DECLS

typedef struct _GumSystemTapProbeDetails GumSystemTapProbeDetails;
typedef gboolean (* GumFoundSystemTapProbeFunc) (
    const GumSystemTapProbeDetails * probe, gpointer user_data);

struct _GumSystemTapProbeDetails
{
  const gchar * provider;
  const gchar * name;
  const gchar * args;
  GumAddress address;
  GumAddress semaphore;
};

G_GNUC_INTERNAL void gum_system_tap_enumerate_probes (GumModule * module,
    GumFoundSystemTapProbeFunc func, gpointer user_data);

G_END_DECLS

#endif
