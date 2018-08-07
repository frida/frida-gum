/*
 * Copyright (C) 2009-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2009 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_WALLCLOCK_SAMPLER_H__
#define __GUM_WALLCLOCK_SAMPLER_H__

#include "gumsampler.h"

G_BEGIN_DECLS

#define GUM_TYPE_WALLCLOCK_SAMPLER (gum_wallclock_sampler_get_type ())
G_DECLARE_FINAL_TYPE (GumWallclockSampler, gum_wallclock_sampler, GUM,
    WALLCLOCK_SAMPLER, GObject)

GUM_API GumSampler * gum_wallclock_sampler_new (void);

G_END_DECLS

#endif
