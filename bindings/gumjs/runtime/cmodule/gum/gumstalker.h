#ifndef __GUM_STALKER_H__
#define __GUM_STALKER_H__

#include "gumdefs.h"
#if defined (HAVE_I386)
# include "arch-x86/gumx86writer.h"
typedef GumX86Writer GumStalkerWriter;
#elif defined (HAVE_ARM)
# include "arch-arm/gumthumbwriter.h"
typedef GumThumbWriter GumStalkerWriter;
#elif defined (HAVE_ARM64)
# include "arch-arm64/gumarm64writer.h"
typedef GumArm64Writer GumStalkerWriter;
#elif defined (HAVE_MIPS)
# include "arch-mips/gummipswriter.h"
typedef GumMipsWriter GumStalkerWriter;
#endif

#include <capstone.h>

typedef struct _GumStalkerIterator GumStalkerIterator;
typedef void (* GumStalkerTransformerCallback) (GumStalkerIterator * iterator,
    GumStalkerWriter * output, gpointer user_data);
typedef void (* GumStalkerCallout) (GumCpuContext * cpu_context,
    gpointer user_data);

typedef struct _GumCallSite GumCallSite;

struct _GumCallSite
{
  gpointer block_address;
  gpointer stack_data;
  GumCpuContext * cpu_context;
};

gboolean gum_stalker_iterator_next (GumStalkerIterator * self,
    const cs_insn ** insn);
void gum_stalker_iterator_keep (GumStalkerIterator * self);
void gum_stalker_iterator_put_callout (GumStalkerIterator * self,
    GumStalkerCallout callout, gpointer data, GDestroyNotify data_destroy);

#endif
