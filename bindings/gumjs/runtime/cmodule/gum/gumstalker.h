#ifndef __GUM_STALKER_H__
#define __GUM_STALKER_H__

#include "gumdefs.h"
#if defined (HAVE_I386)
# include "arch-x86/gumx86writer.h"
#elif defined (HAVE_ARM)
# include "arch-arm/gumarmwriter.h"
# include "arch-arm/gumthumbwriter.h"
#elif defined (HAVE_ARM64)
# include "arch-arm64/gumarm64writer.h"
#elif defined (HAVE_MIPS)
# include "arch-mips/gummipswriter.h"
#endif

#include <capstone.h>

typedef struct _GumStalkerIterator GumStalkerIterator;
typedef struct _GumStalkerOutput GumStalkerOutput;
typedef union _GumStalkerWriter GumStalkerWriter;
typedef void (* GumStalkerTransformerCallback) (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
typedef void (* GumStalkerCallout) (GumCpuContext * cpu_context,
    gpointer user_data);

typedef struct _GumCallSite GumCallSite;

union _GumStalkerWriter
{
#if defined (HAVE_I386)
  GumX86Writer * x86;
#elif defined (HAVE_ARM)
  GumArmWriter * arm;
  GumThumbWriter * thumb;
#elif defined (HAVE_ARM64)
  GumArm64Writer * arm64;
#elif defined (HAVE_MIPS)
  GumMipsWriter * mips;
#endif
};

struct _GumStalkerOutput
{
  GumStalkerWriter writer;
  GumInstructionEncoding encoding;
};

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
