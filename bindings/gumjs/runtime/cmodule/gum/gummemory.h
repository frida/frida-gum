#ifndef __GUM_MEMORY_H__
#define __GUM_MEMORY_H__

#include "gumdefs.h"

typedef guint GumPtrauthSupport;

enum _GumPtrauthSupport
{
  GUM_PTRAUTH_INVALID,
  GUM_PTRAUTH_UNSUPPORTED,
  GUM_PTRAUTH_SUPPORTED
};

gpointer gum_sign_code_pointer (gpointer value);
gpointer gum_strip_code_pointer (gpointer value);
GumAddress gum_sign_code_address (GumAddress value);
GumAddress gum_strip_code_address (GumAddress value);
GumPtrauthSupport gum_query_ptrauth_support (void);

#endif
