/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumpharo.h"

#include <gum/gum.h>
#include <pharovm/pharoClient.h>
#include <stdio.h>

static void
on_message (const gchar * payload,
            GBytes * data,
            gpointer user_data)
{
  gsize size = 0;

  if (data != NULL)
    g_bytes_get_data (data, &size);

  printf ("[message] %s (%zu bytes)\n", payload, size);
  fflush (stdout);
}

int
main (int argc, const char ** argv, const char ** envp)
{
  gum_init_embedded ();
  gum_pharo_set_message_handler (on_message, NULL);

  return vm_main (argc, argv, envp);
}
