#define GUM_DUK_BLOCK_SIZE 4096

#include "duktape.h"

#include <errno.h>
#include <stdio.h>

int
main (int argc,
      char * argv[])
{
  int exit_code = 1;
  const char * input_path, * output_path;
  duk_context * ctx;
  unsigned char * code;
  duk_size_t size, remaining;
  FILE * output = NULL;

  if (argc != 3)
  {
    fprintf (stderr, "Usage: %s input.js output.duk\n", argv[0]);
    return 1;
  }

  input_path = argv[1];
  output_path = argv[2];

  ctx = duk_create_heap (NULL, NULL, NULL, NULL, NULL);

  if (duk_pcompile_file (ctx, DUK_COMPILE_EVAL, input_path) != 0)
  {
    fprintf (stderr, "%s: %s\n", input_path, duk_safe_to_string (ctx, -1));
    goto beach;
  }

  duk_dump_function (ctx);

  code = duk_get_buffer_data (ctx, -1, &size);

  output = fopen (output_path, "wb");
  if (output == NULL)
  {
    perror (output_path);
    goto beach;
  }

  remaining = size;
  while (remaining != 0)
  {
    duk_size_t n = MIN (remaining, GUM_DUK_BLOCK_SIZE);

    if (fwrite (code, n, 1, output) != 1)
    {
      perror (output_path);
      goto beach;
    }

    code += n;
    remaining -= n;
  }

  exit_code = 0;

beach:
  duk_pop (ctx);

  duk_destroy_heap (ctx);

  if (output != NULL)
    fclose (output);

  return exit_code;
}
