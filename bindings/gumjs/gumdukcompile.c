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
  FILE * input = NULL;
  long input_size;
  const char * input_name, * sep;
  char * input_source = NULL;
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

  input_name = NULL;
#if defined _WIN32 || defined __WIN32__
  sep = strrchr (input_path, '\\');
  if (sep != NULL)
    input_name = sep + 1;
#endif
  if (input_name == NULL)
  {
    sep = strrchr (input_path, '/');
    if (sep != NULL)
      input_name = sep + 1;
  }
  if (input_name == NULL)
    input_name = input_path;

  ctx = duk_create_heap (NULL, NULL, NULL, NULL, NULL);

  input = fopen (input_path, "rb");
  if (input == NULL)
  {
    fprintf (stderr, "%s: %s\n", input_path, strerror (errno));
    goto beach;
  }

  fseek (input, 0, SEEK_END);
  input_size = ftell (input);
  rewind (input);

  input_source = malloc (input_size + 1);
  fread (input_source, input_size, 1, input);
  input_source[input_size] = 0;

  duk_push_string (ctx, input_source);
  duk_push_string (ctx, input_name);
  if (duk_pcompile (ctx, DUK_COMPILE_EVAL) != 0)
  {
    fprintf (stderr, "%s: %s\n", input_path, duk_safe_to_string (ctx, -1));
    goto beach;
  }

  duk_dump_function (ctx);

  code = duk_require_buffer_data (ctx, -1, &size);

  output = fopen (output_path, "wb");
  if (output == NULL)
  {
    perror (output_path);
    goto beach;
  }

  remaining = size;
  while (remaining != 0)
  {
    duk_size_t n = (remaining > GUM_DUK_BLOCK_SIZE)
        ? GUM_DUK_BLOCK_SIZE
        : remaining;

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

  if (input_source != NULL)
    free (input_source);

  if (input != NULL)
    fclose (input);

  return exit_code;
}
