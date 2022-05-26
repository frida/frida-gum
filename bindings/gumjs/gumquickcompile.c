#define GUM_QUICK_BLOCK_SIZE 4096

#include <errno.h>
#include <quickjs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (int argc,
      char * argv[])
{
  int exit_code = 1;
  int extra_write_flags = 0;
  const char * input_path, * output_path;
  JSRuntime * rt;
  JSContext * ctx;
  FILE * input = NULL;
  long input_size;
  const char * input_basename, * sep;
  char * input_filename;
  char * input_source = NULL;
  JSValue val = JS_NULL;
  uint8_t * code = NULL;
  size_t size, remaining;
  uint8_t * code_cursor;
  FILE * output = NULL;

  if (argc >= 2 && strcmp (argv[1], "--bswap") == 0)
  {
    extra_write_flags = JS_WRITE_OBJ_BSWAP;

    argc--;
    argv[1] = argv[0];
    argv++;
  }

  if (argc != 3)
  {
    fprintf (stderr, "Usage: %s [--bswap] input.js output.qjs\n", argv[0]);
    return 1;
  }

  input_path = argv[1];
  output_path = argv[2];

  input_basename = NULL;
#if defined _WIN32 || defined __WIN32__
  sep = strrchr (input_path, '\\');
  if (sep != NULL)
    input_basename = sep + 1;
#endif
  if (input_basename == NULL)
  {
    sep = strrchr (input_path, '/');
    if (sep != NULL)
      input_basename = sep + 1;
  }
  if (input_basename == NULL)
    input_basename = input_path;

  input_filename = malloc (2 + strlen (input_basename) + 1);
  strcpy (input_filename, "/_");
  strcat (input_filename, input_basename);

  rt = JS_NewRuntime ();

  ctx = JS_NewContext (rt);

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
  if (fread (input_source, input_size, 1, input) != 1)
  {
    fprintf (stderr, "%s: I/O error\n", input_path);
    goto beach;
  }
  input_source[input_size] = 0;

  val = JS_Eval (ctx, input_source, strlen (input_source), input_filename,
      JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT | JS_EVAL_FLAG_COMPILE_ONLY);
  if (JS_IsException (val))
    goto compilation_failed;

  code = JS_WriteObject (ctx, &size, val,
      JS_WRITE_OBJ_BYTECODE | extra_write_flags);

  output = fopen (output_path, "wb");
  if (output == NULL)
  {
    perror (output_path);
    goto beach;
  }

  code_cursor = code;
  remaining = size;
  while (remaining != 0)
  {
    size_t n = (remaining > GUM_QUICK_BLOCK_SIZE)
        ? GUM_QUICK_BLOCK_SIZE
        : remaining;

    if (fwrite (code_cursor, n, 1, output) != 1)
    {
      perror (output_path);
      goto beach;
    }

    code_cursor += n;
    remaining -= n;
  }

  exit_code = 0;

beach:
  if (code != NULL)
    js_free (ctx, code);

  if (!JS_IsNull (val))
    JS_FreeValue (ctx, val);

  JS_FreeContext (ctx);

  JS_FreeRuntime (rt);

  if (output != NULL)
    fclose (output);

  if (input_source != NULL)
    free (input_source);

  if (input != NULL)
    fclose (input);

  free (input_filename);

  return exit_code;

compilation_failed:
  {
    JSValue exception_val;
    const char * message;

    exception_val = JS_GetException (ctx);

    message = JS_ToCString (ctx, exception_val);

    fprintf (stderr, "%s: %s\n", input_path, message);

    JS_FreeCString (ctx, message);
    JS_FreeValue (ctx, exception_val);

    goto beach;
  }
}
