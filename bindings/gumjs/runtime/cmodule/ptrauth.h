#include <stdint.h>

enum _ptrauth_key
{
  ptrauth_key_asia = 0,
  ptrauth_key_asib = 1,
  ptrauth_key_asda = 2,
  ptrauth_key_asdb = 3,
  ptrauth_key_process_independent_code = ptrauth_key_asia,
  ptrauth_key_process_dependent_code = ptrauth_key_asib,
  ptrauth_key_process_independent_data = ptrauth_key_asda,
  ptrauth_key_process_dependent_data = ptrauth_key_asdb,
  ptrauth_key_function_pointer = ptrauth_key_process_independent_code,
  ptrauth_key_return_address = ptrauth_key_process_dependent_code,
  ptrauth_key_frame_pointer = ptrauth_key_process_dependent_data,
  ptrauth_key_block_function = ptrauth_key_asia,
  ptrauth_key_cxx_vtable_pointer = ptrauth_key_asda,
};

typedef enum _ptrauth_key ptrauth_key;
typedef uintptr_t ptrauth_extra_data_t;
typedef uintptr_t ptrauth_generic_signature_t;

#ifdef HAVE_PTRAUTH

# define ptrauth_strip(value, key) \
    ((key <= ptrauth_key_asib) ? __arm64_ptrauth_strip_i (value)\
        : __arm64_ptrauth_strip_d (value))
# define ptrauth_blend_discriminator(pointer, integer) \
    ((void *) (size_t) (((size_t) (void *) (pointer) & 0x0000ffffffffffffULL) |\
        (((size_t) integer & 0xffffULL) << 48)))
# define ptrauth_sign_unauthenticated(value, key, data) \
    ((key == ptrauth_key_asia) ? __arm64_ptrauth_sign_ia (value, data)\
        : (key == ptrauth_key_asib) ? __arm64_ptrauth_sign_ib (value, data)\
        : (key == ptrauth_key_asda) ? __arm64_ptrauth_sign_da (value, data)\
        : (key == ptrauth_key_asdb) ? __arm64_ptrauth_sign_db (value, data)\
        : value)

#else

# define ptrauth_strip(value, key) value
# define ptrauth_blend_discriminator(pointer, integer) ((uintptr_t) 0)
# define ptrauth_sign_unauthenticated(value, key, data) value

#endif
