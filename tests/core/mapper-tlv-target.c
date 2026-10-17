/*
 * Copyright (C) 2026 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

static __thread unsigned int gum_test_tlv_counter = 42;
static __thread unsigned char gum_test_tlv_scratch[256];

unsigned int
gum_test_tlv_bump (void)
{
  return ++gum_test_tlv_counter;
}

void *
gum_test_tlv_counter_address (void)
{
  return &gum_test_tlv_counter;
}

void *
gum_test_tlv_scratch_address (void)
{
  return gum_test_tlv_scratch;
}
