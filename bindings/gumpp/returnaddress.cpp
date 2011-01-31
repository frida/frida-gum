#include "gumpp.hpp"

#include <gum/gum.h>

namespace Gum
{
  extern "C" bool ReturnAddressDetails_from_address (ReturnAddress address, ReturnAddressDetails & details)
  {
    gum_init ();

    return gum_return_address_details_from_address (address, reinterpret_cast<GumReturnAddressDetails *> (&details)) != FALSE;
  }
}