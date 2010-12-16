#ifndef __GUMPP_INVOCATION_LISTENER_HPP__
#define __GUMPP_INVOCATION_LISTENER_HPP__

#include "gumpp.hpp"

namespace Gum
{
  typedef struct _GumInvocationListenerProxy GumInvocationListenerProxy;

  struct InvocationListenerIface : public Object
  {
    virtual void on_enter (InvocationContext * context) = 0;
    virtual void on_leave (InvocationContext * context) = 0;
  };

  class InvocationListenerProxy : public InvocationListenerIface
  {
  public:
    InvocationListenerProxy (InvocationListener * listener);

    virtual void ref ();
    virtual void unref ();
    virtual void * get_handle () const;

    virtual void on_enter (InvocationContext * context);
    virtual void on_leave (InvocationContext * context);

  protected:
    GumInvocationListenerProxy * cproxy;
    InvocationListener * listener;
  };
}

#endif