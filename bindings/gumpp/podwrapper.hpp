#include <glib.h>

namespace Gum
{
  template <class D, class B, typename T>
  class PodWrapper : public B
  {
  public:
    PodWrapper ()
      : refcount (1),
        handle (NULL)
    {
    }

    ~PodWrapper ()
    {
      static_cast<D *> (this)->destroy_handle ();
    }

    virtual void destroy_handle () = 0;

    virtual void ref ()
    {
      g_atomic_int_add (&refcount, 1);
    }

    virtual void unref ()
    {
      if (g_atomic_int_dec_and_test (&refcount))
        delete static_cast<D *> (this);
    }

    virtual void * get_handle () const
    {
      return handle;
    }

  protected:
    void assign_handle (T * h)
    {
      handle = h;
    }

    volatile gint refcount;
    T * handle;
  };
}