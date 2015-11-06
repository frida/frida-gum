/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscvalue.h"

#include "gumjscscript-priv.h"

#include "wtf/Platform.h"
#include "JSExportMacros.h"
#include "JSArrayBuffer.h"
#include "APICast.h"

using namespace JSC;

class GumValueHandleObserver : public WeakHandleOwner
{
public:
  virtual void finalize (Handle<Unknown>, void * context) override;
};

static GumValueHandleObserver gumjs_value_handle_observer;

struct _GumJscWeakRef
{
public:
  _GumJscWeakRef (JSContextRef ctx,
                     JSValueRef value,
                     GumJscWeakNotify notify,
                     gpointer data,
                     GDestroyNotify dataDestroy)
    : m_notify (notify),
      m_data (data),
      m_dataDestroy (dataDestroy)
  {
    ExecState * exec = toJS (ctx);
    JSGlobalObject * globalObject = exec->lexicalGlobalObject ();
    Weak<JSGlobalObject> globalObjectWeak (globalObject,
        &gumjs_value_handle_observer, this);
    m_globalObject.swap (globalObjectWeak);
    m_lock = &exec->vm ().apiLock ();

    JSValue jsValue = toJS (exec, value);
    if (jsValue.isObject ())
    {
      m_type = GUM_WEAK_OBJECT;
      Weak<JSObject> weak (jsCast<JSObject *> (jsValue.asCell ()),
          &gumjs_value_handle_observer, this);
      u.m_object.swap (weak);
    }
    else if (jsValue.isString ())
    {
      m_type = GUM_WEAK_STRING;
      Weak<JSString> weak (jsCast<JSString *> (jsValue.asCell ()),
          &gumjs_value_handle_observer, this);
      u.m_string.swap (weak);
    }
    else
    {
      m_type = GUM_WEAK_PRIMITIVE;
      u.m_primitive = jsValue;
    }
  }

  ~_GumJscWeakRef ()
  {
    disconnect ();

    if (m_dataDestroy != NULL)
      m_dataDestroy (m_data);
  }

  JSValueRef
  get ()
  {
    WTF::Locker<JSLock> locker (m_lock.get ());
    if (!m_lock->vm ())
      return NULL;

    JSLockHolder apiLocker (m_lock->vm ());

    if (!m_globalObject)
      return NULL;

    if (isClear ())
      return NULL;

    ExecState * exec = m_globalObject->globalExec ();

    JSValue value;
    switch (m_type)
    {
      case GUM_WEAK_PRIMITIVE:
        value = u.m_primitive;
        break;
      case GUM_WEAK_OBJECT:
        value = u.m_object.get ();
        break;
      case GUM_WEAK_STRING:
        value = u.m_string.get ();
        break;
      default:
        g_assert_not_reached ();
    }

    return toRef (exec, value);
  }

  void
  on_finalize ()
  {
    disconnect ();

    m_notify (m_data);
  }

private:
  bool
  isClear () const
  {
    switch (m_type)
    {
      case GUM_WEAK_PRIMITIVE:
        return !u.m_primitive;
      case GUM_WEAK_OBJECT:
        return !u.m_object;
      case GUM_WEAK_STRING:
        return !u.m_string;
      default:
        g_assert_not_reached ();
    }
  }

  void
  disconnect ()
  {
    m_globalObject.clear ();

    switch (m_type)
    {
      case GUM_WEAK_PRIMITIVE:
        u.m_primitive = JSValue ();
        break;
      case GUM_WEAK_OBJECT:
        u.m_object.clear ();
        break;
      case GUM_WEAK_STRING:
        u.m_string.clear ();
        break;
      default:
        g_assert_not_reached ();
    }
  }

  Weak<JSGlobalObject> m_globalObject;
  RefPtr<JSLock> m_lock;

  enum ValueType
  {
    GUM_WEAK_PRIMITIVE,
    GUM_WEAK_OBJECT,
    GUM_WEAK_STRING
  } m_type;

  union ValueUnion {
  public:
    ValueUnion ()
      : m_primitive (JSValue ())
    {
    }

    ~ValueUnion ()
    {
    }

    JSValue m_primitive;
    Weak<JSObject> m_object;
    Weak<JSString> m_string;
  } u;

  GumJscWeakNotify m_notify;
  gpointer m_data;
  GDestroyNotify m_dataDestroy;
};

GumJscWeakRef *
_gumjs_weak_ref_new (JSContextRef ctx,
                     JSValueRef value,
                     GumJscWeakNotify notify,
                     gpointer data,
                     GDestroyNotify data_destroy)
{
  return new _GumJscWeakRef (ctx, value, notify, data, data_destroy);
}

JSValueRef
_gumjs_weak_ref_get (GumJscWeakRef * ref)
{
  return ref->get ();
}

void
_gumjs_weak_ref_free (GumJscWeakRef * ref)
{
  delete ref;
}

void
GumValueHandleObserver::finalize (Handle<Unknown>,
                                  void * context)
{
  static_cast<GumJscWeakRef *> (context)->on_finalize ();
}

gpointer
_gumjs_array_buffer_get_data (JSContextRef ctx,
                              JSValueRef value,
                              gsize * size)
{
  gpointer data;
  JSValueRef exception;

  if (!_gumjs_array_buffer_try_get_data (ctx, value, &data, size, &exception))
    _gumjs_panic (ctx, exception);

  return data;
}

gboolean
_gumjs_array_buffer_try_get_data (JSContextRef ctx,
                                  JSValueRef value,
                                  gpointer * data,
                                  gsize * size,
                                  JSValueRef * exception)
{
  ExecState * exec = toJS (ctx);
  JSLockHolder lock (exec);

  JSValue jsValue = toJS (exec, value);
  ArrayBuffer * buffer = toArrayBuffer (jsValue);
  if (buffer != NULL)
  {
    *data = buffer->data ();
    if (size != NULL)
      *size = buffer->byteLength ();
    return TRUE;
  }
  else
  {
    _gumjs_throw (ctx, exception, "expected an ArrayBuffer");
    return FALSE;
  }
}
