class GumMessageDispatcher
  constructor: ->
    @messages = []
    @callbacks = {}
    _setIncomingMessageCallback(@handleMessage)

  registerCallback: (type, callback) ->
    @callbacks[type] = callback
    @dispatchMessages()

  handleMessage: (rawMessage) =>
    @messages.push(JSON.parse(rawMessage))
    @dispatchMessages()

  dispatchMessages: ->
    pending = @messages.splice(0, @messages.length)
    @dispatch message for message in pending
    return

  dispatch: (message) ->
    if @callbacks[message.type]
      handlerType = message.type
    else if @callbacks['*']
      handlerType = '*'
    else
      @messages.push(message)
      return
    callback = @callbacks[handlerType]
    delete @callbacks[handlerType]
    callback(message)
    return

_dispatcher = new GumMessageDispatcher()

send = (payload) ->
  message =
    type: 'send'
    payload: payload
  _send(JSON.stringify(message))

recv = ->
  if arguments.length == 1
    type = '*'
    callback = arguments[0]
  else
    type = arguments[0]
    callback = arguments[1]
  _dispatcher.registerCallback(type, callback)
