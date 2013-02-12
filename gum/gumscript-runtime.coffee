class GumMessageDispatcher
  constructor: ->
    @messages = []
    @operations = {}
    _setIncomingMessageCallback(@handleMessage)

  registerCallback: (type, callback) ->
    op = new GumMessageRecvOperation(callback)
    @operations[type] = op
    @dispatchMessages()
    return op

  handleMessage: (rawMessage) =>
    @messages.push(JSON.parse(rawMessage))
    @dispatchMessages()

  dispatchMessages: ->
    pending = @messages.splice(0, @messages.length)
    @dispatch message for message in pending
    return

  dispatch: (message) ->
    if @operations[message.type]
      handlerType = message.type
    else if @operations['*']
      handlerType = '*'
    else
      @messages.push(message)
      return
    operation = @operations[handlerType]
    delete @operations[handlerType]
    operation._complete(message)
    return

class GumMessageRecvOperation
  constructor: (@callback) ->
    @completed = false

  wait: () ->
    while !@completed
      _waitForEvent()

  _complete: (message) ->
    @callback(message)
    @completed = true

_dispatcher = new GumMessageDispatcher()

send = (payload, data=null) ->
  message =
    type: 'send'
    payload: payload
  _send(JSON.stringify(message), data)

recv = ->
  if arguments.length == 1
    type = '*'
    callback = arguments[0]
  else
    type = arguments[0]
    callback = arguments[1]
  _dispatcher.registerCallback(type, callback)

ptr = (str) ->
  new NativePointer(str)
