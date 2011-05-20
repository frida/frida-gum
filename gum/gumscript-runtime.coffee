send = (payload) ->
  message =
    type: 'send'
    payload: payload
  _send(JSON.stringify(message))

recv = (callback) ->
  _recv((rawMessage) ->
    callback(JSON.parse(rawMessage)))
