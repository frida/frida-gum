Class {
	#name : 'GumScript',
	#superclass : 'Object',
	#classVars : [
		'Exports',
		'Scripts',
		'MessageSemaphore',
		'MessageSemaphoreIndex'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'running' }
GumScript class >> start [
	self installErrorReporting.
	^ self onMessageDo: [ :message | self dispatch: message ]
]

{ #category : 'running' }
GumScript class >> dispatch: aMessage [
	| payload kind |
	payload := aMessage payload.
	kind := (payload isDictionary)
		ifTrue: [ payload at: 'type' ifAbsent: [ nil ] ]
		ifFalse: [ nil ].

	kind = 'gum:create' ifTrue: [ ^ self create: payload ].
	kind = 'gum:load' ifTrue: [ ^ (self scriptAt: payload) load ].
	kind = 'gum:unload' ifTrue: [ ^ self destroy: payload ].

	^ (self scriptAt: payload) deliver:
		(GumMessage payload: (payload at: 'payload') data: aMessage data)
]

{ #category : 'running' }
GumScript class >> create: aPayload [
	| context |
	context := GumScriptContext
		id: (aPayload at: 'id')
		name: (aPayload at: 'name')
		source: (aPayload at: 'source').
	self scripts at: context id put: context.
	^ context
]

{ #category : 'running' }
GumScript class >> destroy: aPayload [
	| context |
	context := self scriptAt: aPayload.
	context unload.
	self scripts removeKey: context id ifAbsent: [ nil ].
	^ context
]

{ #category : 'running' }
GumScript class >> scriptAt: aPayload [
	^ self scripts at: (aPayload at: 'id')
]

{ #category : 'running' }
GumScript class >> scripts [
	^ Scripts ifNil: [ Scripts := Dictionary new ]
]

{ #category : 'running' }
GumScript class >> onMessage: aBlock [
	GumCurrentScript value onMessage: aBlock
]

{ #category : 'rpc' }
GumScript class >> exports [
	^ Exports ifNil: [ Exports := self findExports ]
]

{ #category : 'rpc' }
GumScript class >> export: aName do: aBlock [
	GumCurrentScript value exports at: aName put: aBlock
]

{ #category : 'rpc' }
GumScript class >> call: aName arguments: anArray [
	^ self reportingErrorsDo: [ self invoke: aName arguments: anArray ]
]

{ #category : 'rpc' }
GumScript class >> invoke: aName arguments: anArray [
	| script block method |
	script := GumCurrentScript value.
	script ifNotNil: [
		block := script exports at: aName ifAbsent: [ nil ].
		block ifNotNil: [ ^ block valueWithArguments: anArray ] ].
	method := self exports
		at: aName
		ifAbsent: [ ^ self error: 'no such export: ' , aName ].
	^ method methodClass instanceSide new
		perform: method selector
		withArguments: anArray
]

{ #category : 'rpc' }
GumScript class >> flushExports [
	Exports := nil
]

{ #category : 'messaging' }
GumScript class >> receive [
	^ self receiveWithTimeout: nil
]

{ #category : 'messaging' }
GumScript class >> receiveWithTimeout: aDuration [
	| handle deadline |
	deadline := aDuration ifNotNil: [ DateAndTime now + aDuration ].
	[ handle := GumPrimitives gumPharoTakeMessage.
	  handle = 0 ] whileTrue: [
		deadline
			ifNil: [ self messageSemaphore wait ]
			ifNotNil: [
				(self messageSemaphore
					waitTimeoutMSecs: (deadline - DateAndTime now) asMilliSeconds)
						ifTrue: [ ^ nil ] ] ].
	^ GumMessage fromHandle: handle
]

{ #category : 'messaging' }
GumScript class >> onMessageDo: aBlock [
	^ [ [ true ] whileTrue: [
		| message |
		message := self receive.
		self reportingErrorsDo: [ aBlock value: message ] ] ]
		forkAt: Processor userBackgroundPriority
		named: 'GumScript message loop'
]

{ #category : 'messaging' }
GumScript class >> send: aPayload [
	^ self send: aPayload data: nil
]

{ #category : 'messaging' }
GumScript class >> send: aPayload data: aByteArray [
	self
		emit: { 'type' -> 'send'. 'payload' -> aPayload } asDictionary
		data: aByteArray
]

{ #category : 'logging' }
GumScript class >> log: aString [
	self log: aString level: 'info'
]

{ #category : 'logging' }
GumScript class >> logDebug: aString [
	self log: aString level: 'debug'
]

{ #category : 'logging' }
GumScript class >> logWarning: aString [
	self log: aString level: 'warning'
]

{ #category : 'logging' }
GumScript class >> logError: aString [
	self log: aString level: 'error'
]

{ #category : 'logging' }
GumScript class >> log: aString level: aLevel [
	self
		emit: {
			'type' -> 'log'.
			'level' -> aLevel.
			'payload' -> aString asString } asDictionary
		data: nil
]

{ #category : 'errors' }
GumScript class >> installErrorReporting [
	(UIManager default isKindOf: GumScriptUIManager)
		ifFalse: [ UIManager default: GumScriptUIManager new ]
]

{ #category : 'errors' }
GumScript class >> reportError: anException [
	self
		emit: {
			'type' -> 'error'.
			'description' -> anException description.
			'stack' -> (self stackFor: anException) } asDictionary
		data: nil
]

{ #category : 'errors' }
GumScript class >> stackFor: anException [
	^ String streamContents: [ :stream |
		| context |
		context := anException signalerContext.
		[ context isNil ] whileFalse: [
			stream nextPutAll: context printString; lf.
			context := context sender ] ]
]

{ #category : 'private' }
GumScript class >> reportingErrorsDo: aBlock [
	^ aBlock on: Error do: [ :error |
		self reportError: error.
		nil ]
]

{ #category : 'rpc' }
GumScript class >> handleRpc: aMessage [
	| request id |
	request := aMessage payload.
	((request isKindOf: Array) and: [
		request size >= 3 and: [ request first = 'frida:rpc' ] ])
			ifFalse: [ ^ false ].
	id := request second.
	request third = 'call'
		ifTrue: [
			[ self replyTo: id with: (self invoke: (request at: 4) arguments: (request at: 5)) ]
				on: Error
				do: [ :error | self replyTo: id withError: error ] ]
		ifFalse: [ self replyTo: id withError: (Error new
			messageText: 'unsupported rpc operation: ' , request third asString) ].
	^ true
]

{ #category : 'rpc' }
GumScript class >> replyTo: anId with: aValue [
	self send: { 'frida:rpc'. anId. 'ok'. aValue }
]

{ #category : 'rpc' }
GumScript class >> replyTo: anId withError: anException [
	self send: {
		'frida:rpc'. anId. 'error'. anException messageText asString.
		anException class name. self stackFor: anException }
]

{ #category : 'private' }
GumScript class >> emit: aMessage data: aByteArray [
	| envelope |
	envelope := Dictionary new
		at: 'id' put: (GumCurrentScript value ifNil: [ 0 ] ifNotNil: [ :each | each id ]);
		at: 'payload' put: aMessage;
		yourself.
	GumPrimitives
		gumPharoPost: (STONJSON toString: envelope)
		data: aByteArray
]

{ #category : 'rpc' }
GumScript class >> findExports [
	| exports |
	exports := Dictionary new.
	self exportedMethods do: [ :method |
		exports at: (self exportedNameOf: method) put: method ].
	^ exports
]

{ #category : 'rpc' }
GumScript class >> exportedMethods [
	^ SystemNavigation default allMethodsSelect: [ :method |
		method pragmas anySatisfy: [ :pragma |
			#( gumExport gumExport: ) includes: pragma selector ] ]
]

{ #category : 'rpc' }
GumScript class >> exportedNameOf: aMethod [
	| pragma |
	pragma := aMethod pragmas detect: [ :each |
		#( gumExport gumExport: ) includes: each selector ].
	^ pragma selector == #gumExport:
		ifTrue: [ pragma arguments first ]
		ifFalse: [ (aMethod selector copyUpTo: $:) asString ]
]

{ #category : 'private' }
GumScript class >> messageSemaphore [
	^ MessageSemaphore ifNil: [
		MessageSemaphore := Semaphore new.
		MessageSemaphoreIndex := Smalltalk
			registerExternalObject: MessageSemaphore.
		GumPrimitives gumPharoSetMessageSemaphore: MessageSemaphoreIndex.
		MessageSemaphore ]
]
