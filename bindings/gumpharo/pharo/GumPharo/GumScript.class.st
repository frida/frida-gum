Class {
	#name : 'GumScript',
	#superclass : 'Object',
	#classVars : [
		'Exports',
		'Handler',
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
	| payload |
	payload := aMessage payload.
	(payload isDictionary and: [ (payload at: 'type' ifAbsent: [ nil ]) = 'gum:eval' ])
		ifTrue: [ ^ self evaluate: (payload at: 'source') ].
	^ Handler ifNotNil: [ Handler value: aMessage ]
]

{ #category : 'running' }
GumScript class >> evaluate: aString [
	^ self reportingErrorsDo: [ Smalltalk compiler evaluate: aString ]
]

{ #category : 'running' }
GumScript class >> onMessage: aBlock [
	Handler := aBlock
]

{ #category : 'rpc' }
GumScript class >> exports [
	^ Exports ifNil: [ Exports := self findExports ]
]

{ #category : 'rpc' }
GumScript class >> call: aName arguments: anArray [
	| method |
	method := self exports
		at: aName
		ifAbsent: [ ^ self error: 'no such export: ' , aName ].
	^ self reportingErrorsDo: [
		method methodClass instanceSide new
			perform: method selector
			withArguments: anArray ]
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

{ #category : 'private' }
GumScript class >> emit: aMessage data: aByteArray [
	GumPrimitives
		gumPharoPost: (STONJSON toString: aMessage)
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
