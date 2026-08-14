Class {
	#name : 'GumInvocationListener',
	#superclass : 'Object',
	#instVars : [
		'handle',
		'onEnterCallback',
		'onLeaveCallback'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'instance creation' }
GumInvocationListener class >> onEnter: enterBlock onLeave: leaveBlock [
	^ self new onEnter: enterBlock onLeave: leaveBlock
]

{ #category : 'initialization' }
GumInvocationListener >> onEnter: enterBlock onLeave: leaveBlock [
	onEnterCallback := self callbackFor: enterBlock.
	onLeaveCallback := self callbackFor: leaveBlock.
	handle := GumPrimitives
		gumPharoListenerNewOnEnter: (self addressOf: onEnterCallback)
		onLeave: (self addressOf: onLeaveCallback)
]

{ #category : 'attaching' }
GumInvocationListener >> detach [
	GumInterceptor detach: self
]

{ #category : 'accessing' }
GumInvocationListener >> handle [
	^ handle
]

{ #category : 'private' }
GumInvocationListener >> callbackFor: aBlock [
	^ aBlock ifNotNil: [
		FFICallback
			signature: #( void ( void * context ) )
			block: [ :context |
				GumScript reportingErrorsDo: [
					aBlock value: (GumInvocationContext on: context) ] ] ]
]

{ #category : 'private' }
GumInvocationListener >> addressOf: aCallback [
	^ aCallback ifNil: [ 0 ] ifNotNil: [ aCallback getHandle asInteger ]
]
