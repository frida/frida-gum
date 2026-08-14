Class {
	#name : 'GumInterceptor',
	#superclass : 'Object',
	#classVars : [
		'Handle'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'attaching' }
GumInterceptor class >> attach: target onEnter: enterBlock [
	^ self attach: target onEnter: enterBlock onLeave: nil
]

{ #category : 'attaching' }
GumInterceptor class >> attach: target onLeave: leaveBlock [
	^ self attach: target onEnter: nil onLeave: leaveBlock
]

{ #category : 'attaching' }
GumInterceptor class >> attach: target onEnter: enterBlock onLeave: leaveBlock [
	| listener status |
	listener := GumInvocationListener onEnter: enterBlock onLeave: leaveBlock.
	status := GumPrimitives
		gumInterceptorAttach: self handle
		target: target
		listener: listener handle
		options: 0.
	status = 0 ifFalse: [
		^ self error: 'unable to attach to ' , target printString ].
	^ listener
]

{ #category : 'attaching' }
GumInterceptor class >> detach: aListener [
	GumPrimitives gumInterceptorDetach: self handle listener: aListener handle
]

{ #category : 'attaching' }
GumInterceptor class >> revert: target [
	GumPrimitives gumInterceptorRevert: self handle target: target
]

{ #category : 'transactions' }
GumInterceptor class >> transactionDo: aBlock [
	GumPrimitives gumInterceptorBeginTransaction: self handle.
	^ aBlock ensure: [
		GumPrimitives gumInterceptorEndTransaction: self handle ]
]

{ #category : 'private' }
GumInterceptor class >> handle [
	^ Handle ifNil: [ Handle := GumPrimitives gumInterceptorObtain ]
]
