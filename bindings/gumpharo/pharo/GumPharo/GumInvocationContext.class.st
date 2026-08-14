Class {
	#name : 'GumInvocationContext',
	#superclass : 'Object',
	#instVars : [
		'handle'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'instance creation' }
GumInvocationContext class >> on: anAddress [
	^ self new setHandle: anAddress asInteger
]

{ #category : 'arguments' }
GumInvocationContext >> argumentAt: anIndex [
	^ GumPrimitives gumInvocationContextGetNthArgument: handle n: anIndex - 1
]

{ #category : 'arguments' }
GumInvocationContext >> argumentAt: anIndex put: aValue [
	GumPrimitives
		gumInvocationContextReplaceNthArgument: handle
		n: anIndex - 1
		value: aValue.
	^ aValue
]

{ #category : 'accessing' }
GumInvocationContext >> returnValue [
	^ GumPrimitives gumInvocationContextGetReturnValue: handle
]

{ #category : 'accessing' }
GumInvocationContext >> returnValue: aValue [
	GumPrimitives gumInvocationContextReplaceReturnValue: handle value: aValue
]

{ #category : 'accessing' }
GumInvocationContext >> returnAddress [
	^ GumPrimitives gumInvocationContextGetReturnAddress: handle
]

{ #category : 'accessing' }
GumInvocationContext >> threadId [
	^ GumPrimitives gumInvocationContextGetThreadId: handle
]

{ #category : 'accessing' }
GumInvocationContext >> depth [
	^ GumPrimitives gumInvocationContextGetDepth: handle
]

{ #category : 'initialization' }
GumInvocationContext >> setHandle: anAddress [
	handle := anAddress
]
