Class {
	#name : 'GumMessage',
	#superclass : 'Object',
	#instVars : [
		'payload',
		'data'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'instance creation' }
GumMessage class >> fromHandle: aHandle [
	| json blob |
	json := GumPrimitives gumPharoMessagePayload: aHandle.
	blob := GumPrimitives gumPharoMessageData: aHandle.
	GumPrimitives gumPharoReleaseMessage: aHandle.
	^ self new setPayload: (STONJSON fromString: json) data: blob
]

{ #category : 'accessing' }
GumMessage >> payload [
	^ payload
]

{ #category : 'accessing' }
GumMessage >> data [
	^ data
]

{ #category : 'printing' }
GumMessage >> printOn: aStream [
	super printOn: aStream.
	aStream nextPut: $(; print: payload.
	data ifNotNil: [ aStream nextPutAll: ', '; print: data size; nextPutAll: ' bytes' ].
	aStream nextPut: $)
]

{ #category : 'initialization' }
GumMessage >> setPayload: aPayload data: aByteArray [
	payload := aPayload.
	data := aByteArray
]
