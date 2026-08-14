Class {
	#name : 'GumThread',
	#superclass : 'GumDetails',
	#instVars : [
		'flags',
		'id',
		'name',
		'state'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'accessing' }
GumThread >> id [
	^ id
]

{ #category : 'accessing' }
GumThread >> name [
	^ name
]

{ #category : 'accessing' }
GumThread >> state [
	^ state
]

{ #category : 'accessing' }
GumThread >> flags [
	^ flags
]

{ #category : 'printing' }
GumThread >> printOn: aStream [
	super printOn: aStream.
	aStream nextPut: $(; print: id; nextPut: $)
]
