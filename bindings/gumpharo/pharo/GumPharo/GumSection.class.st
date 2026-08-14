Class {
	#name : 'GumSection',
	#superclass : 'GumDetails',
	#instVars : [
		'id',
		'name',
		'address',
		'size'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'accessing' }
GumSection >> id [
	^ id
]

{ #category : 'accessing' }
GumSection >> name [
	^ name
]

{ #category : 'accessing' }
GumSection >> address [
	^ address
]

{ #category : 'accessing' }
GumSection >> size [
	^ size
]

{ #category : 'printing' }
GumSection >> printOn: aStream [
	super printOn: aStream.
	aStream nextPut: $(; print: name; nextPut: $)
]
