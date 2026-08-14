Class {
	#name : 'GumExport',
	#superclass : 'GumDetails',
	#instVars : [
		'type',
		'name',
		'address',
		'size'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'accessing' }
GumExport >> type [
	^ type
]

{ #category : 'accessing' }
GumExport >> name [
	^ name
]

{ #category : 'accessing' }
GumExport >> address [
	^ address
]

{ #category : 'accessing' }
GumExport >> size [
	^ size
]

{ #category : 'printing' }
GumExport >> printOn: aStream [
	super printOn: aStream.
	aStream nextPut: $(; print: name; nextPut: $)
]
