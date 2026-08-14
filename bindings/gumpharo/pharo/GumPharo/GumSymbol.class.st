Class {
	#name : 'GumSymbol',
	#superclass : 'GumDetails',
	#instVars : [
		'isGlobal',
		'type',
		'name',
		'address',
		'size'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'accessing' }
GumSymbol >> isGlobal [
	^ isGlobal
]

{ #category : 'accessing' }
GumSymbol >> type [
	^ type
]

{ #category : 'accessing' }
GumSymbol >> name [
	^ name
]

{ #category : 'accessing' }
GumSymbol >> address [
	^ address
]

{ #category : 'accessing' }
GumSymbol >> size [
	^ size
]

{ #category : 'printing' }
GumSymbol >> printOn: aStream [
	super printOn: aStream.
	aStream nextPut: $(; print: name; nextPut: $)
]
