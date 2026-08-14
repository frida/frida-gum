Class {
	#name : 'GumImport',
	#superclass : 'GumDetails',
	#instVars : [
		'type',
		'name',
		'module',
		'address',
		'slot'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'accessing' }
GumImport >> type [
	^ type
]

{ #category : 'accessing' }
GumImport >> name [
	^ name
]

{ #category : 'accessing' }
GumImport >> module [
	^ module
]

{ #category : 'accessing' }
GumImport >> address [
	^ address
]

{ #category : 'accessing' }
GumImport >> slot [
	^ slot
]

{ #category : 'printing' }
GumImport >> printOn: aStream [
	super printOn: aStream.
	aStream nextPut: $(; print: name; nextPut: $)
]
