Class {
	#name : 'GumDependency',
	#superclass : 'GumDetails',
	#instVars : [
		'name',
		'type'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'accessing' }
GumDependency >> name [
	^ name
]

{ #category : 'accessing' }
GumDependency >> type [
	^ type
]

{ #category : 'printing' }
GumDependency >> printOn: aStream [
	super printOn: aStream.
	aStream nextPut: $(; print: name; nextPut: $)
]
