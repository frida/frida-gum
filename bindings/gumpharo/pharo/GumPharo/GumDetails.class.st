Class {
	#name : 'GumDetails',
	#superclass : 'Object',
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'instance creation' }
GumDetails class >> fromBatch: anArray fields: fieldNames [
	| width results |
	width := fieldNames size.
	results := OrderedCollection new: anArray size // width.
	1 to: anArray size by: width do: [ :start |
		| each |
		each := self new.
		fieldNames doWithIndex: [ :fieldName :offset |
			each instVarNamed: fieldName put: (anArray at: start + offset - 1) ].
		results add: each ].
	^ results
]
