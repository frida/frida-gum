Class {
	#name : 'GumProcess',
	#superclass : 'Object',
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'looking up' }
GumProcess class >> id [
	^ GumPrimitives gumProcessGetId
]

{ #category : 'looking up' }
GumProcess class >> mainModule [
	^ GumModule on: GumPrimitives gumProcessGetMainModule
]

{ #category : 'enumerating' }
GumProcess class >> threads [
	^ GumThread
		fromBatch: (GumPrimitives gumProcessEnumerateThreadsAll: 0)
		fields: GumPrimitives gumProcessEnumerateThreadsAllFields
]

{ #category : 'looking up' }
GumProcess class >> moduleNamed: aName [
	^ GumModule named: aName
]

{ #category : 'looking up' }
GumProcess class >> moduleContaining: anAddress [
	^ GumModule containing: anAddress
]

{ #category : 'enumerating' }
GumProcess class >> modules [
	^ (GumPrimitives gumProcessEnumerateModulesAll)
		collect: [ :each | GumModule on: each ]
]
