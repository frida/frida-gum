Class {
	#name : 'GumModule',
	#superclass : 'Object',
	#instVars : [
		'handle'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'instance creation' }
GumModule class >> on: aHandle [
	^ aHandle = 0 ifFalse: [ self new setHandle: aHandle ]
]

{ #category : 'instance creation' }
GumModule class >> named: aName [
	^ self on: (GumPrimitives gumProcessFindModuleByName: aName)
]

{ #category : 'instance creation' }
GumModule class >> containing: anAddress [
	^ self on: (GumPrimitives gumProcessFindModuleByAddress: anAddress)
]

{ #category : 'accessing' }
GumModule >> name [
	^ GumPrimitives gumModuleGetName: handle
]

{ #category : 'accessing' }
GumModule >> path [
	^ GumPrimitives gumModuleGetPath: handle
]

{ #category : 'enumerating' }
GumModule >> imports [
	^ GumImport
		fromBatch: (GumPrimitives gumModuleEnumerateImportsAll: handle)
		fields: GumPrimitives gumModuleEnumerateImportsAllFields
]

{ #category : 'enumerating' }
GumModule >> exports [
	^ GumExport
		fromBatch: (GumPrimitives gumModuleEnumerateExportsAll: handle)
		fields: GumPrimitives gumModuleEnumerateExportsAllFields
]

{ #category : 'enumerating' }
GumModule >> symbols [
	^ GumSymbol
		fromBatch: (GumPrimitives gumModuleEnumerateSymbolsAll: handle)
		fields: GumPrimitives gumModuleEnumerateSymbolsAllFields
]

{ #category : 'enumerating' }
GumModule >> sections [
	^ GumSection
		fromBatch: (GumPrimitives gumModuleEnumerateSectionsAll: handle)
		fields: GumPrimitives gumModuleEnumerateSectionsAllFields
]

{ #category : 'enumerating' }
GumModule >> dependencies [
	^ GumDependency
		fromBatch: (GumPrimitives gumModuleEnumerateDependenciesAll: handle)
		fields: GumPrimitives gumModuleEnumerateDependenciesAllFields
]

{ #category : 'looking up' }
GumModule >> exportNamed: aName [
	| address |
	address := GumPrimitives gumModuleFindExportByName: handle symbolName: aName.
	^ address = 0 ifFalse: [ address ]
]

{ #category : 'looking up' }
GumModule >> symbolNamed: aName [
	| address |
	address := GumPrimitives gumModuleFindSymbolByName: handle symbolName: aName.
	^ address = 0 ifFalse: [ address ]
]

{ #category : 'accessing' }
GumModule >> handle [
	^ handle
]

{ #category : 'printing' }
GumModule >> printOn: aStream [
	super printOn: aStream.
	aStream nextPut: $(; nextPutAll: self name asString; nextPut: $)
]

{ #category : 'initialization' }
GumModule >> setHandle: aHandle [
	handle := aHandle
]
