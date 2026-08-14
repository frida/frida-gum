Class {
	#name : 'GumScriptContext',
	#superclass : 'Object',
	#instVars : [
		'id',
		'name',
		'source',
		'bindings',
		'handler',
		'exports'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'instance creation' }
GumScriptContext class >> id: anId name: aName source: aString [
	^ self new setId: anId name: aName source: aString
]

{ #category : 'accessing' }
GumScriptContext >> id [
	^ id
]

{ #category : 'accessing' }
GumScriptContext >> name [
	^ name
]

{ #category : 'running' }
GumScriptContext >> load [
	^ self during: [
		GumScript reportingErrorsDo: [
			self declareFreeVariables.
			Smalltalk compiler
				bindings: bindings values;
				evaluate: source ] ]
]

{ #category : 'running' }
GumScriptContext >> declareFreeVariables [
	self freeVariableNames do: [ :each |
		bindings at: each ifAbsentPut: [
			AdditionalBinding key: each value: nil ] ]
]

{ #category : 'running' }
GumScriptContext >> freeVariableNames [
	| ast |
	ast := Smalltalk compiler
		source: source;
		bindings: bindings values;
		isScripting: true;
		permitFaulty: true;
		parse.
	ast ifNil: [ ^ #() ].
	^ (ast allNotices select: [ :each | each isUndeclaredNotice ])
		collect: [ :each | each node name asSymbol ]
]

{ #category : 'running' }
GumScriptContext >> unload [
	^ self during: [
		GumScript reportingErrorsDo: [
			bindings do: [ :each |
				(each value respondsTo: #detach) ifTrue: [ each value detach ] ].
			bindings removeAll.
			self exports removeAll ] ]
]

{ #category : 'running' }
GumScriptContext >> deliver: aMessage [
	^ self during: [
		GumScript reportingErrorsDo: [
			(GumScript handleRpc: aMessage) ifFalse: [
				handler ifNotNil: [ handler value: aMessage ] ] ] ]
]

{ #category : 'running' }
GumScriptContext >> during: aBlock [
	^ GumCurrentScript value: self during: aBlock
]

{ #category : 'accessing' }
GumScriptContext >> onMessage: aBlock [
	handler := aBlock
]

{ #category : 'accessing' }
GumScriptContext >> bindings [
	^ bindings
]

{ #category : 'accessing' }
GumScriptContext >> exports [
	^ exports ifNil: [ exports := Dictionary new ]
]

{ #category : 'printing' }
GumScriptContext >> printOn: aStream [
	super printOn: aStream.
	aStream nextPut: $(; nextPutAll: name asString; nextPut: $)
]

{ #category : 'initialization' }
GumScriptContext >> setId: anId name: aName source: aString [
	id := anId.
	name := aName.
	source := aString.
	bindings := Dictionary new
]
