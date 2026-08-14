Class {
	#name : 'GumScriptTest',
	#superclass : 'TestCase',
	#category : 'GumPharo-Tests',
	#package : 'GumPharo-Tests'
}

{ #category : 'helpers' }
GumScriptTest >> scriptNamed: aName source: aString [
	^ GumScriptContext id: aName hash name: aName source: aString
]

{ #category : 'helpers' }
GumScriptTest >> valueOf: aName in: aScript [
	^ (aScript bindings at: aName) value
]

{ #category : 'tests' }
GumScriptTest >> testTopLevelVariableIsDeclaredOnDemand [
	| script |
	script := self scriptNamed: 'solo' source: 'answer := 42'.
	script load.
	self assert: (self valueOf: #answer in: script) equals: 42
]

{ #category : 'tests' }
GumScriptTest >> testScriptsDoNotShareVariables [
	| one other |
	one := self scriptNamed: 'one' source: 'shared := 42'.
	other := self scriptNamed: 'other' source: 'shared := 1'.
	one load.
	other load.
	self assert: (self valueOf: #shared in: one) equals: 42.
	self assert: (self valueOf: #shared in: other) equals: 1
]

{ #category : 'tests' }
GumScriptTest >> testVariablesDoNotLeakIntoTheImage [
	(self scriptNamed: 'leaky' source: 'stowaway := 42') load.
	self deny: (Smalltalk includesKey: #stowaway).
	self deny: (Undeclared includesKey: #stowaway)
]

{ #category : 'tests' }
GumScriptTest >> testUnloadClearsTheNamespace [
	| script |
	script := self scriptNamed: 'transient' source: 'answer := 42'.
	script load.
	script unload.
	self assert: script bindings isEmpty
]

{ #category : 'tests' }
GumScriptTest >> testClosuresKeepSeeingTheirOwnVariables [
	| script |
	script := self scriptNamed: 'closing' source:
		'counter := 0.
		 GumScript onMessage: [ :each | counter := counter + 1 ]'.
	script load.
	script deliver: (GumMessage payload: 'ping' data: nil).
	script deliver: (GumMessage payload: 'ping' data: nil).
	self assert: (self valueOf: #counter in: script) equals: 2
]

{ #category : 'tests' }
GumScriptTest >> testCurrentScriptIsBoundWhileRunning [
	| script |
	script := self scriptNamed: 'aware' source: 'seen := GumCurrentScript value name'.
	script load.
	self assert: (self valueOf: #seen in: script) equals: 'aware'.
	self assert: GumCurrentScript value isNil
]

{ #category : 'tests' }
GumScriptTest >> testScriptExportIsCallable [
	| script |
	script := self scriptNamed: 'exporting' source:
		'GumScript export: ''add'' do: [ :a :b | a + b ]'.
	script load.
	self
		assert: (script during: [ GumScript invoke: 'add' arguments: #(3 4) ])
		equals: 7
]

{ #category : 'tests' }
GumScriptTest >> testScriptExportsAreNotShared [
	| one other |
	one := self scriptNamed: 'one' source:
		'GumScript export: ''answer'' do: [ 42 ]'.
	other := self scriptNamed: 'other' source: 'GumScript log: ''idle'''.
	one load.
	other load.
	self assert: (one exports includesKey: 'answer').
	self deny: (other exports includesKey: 'answer')
]

{ #category : 'tests' }
GumScriptTest >> testUnloadForgetsExports [
	| script |
	script := self scriptNamed: 'transient' source:
		'GumScript export: ''answer'' do: [ 42 ]'.
	script load.
	script unload.
	self assert: script exports isEmpty
]
