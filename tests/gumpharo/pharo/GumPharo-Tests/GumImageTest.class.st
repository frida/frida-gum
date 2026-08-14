Class {
	#name : 'GumImageTest',
	#superclass : 'TestCase',
	#category : 'GumPharo-Tests',
	#package : 'GumPharo-Tests'
}

{ #category : 'helpers' }
GumImageTest >> addressOfGetpid [
	^ GumPrimitives
		gumModuleFindExportByName:
			(GumPrimitives gumProcessFindModuleByName: self libraryName)
		symbolName: 'getpid'
]

{ #category : 'helpers' }
GumImageTest >> callGetpid [
	^ LibC uniqueInstance getpid
]

{ #category : 'helpers' }
GumImageTest >> libraryName [
	^ Smalltalk os isMacOS
		ifTrue: [ 'libSystem.B.dylib' ]
		ifFalse: [ 'libc.so.6' ]
]

{ #category : 'tests' }
GumImageTest >> testPluginIsRegistered [
	self assert: (Smalltalk vm listBuiltinModules includes: 'GumPlugin')
]

{ #category : 'tests' }
GumImageTest >> testStringArgumentAndResult [
	| module |
	module := GumPrimitives gumProcessFindModuleByName: self libraryName.
	self assert: (GumPrimitives gumModuleGetName: module) equals: self libraryName
]

{ #category : 'tests' }
GumImageTest >> testExportLookupAnswersAnAddress [
	self assert: self addressOfGetpid > 0
]

{ #category : 'tests' }
GumImageTest >> testHookObservesEnterAndLeave [
	| listener hits |
	hits := OrderedCollection new.
	listener := GumInterceptor
		attach: self addressOfGetpid
		onEnter: [ :context | hits add: #enter ]
		onLeave: [ :context | hits add: context returnValue ].
	self callGetpid.
	listener detach.
	self assert: hits size equals: 2.
	self assert: hits first equals: #enter.
	self assert: hits second > 0
]

{ #category : 'tests' }
GumImageTest >> testDetachedHookStopsFiring [
	| listener hits |
	hits := OrderedCollection new.
	listener := GumInterceptor
		attach: self addressOfGetpid
		onEnter: [ :context | hits add: #enter ]
		onLeave: nil.
	self callGetpid.
	listener detach.
	self callGetpid.
	self assert: hits size equals: 1
]

{ #category : 'tests' }
GumImageTest >> testInvocationContextAnswersTheThreadId [
	| listener seen |
	listener := GumInterceptor
		attach: self addressOfGetpid
		onEnter: [ :context | seen := context threadId ]
		onLeave: nil.
	self callGetpid.
	listener detach.
	self assert: seen notNil.
	self assert: seen > 0
]

{ #category : 'tests' }
GumImageTest >> testEnumeratingModulesReachesTheCallback [
	| seen callback |
	seen := OrderedCollection new.
	callback := FFICallback
		signature: #( bool ( void * module, void * userData ) )
		block: [ :module :userData |
			seen add: (GumPrimitives gumModuleGetName: module asInteger).
			true ].
	GumPrimitives
		gumProcessEnumerateModules: callback getHandle asInteger
		userData: 0.
	self assert: seen size > 1.
	self assert: (seen anySatisfy: [ :each | each includesSubstring: self libraryName ])
]

{ #category : 'tests' }
GumImageTest >> testProcessAnswersItsModules [
	| modules |
	modules := GumProcess modules.
	self assert: modules size > 1.
	self assert: (modules allSatisfy: [ :each | each isKindOf: GumModule ]).
	self assert: (modules anySatisfy: [ :each | each name = self libraryName ])
]

{ #category : 'tests' }
GumImageTest >> testProcessAnswersItsThreads [
	| threads |
	threads := GumProcess threads.
	self assert: threads size > 0.
	self assert: (threads allSatisfy: [ :each | each id > 0 ])
]

{ #category : 'tests' }
GumImageTest >> testModuleLookupByName [
	| module |
	module := GumProcess moduleNamed: self libraryName.
	self assert: module name equals: self libraryName.
	self assert: module path isString.
	self assert: (GumProcess moduleNamed: 'no-such-module-here') isNil
]

{ #category : 'tests' }
GumImageTest >> testModuleLookupByAddress [
	| module |
	module := GumProcess moduleContaining: self addressOfGetpid.
	self assert: module notNil.
	self assert: module name isString.
	self assert: (module exportNamed: 'getpid') equals: self addressOfGetpid
]

{ #category : 'tests' }
GumImageTest >> testExportLookupIsDirect [
	| module |
	module := GumProcess moduleNamed: self libraryName.
	self assert: (module exportNamed: 'getpid') equals: self addressOfGetpid.
	self assert: (module exportNamed: 'no-such-export') isNil
]

{ #category : 'tests' }
GumImageTest >> testModuleAnswersItsExportsAndSymbols [
	| module exports symbols |
	module := GumProcess moduleNamed: self libraryName.
	exports := module exports.
	symbols := module symbols.
	self assert: exports size > 0.
	self assert: (exports allSatisfy: [ :each | each isKindOf: GumExport ]).
	self assert: (exports anySatisfy: [ :each | each name = 'getpid' ]).
	self assert: symbols size > 0.
	self assert: (symbols anySatisfy: [ :each | each address > 0 ])
]

{ #category : 'tests' }
GumImageTest >> testModuleAnswersItsSections [
	| sections |
	sections := (GumProcess moduleNamed: self libraryName) sections.
	self assert: sections size > 0.
	self assert: (sections allSatisfy: [ :each | each name notNil ])
]

{ #category : 'tests' }
GumImageTest >> testNullHandleRaisesRatherThanCrashing [
	self should: [ GumPrimitives gumModuleGetName: 0 ] raise: Error
]

{ #category : 'tests' }
GumImageTest >> testSendCarriesPayloadAndData [
	GumScript send: (Dictionary new at: 'a' put: 1; yourself) data: #[1 2 3]
]

{ #category : 'tests' }
GumImageTest >> testLogEmitsEveryLevel [
	GumScript log: 'info here'.
	GumScript logDebug: 'debug here'.
	GumScript logWarning: 'warning here'.
	GumScript logError: 'error here'
]

{ #category : 'tests' }
GumImageTest >> testTranscriptReachesTheHost [
	GumTranscript install.
	[ Transcript show: 'via transcript'; cr ]
		ensure: [ GumTranscript uninstall ]
]

{ #category : 'tests' }
GumImageTest >> testErrorReportingIsInstalled [
	self assert: (UIManager default isKindOf: GumScriptUIManager)
]

{ #category : 'tests' }
GumImageTest >> testFailingExportIsReportedRatherThanRaised [
	self assert: (GumScript call: 'boom' arguments: #()) isNil
]

{ #category : 'tests' }
GumImageTest >> testRpcExportNamedAfterTheSelector [
	self assert: (GumScript call: 'answer' arguments: #()) equals: 42
]

{ #category : 'tests' }
GumImageTest >> testRpcExportNamedByThePragma [
	self assert: (GumScript call: 'sum' arguments: #(3 4)) equals: 7
]

{ #category : 'exports' }
GumImageTest >> answer [
	<gumExport>
	^ 42
]

{ #category : 'exports' }
GumImageTest >> add: a to: b [
	<gumExport: 'sum'>
	^ a + b
]

{ #category : 'exports' }
GumImageTest >> boom [
	<gumExport>
	^ 1 / 0
]
