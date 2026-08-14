Class {
	#name : 'GumTranscript',
	#superclass : 'Object',
	#instVars : [
		'level',
		'pending'
	],
	#classVars : [
		'Displaced'
	],
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'instance creation' }
GumTranscript class >> level: aLevel [
	^ self new setLevel: aLevel
]

{ #category : 'installing' }
GumTranscript class >> install [
	Displaced ifNotNil: [ ^ self ].
	Displaced := Smalltalk at: #Transcript.
	Smalltalk at: #Transcript put: (self level: 'info')
]

{ #category : 'installing' }
GumTranscript class >> uninstall [
	Displaced ifNil: [ ^ self ].
	Smalltalk at: #Transcript put: Displaced.
	Displaced := nil
]

{ #category : 'writing' }
GumTranscript >> nextPutAll: aString [
	pending nextPutAll: aString asString.
	^ aString
]

{ #category : 'writing' }
GumTranscript >> nextPut: aCharacter [
	aCharacter = Character cr
		ifTrue: [ self flush ]
		ifFalse: [ pending nextPut: aCharacter ].
	^ aCharacter
]

{ #category : 'writing' }
GumTranscript >> show: anObject [
	^ self nextPutAll: anObject asString
]

{ #category : 'writing' }
GumTranscript >> print: anObject [
	^ self nextPutAll: anObject printString
]

{ #category : 'writing' }
GumTranscript >> << anObject [
	self nextPutAll: anObject asString.
	^ self
]

{ #category : 'writing' }
GumTranscript >> tab [
	^ self nextPutAll: String tab
]

{ #category : 'writing' }
GumTranscript >> space [
	^ self nextPutAll: String space
]

{ #category : 'writing' }
GumTranscript >> cr [
	self flush
]

{ #category : 'writing' }
GumTranscript >> crShow: anObject [
	self flush.
	^ self show: anObject
]

{ #category : 'writing' }
GumTranscript >> showln: anObject [
	self show: anObject.
	self flush
]

{ #category : 'writing' }
GumTranscript >> flush [
	| text |
	text := pending contents.
	pending reset.
	text ifNotEmpty: [ GumScript log: text level: level ]
]

{ #category : 'initialization' }
GumTranscript >> setLevel: aLevel [
	level := aLevel.
	pending := WriteStream on: String new
]
