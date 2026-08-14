Class {
	#name : 'GumScriptUIManager',
	#superclass : 'NonInteractiveUIManager',
	#category : 'GumPharo',
	#package : 'GumPharo'
}

{ #category : 'error handling' }
GumScriptUIManager >> handleError: anError [
	^ self handleError: anError log: true
]

{ #category : 'error handling' }
GumScriptUIManager >> handleError: anError log: aBoolean [
	GumScript reportError: anError.
	^ Processor terminateActive
]

{ #category : 'error handling' }
GumScriptUIManager >> unhandledErrorDefaultAction: anError [
	GumScript reportError: anError.
	^ Processor terminateActive
]
