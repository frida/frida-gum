Class {
	#name : 'BaselineOfGumPharo',
	#superclass : 'BaselineOf',
	#category : 'BaselineOfGumPharo',
	#package : 'BaselineOfGumPharo'
}

{ #category : 'baselines' }
BaselineOfGumPharo >> baseline: spec [
	<baseline>
	spec for: #common do: [
		spec postLoadDoIt: #installErrorReporting.
		spec
			package: 'GumPharo';
			package: 'GumPharo-Tests' with: [ spec requires: 'GumPharo' ].
		spec
			group: 'default' with: #( 'GumPharo' );
			group: 'tests' with: #( 'GumPharo-Tests' ) ]
]

{ #category : 'actions' }
BaselineOfGumPharo >> installErrorReporting [
	GumScript installErrorReporting
]
