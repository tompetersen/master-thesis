# Master thesis
Topic (german): "Datenschutzfreundliche Speicherung unternehmensinterner Überwachungsdaten mittels Pseudonymisierung und kryptographischer Schwellwertschemata"

## Contents

- **expose**: a small topic overview written beforehand _(LaTeX)_
- **thesis**: the thesis itself _(LaTeX)_
- **sources**: implementations of different system components _(python)_
	- **proxy**: a syslog proxy for altering syslog messages including the possibility of writing custom plugins (pseudonym plugin already included)
	- **pseudo-service**: django-based service handling pseudonym storage and threshold scheme communication
	- **threshold-client**: CLI application for share owners of the threshold scheme
	- **threshold-crypto**: stateless ElGamal-based threshold decryption library
	- (_threshold-test: test implementations for some algorithms_)