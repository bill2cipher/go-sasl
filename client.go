package sasl

// Client performs SASL authentication as a client.
//
// A protocol library such as one for LDAP gets an instance of this
// class in order to perform authentication defined by a specific SASL
// mechanism. Invoking methods on the Client instance
// process challenges and create responses according to the SASL
// mechanism implemented by the Client.
// As the authentication proceeds, the instance
// encapsulates the state of a SASL client's authentication exchange.
//
// If the mechanism has an initial response, the library invokes
// EvaludateChallenge() with an empty
// challenge and to get initial response.
// Protocols such as IMAP4, which do not include an initial response with
// their first authentication command to the server, initiates the
// authentication without first calling HasInitialResponse()
// or EvaludateChallenge().
// When the server responds to the command, it sends an initial challenge.
// For a SASL mechanism in which the client sends data first, the server should
// have issued a challenge with no data. This will then result in a call
// (on the client) to EvaludateChallenge() with an empty challenge.
type Client interface {
	// Returns the IANA-registered mechanism name of this SASL client.
	// (e.g. "CRAM-MD5", "GSSAPI").
	GetMechanismName() string

	// Determines whether this mechanism has an optional initial response.
	// If true, caller should call EaluateChallenge() with an
	// empty array to get the initial response.
	HasInitialResponse() bool

	// Evaluates the challenge data and generates a response.
	// If a challenge is received from the server during the authentication
	// process, this method is called to prepare an appropriate next
	// response to submit to the server.
	// The challenge array may have zero length.
	// The response to send to the server may has zero length.
	// It is null if the challenge accompanied a "SUCCESS" status and the challenge
	// only contains data for the client to update its state and no response
	// needs to be sent to the server. The response is a zero-length byte
	// array if the client is to send a response with no data.
	EvaluateChallenge(challenge []byte) ([]byte, error)

	// Determines whether the authentication exchange has completed.
	// This method may be called at any time, but typically, it
	// will not be called until the caller has received indication
	// from the server (in a protocol-specific manner) that the exchange has completed.
	IsComplete() bool

	// Unwraps a byte array received from the server.
	// This method can be called only after the authentication exchange has
	// completed (i.e., when IsComplete() returns true) and only if
	// the authentication exchange has negotiated integrity and/or privacy
	// as the quality of protection; otherwise, an error is returned.
	Unwrap(incoming []byte, offset, len int) ([]byte, error)

	// Wraps a byte array to be sent to the server.
	// This method can be called only after the authentication exchange has
	// completed (i.e., when IsComplete() returns true) and only if
	// the authentication exchange has negotiated integrity and/or privacy
	// as the quality of protection; otherwise, an error is returned.
	Wrap(outgoing []byte, offset, len int) ([]byte, error)

	// Retrieves the negotiated property.
	// This method can be called only after the authentication exchange has
	// completed (i.e., when IsComplete() returns true); otherwise, an
	// error is returned.
	GetNegotiatedProperty(propName string) (interface{}, error)

	// Disposes of any system resources or security-sensitive information
	// the SaslClient might be using. Invoking this method invalidates
	// the SaslClient instance. This method is idempotent.
	Dispose() error
}
