package sasl

import "errors"
import "bytes"

var (
	// SEP is US-ASCII <NUL>
	SEP byte
)

// PlainClient implements the PLAIN SASL client mechanism
// http://ftp.isi.edu/in-notes/rfc2595.txt
type PlainClient struct {
	completed        bool
	pw               []byte
	authorizationID  string
	authenticationID string
}

// NewPlainClient creates a new PlainClient instance
func NewPlainClient(authorizationID, authenticationID string, pw []byte) (*PlainClient, error) {
	if len(authenticationID) <= 0 || pw == nil {
		return nil, errors.New("PLAIN: authorization ID and password must be specified")
	}
	client := &PlainClient{
		authenticationID: authenticationID,
		authorizationID:  authorizationID,
		pw:               pw,
	}
	return client, nil
}

// GetMechanismName retrieves this mechanism's name for to initiate the PLAIN protocol
// exchange.
func (c *PlainClient) GetMechanismName() string {
	return "PLAIN"
}

// HasInitialResponse test if has initial response
func (c *PlainClient) HasInitialResponse() bool {
	return true
}

// Dispose the sasl
func (c *PlainClient) Dispose() error {
	c.clearPassword()
	return nil
}

// EvaluateChallenge retrieves the initial response for the SASL command, which for
// PLAIN is the concatenation of authorization ID, authentication ID
// and password, with each component separated by the US-ASCII <NUL> byte.
func (c *PlainClient) EvaluateChallenge(challengeData []byte) ([]byte, error) {
	if c.completed {
		return nil, errors.New("PLAIN authentication already completed")
	}
	c.completed = true

	var authz []byte
	if len(c.authorizationID) > 0 {
		authz = []byte(c.authorizationID)
	}

	auth := []byte(c.authenticationID)
	answer := new(bytes.Buffer)
	if len(authz) > 0 {
		answer.Write(authz)
	}
	answer.WriteByte(SEP)
	answer.Write(auth)
	answer.WriteByte(SEP)
	answer.Write(c.pw)
	c.clearPassword()
	return answer.Bytes(), nil
}

// IsComplete determines whether this mechanism has completed.
// Plain completes after returning one response.
func (c *PlainClient) IsComplete() bool {
	return c.completed
}

// Unwrap the incoming buffer.
func (c *PlainClient) Unwrap(incoming []byte, offset, len int) ([]byte, error) {
	if c.completed {
		return nil, errors.New("PLAIN supports neither integrity nor privacy")
	}
	return nil, errors.New("PLAIN authentication not completed")
}

// Wrap the outgoing buffer.
func (c *PlainClient) Wrap(outgong []byte, offset, len int) ([]byte, error) {
	if c.completed {
		return nil, errors.New("PLAIN supports neither integrity nor privacy")
	}
	return nil, errors.New("PLAIN authentication not completed")
}

// GetNegotiatedProperty retrieves the negotiated property.
// This method can be called only after the authentication exchange has
// completed (i.e., when IsComplete() returns true); otherwise, an error
// is returned.
func (c *PlainClient) GetNegotiatedProperty(propName string) (interface{}, error) {
	if !c.completed {
		return nil, errors.New("PLAIN authentication not completed")
	}

	if propName == Sasl.QOP {
		return "auth", nil
	}
	return nil, nil
}

func (c *PlainClient) clearPassword() {
	if c.pw == nil {
		return
	}
	for i := range c.pw {
		c.pw[i] = 0
	}
	c.pw = nil
}
