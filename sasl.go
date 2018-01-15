package sasl

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// SaslPropertyQop is a property that specifies the quality-of-protection to use.
	// The property contains a comma-separated, ordered list
	// of quality-of-protection values that the
	// client or server is willing to support.  A qop value is one of
	//
	// "auth" - authentication only
	// "auth-int" - authentication plus integrity protection
	// "auth-conf" - authentication plus integrity and confidentiality protection
	//
	// The order of the list specifies the preference order of the client or
	// server. If this property is absent, the default qop is "auth".
	// The value of this constant is "golang.security.sasl.qop".
	SaslPropertyQop = "golang.security.sasl.qop"

	// SaslPropertyStrength is a property that specifies the cipher strength to use.
	// The property contains a comma-separated, ordered list
	// of cipher strength values that
	// the client or server is willing to support. A strength value is one of
	//
	// "low", "medium", "high"
	//
	// The order of the list specifies the preference order of the client or
	// server.  An implementation should allow configuration of the meaning
	// of these values.  An application may use the Java Cryptography
	// Extension (JCE) with JCE-aware mechanisms to control the selection of
	// cipher suites that match the strength values.
	// If this property is absent, the default strength is
	// "high,medium,low".
	// The value of this constant is "golang.security.sasl.strength".
	SaslPropertyStrength = "golang.security.sasl.strength"

	// SaslPropertyServerAuth is a property that specifies whether the
	// server must authenticate to the client. The property contains
	// "true" if the server must authenticate the to client;
	// "false" otherwise. The default is "false". The value of this
	// constant is "golang.security.sasl.server.authentication".
	SaslPropertyServerAuth = "golang.security.sasl.server.authentication"

	// SaslPropertyBoundServerName is a property that specifies the bound server name for
	// an unbound server. A server is created as an unbound server by setting
	// the serverName argument in CreateSaslServer as null.
	// The property contains the bound host name after the authentication
	// exchange has completed. It is only available on the server side.
	// The value of this constant is
	// golang.security.sasl.bound.server.name".
	SaslPropertyBoundServerName = "golang.security.sasl.bound.server.name"

	// SaslPropertyMaxBuffer is a property that specifies the maximum size of the receive
	// buffer in bytes of SaslClient/SaslServer.
	// The property contains the string representation of an integer.
	// If this property is absent, the default size
	// is defined by the mechanism.
	// The value of this constant is "golang.security.sasl.maxbuffer".
	SaslPropertyMaxBuffer = "golang.security.sasl.maxbuffer"

	// SaslPropertyRawSendSize is a property that specifies the maximum size of the raw send
	// buffer in bytes of SaslClient/ SaslServer.
	// The property contains the string representation of an integer.
	// The value of this property is negotiated between the client and server
	// during the authentication exchange.
	// The value of this constant is "golang.security.sasl.rawsendsize".
	SaslPropertyRawSendSize = "golang.security.sasl.rawsendsize"

	// SaslPropertyReuse is a property that specifies whether to reuse previously
	// authenticated session information. The property contains "true" if the
	// mechanism implementation may attempt to reuse previously authenticated
	// session information; it contains "false" if the implementation must
	// not reuse previously authenticated session information.  A setting of
	// "true" serves only as a hint: it does not necessarily entail actual
	// reuse because reuse might not be possible due to a number of reasons,
	// including, but not limited to, lack of mechanism support for reuse,
	// expiration of reusable information, and the peer's refusal to support
	// reuse.
	//
	// The property's default value is "false".  The value of this constant
	// is "golang.security.sasl.reuse".
	//
	// Note that all other parameters and properties required to create a
	// SASL client/server instance must be provided regardless of whether
	// this property has been supplied. That is, you cannot supply any less
	// information in anticipation of reuse.
	//
	// Mechanism implementations that support reuse might allow customization
	// of its implementation, for factors such as cache size, timeouts, and
	// criteria for reusability. Such customizations are
	// implementation-dependent.
	SaslPropertyReuse = "golang.security.sasl.reuse"

	// SaslPropertyPolicyNoPlainText is a property that specifies
	// whether mechanisms susceptible to simple plain passive attacks (e.g.,
	// "PLAIN") are not permitted. The property
	// contains "true" if such mechanisms are not permitted;
	// "false" if such mechanisms are permitted.
	// The default is "false". The value of this constant is
	// "golang.security.sasl.policy.noplaintext".
	SaslPropertyPolicyNoPlainText = "golang.security.sasl.policy.noplaintext"

	// SaslPropertyPolicyNoActive is a property that specifies whether
	// mechanisms susceptible to active (non-dictionary) attacks
	// are not permitted. The property contains "true"
	// if mechanisms susceptible to active attacks
	// are not permitted; "false" if such mechanisms are permitted.
	// The default is "false". The value of this constant is
	// "golang.security.sasl.policy.noactive".
	SaslPropertyPolicyNoActive = "golang.security.sasl.policy.noactive"

	// SaslPropertyPolicyNoDictionary is a property that specifies whether
	// mechanisms susceptible to passive dictionary attacks are not permitted.
	// The property contains "true"
	// if mechanisms susceptible to dictionary attacks are not permitted;
	// "false" if such mechanisms are permitted.
	// The default is "false". The value of this constant is
	// "golang.security.sasl.policy.nodictionary".
	SaslPropertyPolicyNoDictionary = "golang.security.sasl.policy.nodictionary"

	// SaslPropertyPolicyNoAnonymous is a property that specifies whether mechanisms that accept
	// anonymous login are not permitted. The property contains "true"
	// if mechanisms that accept anonymous login are not permitted;
	// "false"
	// if such mechanisms are permitted. The default is "false".
	// The value of this constant is
	// "golang.security.sasl.policy.noanonymous".
	SaslPropertyPolicyNoAnonymous = "golang.security.sasl.policy.noanonymous"

	// SaslPropertyPolicyForwardSecrecy is a property that specifies whether mechanisms that implement
	// forward secrecy between sessions are required. Forward secrecy
	// means that breaking into one session will not automatically
	// provide information for breaking into future sessions.
	// The property contains "true" if mechanisms that implement forward secrecy
	// between sessions are required; "false" if such mechanisms
	// are not required. The default is "false".
	// The value of this constant is
	// "golang.security.sasl.policy.forward".
	SaslPropertyPolicyForwardSecrecy = "golang.security.sasl.policy.forward"

	// SaslPropertyPolicyPassCredentials is a property that specifies whether
	// mechanisms that pass client credentials are required. The property
	// contains "true" if mechanisms that pass
	// client credentials are required; "false"
	// if such mechanisms are not required. The default is "false".
	// The value of this constant is
	// "golang.security.sasl.policy.credentials".
	SaslPropertyPolicyPassCredentials = "golang.security.sasl.policy.credentials"

	// SaslPropertyCredentials is a property that specifies the credentials to use.
	// The property contains a mechanism-specific golang credential object.
	// Mechanism implementations may examine the value of this property
	// to determine whether it is a class that they support.
	// The property may be used to supply credentials to a mechanism that
	// supports delegated authentication.
	// The value of this constant is
	// "golang.security.sasl.credentials".
	SaslPropertyCredentials = "golang.security.sasl.credentials"
)

const (
	SASL_LOGGER_NAME          = "golang.security.sasl"
	MAX_SEND_BUF              = "golang.security.sasl.sendmaxbuffer"
	NO_PROTECTION             = byte(1)
	INTEGRITY_ONLY_PROTECTION = byte(2)
	PRIVACY_PROTECTION        = byte(4)
	LOW_STRENGTH              = byte(1)
	MEDIUM_STRENGTH           = byte(2)
	HIGH_STRENGTH             = byte(4)
)

var (
	DEFAULT_QOP      = []byte{NO_PROTECTION}
	QOP_TOKENS       = []string{"auth-conf", "auth-int", "auth"}
	QOP_MASKS        = []byte{PRIVACY_PROTECTION, INTEGRITY_ONLY_PROTECTION, NO_PROTECTION}
	DEFAULT_STRENGTH = []byte{HIGH_STRENGTH, MEDIUM_STRENGTH, LOW_STRENGTH}
	STRENGTH_TOKENS  = []string{"low", "medium", "high"}
	STRENGTH_MASKS   = []byte{LOW_STRENGTH, MEDIUM_STRENGTH, HIGH_STRENGTH}
)

// Sasl defines the policy of how to locate, load, and instantiate
// SASL clients and servers.
type Sasl struct {
	Completed      bool
	Privacy        bool
	Integrity      bool
	Qop            []byte
	AllQop         byte
	Strength       []byte
	SendMaxBufSize int
	RecvMaxBufSize int
	RawSendSize    int
}

// IsCompete determines whether the authentication exchange has completed.
// This method may be called at any time, but typically, it
// will not be called until the caller has received indication
// from the server (in a protocol-specific manner) that the exchange has completed.
func (s *Sasl) IsCompete() bool {
	return s.Completed
}

// GetNegotiatedProperty retrieves the negotiated property.
// This method can be called only after the authentication exchange has
// completed (i.e., when IsComplete() returns true); otherwise, an
// error is returned.
func (s *Sasl) GetNegotiatedProperty(propName string) (interface{}, error) {
	if !s.Completed {
		return nil, errors.New("sasl authentication not completed")
	}
	switch propName {
	case SaslPropertyQop:
		if s.Privacy {
			return "auth-conf", nil
		} else if s.Integrity {
			return "auth-int", nil
		} else {
			return "auth", nil
		}
	case SaslPropertyMaxBuffer:
		return fmt.Sprintf("%d", s.RecvMaxBufSize), nil
	case SaslPropertyRawSendSize:
		return fmt.Sprintf("%d", s.RawSendSize), nil
	case SaslPropertyMaxBuffer:
		return fmt.Sprintf("%d", s.SendMaxBufSize), nil
	default:
		return nil, nil
	}
}

func (s *Sasl) combineMasks(in []byte) byte {
	answer := byte(0)
	for i := 0; i < len(in); i++ {
		answer |= in[i]
	}
	return answer
}

func (s *Sasl) findPreferredMask(pref byte, in []byte) byte {
	for i := 0; i < len(in); i++ {
		if (in[i] & pref) != 0 {
			return in[i]
		}
	}
	return 0
}

func (s *Sasl) parseQop(qop string) ([]byte, error) {
	return s.parseQop2(qop, nil, false)
}

func (s *Sasl) parseQop2(qop string, saveTokens []string, ignore bool) ([]byte, error) {
	if qop == "" {
		return DEFAULT_QOP, nil
	}
	return s.parseProp(SaslPropertyQop, qop, QOP_TOKENS, QOP_MASKS, saveTokens, ignore)
}

func (s *Sasl) parseStrength(strength string) ([]byte, error) {
	if len(strength) <= 0 {
		return DEFAULT_STRENGTH, nil
	}
	return s.parseProp(SaslPropertyStrength, strength, STRENGTH_TOKENS, STRENGTH_MASKS, nil, false)
}

func (s *Sasl) parseProp(propName, propVal string, vals []string, masks []byte, tokens []string, ignore bool) ([]byte, error) {
	found := false
	parts := strings.Split(propVal, ", \t\n")
	answer := make([]byte, len(vals), len(vals))
	i := 0
	for i = 0; i < len(answer) && i < len(parts); i++ {
		found = false
		for j := 0; !found && j < len(vals); j++ {
			if strings.ToLower(parts[i]) != strings.ToLower(vals[i]) {
				continue
			}
			found = true
			answer[i] = masks[j]
			if tokens != nil {
				tokens[j] = parts[i]
			}
		}
		if !found && !ignore {
			return nil, fmt.Errorf("Invalid token in %s: %s", propName, propVal)
		}
	}

	for j := i; j < len(answer); j++ {
		answer[j] = 0
	}
	return answer, nil
}

// Returns the integer represented by 4 bytes in network byte order.
func (s *Sasl) networkByteOrderToInt(buf []byte, start, count int) (int, error) {
	if count > 4 {
		return 0, errors.New("cannot handle more than 4 bytes")
	}
	result := 0
	for idx := 0; idx < count; idx++ {
		result <<= 8
		result |= int(buf[start+idx]) & 0xFF
	}
	return result, nil
}

// Encodes an integer into 4 bytes in network byte order in the buffer
func (s *Sasl) intToNetworkByteOrder(num int, buf []byte, start, count int) error {
	if count > 4 {
		return errors.New("cannot handle more than 4 bytes")
	}
	uNum := uint32(num)
	for idx := count - 1; idx >= 0; idx-- {
		buf[start+idx] = byte(uNum & 0xFF)
		uNum >>= 8
	}
	return nil
}
