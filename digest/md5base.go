package digest

import sasl "github.com/jellybean4/go-sasl"

const (
	MAX_CHALLENGE_LENGTH = 2048
	MAX_RESPONSE_LENGTH  = 4096
	DEFAULT_MAXBUF       = 65536
)

// Supported ciphers for 'auth-conf'
const (
	DES3 = iota
	RC4
	DES
	RC4_56
	RC4_40
)

// If QOP is set to 'auth-conf', a DIGEST-MD5 mechanism must have
// support for the DES and Triple DES cipher algorithms (optionally,
// support for RC4 [128/56/40 bit keys] ciphers) to provide for
// confidentiality. See RFC 2831 for details. This implementation
// provides support for DES, Triple DES and RC4 ciphers.
//
// The value of strength effects the strength of cipher used. The mappings
// of 'high', 'medium', and 'low' give the following behaviour.
//
//  HIGH_STRENGTH   - Triple DES
//                  - RC4 (128bit)
//  MEDIUM_STRENGTH - DES
//                  - RC4 (56bit)
//  LOW_SRENGTH     - RC4 (40bit)
const (
	DES_3_STRENGTH        = sasl.HIGH_STRENGTH
	RC4_STRENGTH          = sasl.HIGH_STRENGTH
	DES_STRENGTH          = sasl.MEDIUM_STRENGTH
	RC4_56_STRENGTH       = sasl.MEDIUM_STRENGTH
	RC4_40_STRENGTH       = sasl.LOW_STRENGTH
	UNSET                 = byte(0)
	SECURITY_LAYER_MARKER = ":00000000000000000000000000000000"
)

var (
	CIPHER_MASKS    = []byte{DES_3_STRENGTH, RC4_STRENGTH, DES_3_STRENGTH, RC4_56_STRENGTH, RC4_40_STRENGTH}
	CIPHER_TOKENS   = []string{"3des", "rc4", "des", "rc4-56", "rc4-40"}
	JCE_CIPHER_NAME = []string{"DESede/CBC/NoPadding", "RC4", "DES/CBC/NoPadding"}
)

// MD5Base is a utility class for DIGEST-MD5 mechanism.
// Provides utility methods and contains two inner classes which
// implement the SecurityCtx interface.
// The inner classes provide the funtionality to allow
// for quality-of-protection (QOP) with integrity checking and
// privacy.
type MD5Base struct {
	sasl.Sasl
}
