package digest

const (
	MAX_CHALLENGE_LENGTH = 2048
	MAX_RESPONSE_LENGTH  = 4096
	DEFAULT_MAXBUF       = 65536
)

var (
	CIPHER_TOKENS   = []string{"3des", "rc4", "des", "rc4-56", "rc4-40"}
	JCE_CIPHER_NAME = []string{
		"DESede/CBC/NoPadding",
		"RC4",
		"DES/CBC/NoPadding",
	}
)

const (
	DES3 = iota
	RC4
	DES
	RC4_56
	RC4_40
)

// DigestMD5Base is a utility class for DIGEST-MD5 mechanism.
// Provides utility methods and contains two inner classes which
// implement the SecurityCtx interface.
// The inner classes provide the funtionality to allow
// for quality-of-protection (QOP) with integrity checking and
// privacy.
type DigestMD5Base struct {
}
