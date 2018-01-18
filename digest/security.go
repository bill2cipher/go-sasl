package digest

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"fmt"
)

const (
	CLIENT_INT_MAGIC  = "golang sasl integrity client-to-server magic key"
	SVR_INT_MAGIC     = "golang sasl integrity server-to-client magic key"
	CLIENT_CONF_MAGIC = "Digest H(A1) to client-to-server sealing key magic constant"
	SVR_CONF_MAGIC    = "Digest H(A1) to server-to-client sealing key magic constant"
)

var (
	EMPTY_BYTE_SLICE = make([]byte, 0)
)

// SecurityCtx is an interface used for classes implementing integrity checking and privacy
// for DIGEST-MD5 SASL mechanism implementation.
type SecurityCtx interface {
	// Wrap out-going message and return wrapped message
	Wrap(dest []byte, start, len int) ([]byte, error)

	// Unwrap incoming message and return original message
	Unwrap(outgoing []byte, start, len int) ([]byte, error)
}

// Integrity is a implementation of the SecurityCtx interface allowing
// for messages between the client and server to be integrity checked. After a
// successful DIGEST-MD5 authentication, integrity checking is invoked if the
// SASL QOP is set to 'auth-int'.
type Integrity struct {
	myKi        []byte
	peerKi      []byte
	mySeqNum    int
	peerSeqNum  int
	messageType []byte
	sequenceNum []byte
	md5Base     *MD5Base
}

type rc4Block struct {
	rc4Cipher *rc4.Cipher
}

func (r *rc4Block) BlockSize() int {
	return 1
}

func (r *rc4Block) Encrypt(dst, src []byte) {
	r.rc4Cipher.XORKeyStream(dst, src)
}

func (r *rc4Block) Decrypt(dst, src []byte) {
	r.rc4Cipher.XORKeyStream(src, dst)
}

// NewIntegrity create a new instance of Integrity
func NewIntegrity(clientMode bool) (*Integrity, error) {
	i := &Integrity{}
	if err := i.generateIntegrityKeyPair(clientMode); err != nil {
		return nil, err
	} else if err := i.md5Base.IntToNetworkByteOrder(1, i.messageType, 0, 2); err != nil {
		return nil, err
	}
	return i, nil
}

// generateKeyPair generate client-server, server-client key pairs for
// DIGEST-MD5 integrity checking.
func (i *Integrity) generateIntegrityKeyPair(clientMode bool) error {
	ciMagic := []byte(CLIENT_INT_MAGIC)
	siMagic := []byte(SVR_INT_MAGIC)

	// kic: key for protecting maps from client to server
	keyBuffer := make([]byte, len(i.md5Base.hA1)+len(ciMagic))
	copy(keyBuffer, i.md5Base.hA1)
	copy(keyBuffer[len(i.md5Base.hA1):], ciMagic)
	kic := md5.Sum(keyBuffer)

	// kis: key for protecting msgs from server to client
	copy(keyBuffer[len(i.md5Base.hA1):], siMagic)
	kis := md5.Sum(keyBuffer)

	if clientMode {
		i.myKi = kic[:]
		i.peerKi = kis[:]
	} else {
		i.myKi = kis[:]
		i.peerKi = kic[:]
	}
	return nil
}

// Wrap append MAC onto outgoing message
func (i *Integrity) Wrap(outgoing []byte, start, msgLen int) ([]byte, error) {
	if msgLen == 0 {
		return EMPTY_BYTE_SLICE, nil
	}

	wrapped := &bytes.Buffer{}
	if _, err := wrapped.Write(outgoing[start : start+msgLen]); err != nil {
		return nil, err
	}
	i.IncrementSeqNum()
	if mac, err := i.GetHMac(i.myKi, i.sequenceNum, outgoing, start, msgLen); err != nil {
		return nil, err
	} else if _, err := wrapped.Write(mac[:10]); err != nil {
		return nil, err
	} else if _, err := wrapped.Write(i.messageType[:2]); err != nil {
		return nil, err
	} else if wrapped.Write(i.sequenceNum[:4]); err != nil {
		return nil, err
	}
	return wrapped.Bytes(), nil
}

// Unwrap return verified message without MAC - only if the received MAC
// and re-generated MAC are the same
func (i *Integrity) Unwrap(incoming []byte, start, msgLen int) ([]byte, error) {
	if msgLen == 0 {
		return EMPTY_BYTE_SLICE, nil
	}
	mac := make([]byte, 10, 10)
	msg := make([]byte, msgLen-16, msgLen-16)
	msgType := make([]byte, 2, 2)
	seqNum := make([]byte, 4, 4)

	copy(msg, incoming[start:])
	copy(mac, incoming[start+len(msg):])
	copy(msgType, incoming[start+len(msg)+10:])
	copy(seqNum, incoming[start+len(msg)+12:])

	if expectedMac, err := i.GetHMac(i.peerKi, seqNum, msg, 0, len(msg)); err != nil {
		return nil, err
	} else if bytes.Compare(expectedMac, mac) != 0 {
		return EMPTY_BYTE_SLICE, nil
	} else if parsedSeqNum, err := i.md5Base.NetworkByteOrderToInt(seqNum, 0, 4); err != nil {
		return nil, err
	} else if parsedSeqNum != i.peerSeqNum {
		return nil, fmt.Errorf("DIGEST-MD5: Out of order sequencing of messages from server. Got: %d, Expected: %d",
			parsedSeqNum, i.peerSeqNum)
	}
	i.peerSeqNum++
	return msg, nil
}

// GetHMac generates MAC to be appended onto out-going messages.
func (i *Integrity) GetHMac(ki, seqnum, msg []byte, start, msgLen int) ([]byte, error) {
	seqAndMsg := &bytes.Buffer{}
	seqAndMsg.Write(seqnum[:4])
	seqAndMsg.Write(msg[start : start+msgLen])

	mac := hmac.New(md5.New, ki)
	if _, err := mac.Write(seqAndMsg.Bytes()); err != nil {
		return nil, err
	}
	return mac.Sum(nil)[:10], nil
}

// IncrementSeqNum increment own sequence number and set answer in NBO
// sequenceNum field.
func (i *Integrity) IncrementSeqNum() {
	i.md5Base.IntToNetworkByteOrder(i.mySeqNum, i.sequenceNum, 0, 4)
	i.mySeqNum++
}

// Privacy is implementation of the SecurityCtx interface allowing for messages
// between the client and server to be integrity checked and encrypted.
// After a successful DIGEST-MD5 authentication, privacy is invoked if the
// SASL QOP (quality-of-protection) is set to 'auth-conf'.
type Privacy struct {
	*Integrity
	encCipher cipher.Block
	decCipher cipher.Block
}

// NewPrivacy create a new Privacy instance for privacy check
func NewPrivacy(clientMode bool) (*Privacy, error) {
	p := &Privacy{}
	if intergity, err := NewIntegrity(clientMode); err != nil {
		return nil, err
	} else {
		p.Integrity = intergity
	}
	return p, nil
}

func (p *Privacy) generatePrivacyKeyPair(clientMode bool) error {
	ccmagic := []byte(CLIENT_CONF_MAGIC)
	scmagic := []byte(SVR_CONF_MAGIC)
	n := 0
	if p.md5Base.negotiatedCipher == CIPHER_TOKENS[RC4_40] {
		n = 5
	} else if p.md5Base.negotiatedCipher == CIPHER_TOKENS[RC4_56] {
		n = 7
	} else {
		n = 16
	}

	keyBuffer := make([]byte, n+len(ccmagic))
	copy(keyBuffer, p.md5Base.hA1[:n])
	copy(keyBuffer[n:], ccmagic)
	kcc := md5.Sum(keyBuffer)

	copy(keyBuffer[n:], scmagic)
	kcs := md5.Sum(keyBuffer)

	var myKc, peerKc []byte
	if clientMode {
		myKc = kcc[:]
		peerKc = kcs[:]
	} else {
		myKc = kcs[:]
		peerKc = kcc[:]
	}

	if encoder, err := buildCipher(p.md5Base.negotiatedCipher, myKc); err != nil {
		return nil, err
	} else if decoder, err := buildCipher(p.md5Base.negotiatedCipher, peerKc); err != nil {
		return nil, err
	} else {
		p.encCipher = encoder
		p.decCipher = decoder
	}
	return nil
}

func (p *Privacy) buildCipher(name string, key []byte) (cipher.Block, error) {
	switch name {
	case CIPHER_TOKENS[DES3]:
		return des.NewTripleDESCipher(key)
	case CIPHER_TOKENS[DES]:
		return des.NewCipher(key)
	case CIPHER_TOKENS[RC4], CIPHER_TOKENS[RC4_56], CIPHER_TOKENS[RC4_40]:
		if stream, err := rc4.NewCipher(key); err != nil {
			return nil, err
		} else {
			return &rc4Block{stream}, nil
		}
	default:
		return nil, fmt.Errorf("cipher %s not support", name)
	}
}

// func (p *Privacy) Wrap(outgoing []byte, start, msgLen int) ([]byte, error) {
// 	if msgLen == 0 {
// 		return EMPTY_BYTE_SLICE, nil
// 	}

// 	p.IncrementSeqNum()
// 	mac, err := p.GetHMac(p.myKi, p.sequenceNum, outgoing, start, msgLen)
// 	if err != nil {
// 		return nil, err
// 	}
// }
