package digest

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"fmt"
)

const (
	CLIENT_INT_MAGIC = "golang sasl integrity client-to-server magic key"
	SVR_INT_MAGIC    = "golang sasl integrity server-to-client magic key"
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
	hA1         []byte
	md5base     *MD5Base
}

// NewIntegrity create a new instance of Integrity
func NewIntegrity(clientMode bool) (*Integrity, error) {
	i := &Integrity{}
	if err := i.generateKeyPair(clientMode); err != nil {
		return nil, err
	} else if err := i.md5base.IntToNetworkByteOrder(1, i.messageType, 0, 2); err != nil {
		return nil, err
	}
	return i, nil
}

// generateKeyPair generate client-server, server-client key pairs for
// DIGEST-MD5 integrity checking.
func (i *Integrity) generateKeyPair(clientMode bool) error {
	ciMagic := []byte(CLIENT_INT_MAGIC)
	siMagic := []byte(SVR_INT_MAGIC)
	md5Digest := md5.New()

	// kic: key for protecting maps from client to server
	keyBuffer := bytes.Buffer{}
	keyBuffer.Write(i.hA1)
	keyBuffer.Write(ciMagic)
	kic := md5Digest.Sum(keyBuffer.Bytes())

	// kis: key for protecting msgs from server to client
	keyBuffer.Write(i.hA1)
	keyBuffer.Write(siMagic)
	kis := md5Digest.Sum(keyBuffer.Bytes())

	if clientMode {
		i.myKi = kic
		i.peerKi = kis
	} else {
		i.myKi = kis
		i.peerKi = kic
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

	copy(msg, incoming[start:start+len(msg)])
	copy(mac, incoming[start+len(msg):start+len(msg)+10])
	copy(msgType, incoming[start+len(msg)+10:start+len(msg)+12])
	copy(seqNum, incoming[start+len(msg)+12:start+len(msg)+16])

	if expectedMac, err := i.GetHMac(i.peerKi, seqNum, msg, 0, len(msg)); err != nil {
		return nil, err
	} else if bytes.Compare(expectedMac, mac) != 0 {
		return EMPTY_BYTE_SLICE, nil
	} else if parsedSeqNum, err := i.md5base.NetworkByteOrderToInt(seqNum, 0, 4); err != nil {
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
	return mac.Sum(nil), nil
}

// IncrementSeqNum increment own sequence number and set answer in NBO
// sequenceNum field.
func (i *Integrity) IncrementSeqNum() {
	i.md5base.IntToNetworkByteOrder(i.mySeqNum, i.sequenceNum, 0, 4)
	i.mySeqNum++
}
