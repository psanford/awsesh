package server

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	emptyPassword                   = ""
	defaultPassword                 = ""
	cmdHmacStart    tpmutil.Command = 0x0000015B
)

type TpmHmac struct {
	tpm    *tpmDev
	handle tpmutil.Handle
	buf    bytes.Buffer
}

func (h *TpmHmac) Write(b []byte) (int, error) {
	return h.buf.Write(b)
}

func (h *TpmHmac) Sum(b []byte) []byte {
	msg, err := h.tpm.HmacMsg(h.handle, h.buf.Bytes())
	if err != nil {
		panic(err)
	}
	if b != nil {
		b = append(b, msg...)
		return b
	}
	return msg
}

func (h *TpmHmac) Size() int {
	return sha256.Size
}

func (h *TpmHmac) BlockSize() int {
	return sha256.BlockSize
}

func (h *TpmHmac) Reset() {
	h.buf.Reset()
}

type tpmDev struct {
	mu  sync.Mutex
	tpm io.ReadWriteCloser
}

func (t *tpmDev) HmacMsg(handle tpmutil.Handle, msg []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	seqAuth := ""
	seq, err := t.hmacStart(seqAuth, handle, tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(t.tpm, seq)

	maxDigestBuffer := 1024
	for len(msg) > maxDigestBuffer {
		if err = tpm2.SequenceUpdate(t.tpm, seqAuth, seq, msg[:maxDigestBuffer]); err != nil {
			return nil, err
		}
		msg = msg[maxDigestBuffer:]
	}

	digest, _, err := tpm2.SequenceComplete(t.tpm, seqAuth, seq, tpm2.HandleNull, msg)
	if err != nil {
		return nil, err
	}

	return digest, nil
}

func (t *tpmDev) hmacStart(sequenceAuth string, handle tpmutil.Handle, hashAlg tpm2.Algorithm) (seqHandle tpmutil.Handle, err error) {

	auth, err := encodeAuthArea(tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(sequenceAuth)})
	if err != nil {
		return 0, err
	}
	out, err := tpmutil.Pack(handle)
	if err != nil {
		return 0, err
	}
	Cmd, err := concat(out, auth)
	if err != nil {
		return 0, err
	}

	resp, err := runCommand(t.tpm, tpm2.TagSessions, cmdHmacStart, tpmutil.RawBytes(Cmd), tpmutil.U16Bytes(sequenceAuth), hashAlg)
	if err != nil {
		return 0, err
	}
	var rhandle tpmutil.Handle
	_, err = tpmutil.Unpack(resp, &rhandle)
	return rhandle, err
}

func runCommand(rw io.ReadWriter, tag tpmutil.Tag, Cmd tpmutil.Command, in ...interface{}) ([]byte, error) {
	resp, code, err := tpmutil.RunCommand(rw, tag, Cmd, in...)
	if err != nil {
		return nil, err
	}
	if code != tpmutil.RCSuccess {
		return nil, decodeResponse(code)
	}
	return resp, decodeResponse(code)
}

func concat(chunks ...[]byte) ([]byte, error) {
	return bytes.Join(chunks, nil), nil
}

func decodeResponse(code tpmutil.ResponseCode) error {
	if code == tpmutil.RCSuccess {
		return nil
	}
	if code&0x180 == 0 { // Bits 7:8 == 0 is a TPM1 error
		return fmt.Errorf("response status 0x%x", code)
	}
	if code&0x80 == 0 { // Bit 7 unset
		if code&0x400 > 0 { // Bit 10 set, vendor specific code
			return tpm2.VendorError{Code: uint32(code)}
		}
		if code&0x800 > 0 { // Bit 11 set, warning with code in bit 0:6
			return tpm2.Warning{Code: tpm2.RCWarn(code & 0x7f)}
		}
		// error with code in bit 0:6
		return tpm2.Error{Code: tpm2.RCFmt0(code & 0x7f)}
	}
	if code&0x40 > 0 { // Bit 6 set, code in 0:5, parameter number in 8:11
		return tpm2.ParameterError{Code: tpm2.RCFmt1(code & 0x3f), Parameter: tpm2.RCIndex((code & 0xf00) >> 8)}
	}
	if code&0x800 == 0 { // Bit 11 unset, code in 0:5, handle in 8:10
		return tpm2.HandleError{Code: tpm2.RCFmt1(code & 0x3f), Handle: tpm2.RCIndex((code & 0x700) >> 8)}
	}
	// Code in 0:5, Session in 8:10
	return tpm2.SessionError{Code: tpm2.RCFmt1(code & 0x3f), Session: tpm2.RCIndex((code & 0x700) >> 8)}
}

func encodeAuthArea(sections ...tpm2.AuthCommand) ([]byte, error) {
	var res tpmutil.RawBytes
	for _, s := range sections {
		buf, err := tpmutil.Pack(s)
		if err != nil {
			return nil, err
		}
		res = append(res, buf...)
	}

	size, err := tpmutil.Pack(uint32(len(res)))
	if err != nil {
		return nil, err
	}

	return concat(size, res)
}
