package authConn

import (
	"bytes"
	"errors"
	"io"

	"github.com/eleztian/authConn/auth"
)

type AuthPacket struct {
	data map[string]string
}

func NewAuthPacket(credential auth.Credential) Packet {
	return &AuthPacket{credential.Detail()}
}

func (a *AuthPacket) reset(src io.Reader) error {
	kNum, err := decodeUint16(src)
	if err != nil {
		return err
	}
	data := make(map[string]string)
	for i := 0; i < int(kNum); i++ {
		k, err := decodeString(src)
		if err != nil {
			return err
		}
		v, err := decodeString(src)
		if err != nil {
			return err
		}
		data[k] = v
	}
	a.data = data
	return nil
}

func (a *AuthPacket) Reset(src io.Reader) error {
	packetType, err := decodeUint64(src)
	if err != nil {
		return err
	}
	if packetType != PACKET_TYPE_AUTH {
		return errors.New("invalid auth req packet")
	}
	return a.reset(src)
}

func (a AuthPacket) Packet() []byte {
	buf := bytes.NewBuffer(encodeUint64(PACKET_TYPE_AUTH))
	buf.Write(encodeUint16(uint16(len(a.data))))
	for k, v := range a.data {
		buf.Write(encodeString(k))
		buf.Write(encodeString(v))
	}
	return buf.Bytes()
}

type AuthRspPacket struct {
	ReturnCode byte
}

func (a *AuthRspPacket) Packet() []byte {
	buf := bytes.NewBuffer(encodeUint64(PACKET_TYPE_AUTH_RSP))
	buf.Write([]byte{a.ReturnCode})
	return buf.Bytes()
}

func (a *AuthRspPacket) reset(src io.Reader) error {
	res := make([]byte, 1)
	_, err := io.ReadFull(src, res)
	if err != nil {
		return err
	}
	a.ReturnCode = res[0]
	return nil
}

func (a *AuthRspPacket) Reset(src io.Reader) error {
	packetType, err := decodeUint64(src)
	if err != nil {
		return err
	}
	if packetType != PACKET_TYPE_AUTH_RSP {
		return errors.New("invalid auth rsp packet")
	}
	return a.reset(src)
}

func (a *AuthPacket) ToCredential(credential auth.Credential) error {
	return credential.Reset(a.data)
}
