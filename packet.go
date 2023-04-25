package authConn

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	PACKET_TYPE_AUTH     = 0x1001
	PACKET_TYPE_AUTH_RSP = 0x1002
)

var (
	ErrPacketTypeInvalid = errors.New("invalid packet type")
)

type Packet interface {
	Packet() []byte
	Reset(src io.Reader) error
}

func ReadPacket(reader io.Reader) (res Packet, err error) {
	packetType, err := decodeUint64(reader)
	if err != nil {
		return nil, err
	}
	switch packetType {
	case PACKET_TYPE_AUTH:
		res = &AuthPacket{data: map[string]string{}}
		err = res.(*AuthPacket).reset(reader)
	case PACKET_TYPE_AUTH_RSP:
		res = &AuthRspPacket{}
		err = res.(*AuthRspPacket).reset(reader)
	default:
		err = ErrPacketTypeInvalid
	}
	return
}

func decodeByte(b io.Reader) (byte, error) {
	num := make([]byte, 1)
	_, err := io.ReadFull(b, num)
	if err != nil {
		return 0, err
	}

	return num[0], nil
}

func decodeUint16(b io.Reader) (uint16, error) {
	num := make([]byte, 2)
	_, err := io.ReadFull(b, num)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(num), nil
}

func decodeUint64(b io.Reader) (uint64, error) {
	num := make([]byte, 8)
	_, err := io.ReadFull(b, num)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(num), nil
}

func encodeUint16(num uint16) []byte {
	bytesResult := make([]byte, 2)
	binary.BigEndian.PutUint16(bytesResult, num)
	return bytesResult
}

func encodeUint64(num uint64) []byte {
	bytesResult := make([]byte, 8)
	binary.BigEndian.PutUint64(bytesResult, num)
	return bytesResult
}

func encodeString(field string) []byte {
	return encodeBytes([]byte(field))
}

func decodeString(b io.Reader) (string, error) {
	buf, err := decodeBytes(b)
	return string(buf), err
}

func decodeBytes(b io.Reader) ([]byte, error) {
	fieldLength, err := decodeUint16(b)
	if err != nil {
		return nil, err
	}

	field := make([]byte, fieldLength)
	_, err = io.ReadFull(b, field)
	if err != nil {
		return nil, err
	}

	return field, nil
}

func encodeBytes(field []byte) []byte {
	fieldLength := make([]byte, 2)
	binary.BigEndian.PutUint16(fieldLength, uint16(len(field)))
	return append(fieldLength, field...)
}

func encodeLength(length int) []byte {
	var encLength []byte
	for {
		digit := byte(length % 128)
		length /= 128
		if length > 0 {
			digit |= 0x80
		}
		encLength = append(encLength, digit)
		if length == 0 {
			break
		}
	}
	return encLength
}

func decodeLength(r io.Reader) (int, error) {
	var rLength uint32
	var multiplier uint32
	b := make([]byte, 1)
	for multiplier < 27 {
		_, err := io.ReadFull(r, b)
		if err != nil {
			return 0, err
		}

		digit := b[0]
		rLength |= uint32(digit&127) << multiplier
		if (digit & 128) == 0 {
			break
		}
		multiplier += 7
	}
	return int(rLength), nil
}
