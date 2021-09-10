package authConn

import (
	"context"
	"fmt"
	"net"

	"git.moresec.cn/cloudplatform/authConn/auth"
)

type Dialer struct {
	auth.Credential
	net.Dialer
}

func NewDialer(dialer net.Dialer, credential auth.Credential) *Dialer {
	return &Dialer{
		Credential: credential,
		Dialer:     dialer,
	}
}

func (d Dialer) authFlow(conn net.Conn) error {
	_, err := conn.Write(NewAuthPacket(d.Credential).Packet())
	if err != nil {
		return err
	}

	authRsp := AuthRspPacket{ReturnCode: 0}
	err = authRsp.Reset(conn)
	if err != nil {
		return err
	}

	if authRsp.ReturnCode != 0 {
		return fmt.Errorf("auth-failure(%d)", authRsp.ReturnCode)
	}
	return nil
}

func (d Dialer) Dial(network, address string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	err = d.authFlow(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	err = d.authFlow(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func Dial(network, address string, credential auth.Credential) (net.Conn, error) {
	d := &Dialer{
		Credential: credential,
		Dialer:     net.Dialer{},
	}
	return d.Dial(network, address)
}

func DialContext(ctx context.Context, network, address string, credential auth.Credential) (net.Conn, error) {
	d := &Dialer{
		Credential: credential,
		Dialer:     net.Dialer{},
	}
	return d.DialContext(ctx, network, address)
}
