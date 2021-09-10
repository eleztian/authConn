package authConn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/eleztian/authConn/auth"
)

type Dialer struct {
	auth.Credential
	*net.Dialer
}

func NewDialer(dialer *net.Dialer, credential auth.Credential) *Dialer {
	return &Dialer{
		Credential: credential,
		Dialer:     dialer,
	}
}

func authFlow(conn net.Conn, credential auth.Credential) error {
	_ = conn.SetWriteDeadline(time.Now().Add(defaultTimeout))
	_, err := conn.Write(NewAuthPacket(credential).Packet())
	_ = conn.SetWriteDeadline(time.Time{})

	if err != nil {
		return err
	}

	authRsp := AuthRspPacket{ReturnCode: 0}

	_ = conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	err = authRsp.Reset(conn)
	_ = conn.SetReadDeadline(time.Time{})

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

	err = authFlow(conn, d.Credential)
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

	err = authFlow(conn, d.Credential)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func Dial(network, address string, credential auth.Credential) (net.Conn, error) {
	d := &Dialer{
		Credential: credential,
		Dialer:     &net.Dialer{},
	}
	return d.Dial(network, address)
}

func DialContext(ctx context.Context, network, address string, credential auth.Credential) (net.Conn, error) {
	d := &Dialer{
		Credential: credential,
		Dialer:     &net.Dialer{},
	}
	return d.DialContext(ctx, network, address)
}

type TlsDialer struct {
	*tls.Dialer
	Credential auth.Credential
}

func NewTlsDialer(dialer *tls.Dialer, credential auth.Credential) *TlsDialer {
	return &TlsDialer{
		Credential: credential,
		Dialer:     dialer,
	}
}

func (d TlsDialer) Dial(network, address string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	err = authFlow(conn, d.Credential)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func (d TlsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	err = authFlow(conn, d.Credential)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func TlsDial(network, address string, config *tls.Config, credential auth.Credential) (net.Conn, error) {
	d := &TlsDialer{
		Dialer: &tls.Dialer{
			NetDialer: &net.Dialer{},
			Config:    config,
		},
	}
	return d.Dial(network, address)
}

func TlsDialContext(ctx context.Context, network, address string, config *tls.Config, credential auth.Credential) (net.Conn, error) {
	d := &TlsDialer{
		Dialer: &tls.Dialer{
			NetDialer: &net.Dialer{},
			Config:    config,
		},
	}
	return d.DialContext(ctx, network, address)
}

func AuthWithCredential(conn net.Conn, credential auth.Credential) error {
	err := authFlow(conn, credential)
	if err != nil {
		return err
	}
	return nil
}
