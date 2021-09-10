package authConn

import (
	"context"
	"io"
	"log"
	"net"
	"sync"

	"github.com/eleztian/authConn/auth"
)

type ConnWithCredential struct {
	auth.Credential
	net.Conn
}

// Auth if auth pass return 0 and Credential.
type Auth func(authPacket *AuthPacket) (rc byte, credential auth.Credential)

type Listener struct {
	ctx    context.Context
	cancel func()
	wg     *sync.WaitGroup
	err    error

	ln       net.Listener
	authFunc Auth

	ch chan net.Conn
}

func Listen(network, address string, authFunc Auth) (net.Listener, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	res := &Listener{
		ln:       ln,
		ctx:      ctx,
		cancel:   cancel,
		wg:       &sync.WaitGroup{},
		authFunc: authFunc,
		ch:       make(chan net.Conn, 5),
	}
	go res.start()

	return res, nil
}

func (l *Listener) start() {
	defer close(l.ch)
	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}

		conn, err := l.ln.Accept()
		if err != nil {
			l.err = err
			return
		}

		l.wg.Add(1)
		go func() {
			defer l.wg.Done()

			authPacket := &AuthPacket{data: map[string]string{}}
			err = authPacket.Reset(conn)
			if err != nil {
				_ = conn.Close()
				return
			}
			select {
			case <-l.ctx.Done():
				_ = conn.Close()
				return
			default:
				authRsp := AuthRspPacket{ReturnCode: 0}
				var cre auth.Credential
				authRsp.ReturnCode, cre = l.authFunc(authPacket)
				_, err = conn.Write(authRsp.Packet())
				if err != nil {
					_ = conn.Close()
					if err != io.EOF {
						log.Printf("Conn: %v", err)
					}
					return
				}
				if authRsp.ReturnCode != 0 {
					_ = conn.Close()
					log.Printf("Conn: auth failed %d", authRsp.ReturnCode)
				}

				conn = &ConnWithCredential{
					Credential: cre,
					Conn:       conn,
				}

				select {
				case l.ch <- conn:
				case <-l.ctx.Done():
					_ = conn.Close()
				}
			}

		}()
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, io.EOF
	case conn := <-l.ch:
		return conn, nil
	}
}

func (l *Listener) Close() error {
	l.cancel()

	err := l.ln.Close()
	if err != nil {
		return err
	}

	for conn := range l.ch {
		_ = conn.Close()
	}

	l.wg.Wait()

	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *Listener) Error() error {
	return l.err
}
