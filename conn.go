package authConn

import (
	"github.com/eleztian/authConn/auth"
	"net"
)

type AuthConn struct {
	net.Conn
	auth.Credential
}
