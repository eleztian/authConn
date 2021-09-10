package authConn

import (
	"git.moresec.cn/cloudplatform/authConn/auth"
	"net"
)

type AuthConn struct {
	net.Conn
	auth.Credential
}
