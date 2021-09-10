package authConn

import (
	"fmt"
	"git.moresec.cn/cloudplatform/authConn/auth"
	"testing"
)

func TestListener(t *testing.T) {

	ln, err := Listen("tcp", ":8082", func(authPacket *AuthPacket) (rc byte, credential auth.Credential) {
		fmt.Println("auth", authPacket)
		cre := &auth.BasicCredential{}
		err := authPacket.ToCredential(cre)
		if err != nil {
			fmt.Println("auth", err)
			return 1, nil
		}
		return 0, cre
	})
	if err != nil {
		t.Error(err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			break
		}
		creConn := conn.(*ConnWithCredential)
		fmt.Println("accept", creConn.Credential.Detail())
		_ = conn.Close()
		break
	}

}

func TestDialer(t *testing.T) {

	conn, err := Dial("tcp", "127.0.0.1:8082", &auth.BasicCredential{
		Username: "zhangtian",
		Password: "123",
	})
	if err != nil {
		t.Error(err)
		return
	}
	_ = conn.Close()

}
