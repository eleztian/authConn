package authConn

import (
	"fmt"
	"github.com/eleztian/authConn/auth"
	"sync"
	"testing"
)

func TestListener(t *testing.T) {

	ln, err := Listen("tcp", ":8082",
		func(authPacket *AuthPacket) (rc byte, credential auth.Credential) {
			fmt.Println("auth", authPacket)
			cre := &auth.BasicCredential{}
			err := authPacket.ToCredential(cre)
			if err != nil {
				fmt.Println("auth", err)
				return 1, nil
			}
			if cre.Username != "john" || cre.Password != "123" {
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
	}

}

func TestDialer(t *testing.T) {
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := Dial("tcp", "127.0.0.1:8082", &auth.BasicCredential{
				Username: "john",
				Password: "123",
			})
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
		}()

	}
	wg.Wait()

}
