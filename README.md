# authConn
auth conn

##Example

### Listener

```go
authFunc := func(authPacket *AuthPacket) (rc byte, credential auth.Credential) {
    cre := &auth.BasicCredential{}
    err := authPacket.ToCredential(cre)
    if err != nil {
    return 1, nil
    }
    if cre.Username != "john" || cre.Password != "123" {
    return 1, nil
    }
    return 0, cre
}
ln, err := Listen("tcp", ":8082", authFunc)
if err != nil {
    panic(err)
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
```

### Dialer

```go
conn, err := Dial("tcp", "127.0.0.1:8082", &auth.BasicCredential{
    Username: "john",
    Password: "123",
})
if err != nil {
    t.Error(err)
    return
}
_ = conn.Close()
```

### Customer Auth Way

```go
// AuthToken implement auth.Credential
type AuthToken struct {
	tk string
}

func (a AuthToken) Detail() map[string]string {
	return map[string]string{
		"tk": a.tk,
	}
}

func (a *AuthToken) Reset(m map[string]string) error {
	tk, ok := m["tk"]
	if !ok {
		return errors.New("not found tk")
	}
	a.tk = tk
	return nil
}

func main() {
    conn, err := Dial("tcp", "127.0.0.1:8082", &AuthToken{
        tk: "token",
    })
    if err != nil {
        fmt.Println(err)
        return
    }
    conn.Close()
}
```