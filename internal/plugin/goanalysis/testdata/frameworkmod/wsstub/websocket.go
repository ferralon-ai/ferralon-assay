// Package websocket mirrors the part of gorilla/websocket a server endpoint uses.
package websocket

import http "tegron.test/nethttp"

// Conn mirrors websocket.Conn.
type Conn struct{ next []byte }

// ReadMessage mirrors (*Conn).ReadMessage.
func (c *Conn) ReadMessage() (messageType int, p []byte, err error) { return 1, c.next, nil }

// Upgrader mirrors websocket.Upgrader.
type Upgrader struct{}

// Upgrade mirrors (*Upgrader).Upgrade.
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (*Conn, error) {
	return &Conn{}, nil
}

// Upgrade mirrors the deprecated package function, which calls the method.
func Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header, readBufSize, writeBufSize int) (*Conn, error) {
	u := Upgrader{}
	return u.Upgrade(w, r, responseHeader)
}
