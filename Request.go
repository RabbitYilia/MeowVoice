package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"strconv"
)

// SIPVersion is the version of SIP used by this library.
const SIPVersion = "SIP/2.0"

// SIP request methods.
const (
	MethodInvite   = "INVITE"
	MethodAck      = "ACK"
	MethodBye      = "BYE"
	MethodCancel   = "CANCEL"
	MethodRegister = "REGISTER"
	MethodOptions  = "OPTIONS"
	MethodInfo     = "INFO"
)

// Request represents a SIP request (i.e. a message sent by a UAC to a UAS).
type Request struct {
	Method     string
	Server     string
	SIPVersion string
	Header     Header
	Body       []byte
	Sender     *net.UDPAddr
}

// NewRequest returns a new request.
func NewRequest() *Request {
	return &Request{
		SIPVersion: SIPVersion,
		Header:     make(Header),
	}
}

var ErrBadMessage = errors.New("sip: bad message")

func (r *Request) WriteTo() error {
	var buff bytes.Buffer

	buff.Write([]byte(r.Method + " " + r.Server + " " + SIPVersion + "\r\n"))
	r.Header.Set("Content-Length", strconv.Itoa(len(r.Body)))

	b := bytes.NewBuffer(make([]byte, 0))
	_, err := r.Header.WriteTo(b)
	if err != nil {
		return err
	}
	buff.Write(b.Bytes())
	buff.Write(r.Body)
	log.Println("TX")
	log.Println(string(buff.Bytes()))
	log.Println("---")

	_, err = ServerConn.WriteToUDP(buff.Bytes(), r.Sender)
	if err != nil {
		return err
	}
	return nil
}
