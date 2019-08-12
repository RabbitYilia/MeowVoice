package main

import (
	"bytes"
	"net"
	"strconv"
)

// Response represents a SIP response (i.e. a message sent by a UAS to a UAC).
type Response struct {
	StatusCode int
	Status     string
	SIPVersion string
	Receiver   *net.UDPAddr
	Header     Header
	Body       []byte
}

// NewResponse returns a new response.
func NewResponse() *Response {
	return &Response{
		SIPVersion: SIPVersion,
		Header:     make(Header),
	}
}

func (r *Response) ServerError(req *Request, reason string) {
	r.StatusCode = StatusServerInternalError
	r.Header.Set("Reason-Phrase", reason)
	r.WriteTo(req)
}

// BadRequest responds to a Conn with a StatusBadRequest for convenience.
func (r *Response) BadRequest(req *Request, reason string) {
	r.StatusCode = StatusBadRequest
	r.Header.Set("Reason-Phrase", reason)
	r.WriteTo(req)
}

func (r *Response) WriteTo(req *Request) error {
	var buffer bytes.Buffer
	buffer.Write([]byte(SIPVersion + " " + strconv.Itoa(r.StatusCode) + " " + StatusText(r.StatusCode) + "\r\n"))

	r.Header.Set("Content-Length", strconv.Itoa(len(r.Body)))
	reqVia, err := ParseVia(req.Header.Get("Via"))
	if err != nil {
		return err
	}

	reqVia.Arguments.Set("received", r.Receiver.IP.String())
	reqVia.Arguments.Set("rport", strconv.Itoa(r.Receiver.Port))
	r.Header.Set("Via", reqVia.String())
	r.Header.Set("CSeq", req.Header.Get("CSeq"))
	r.Header.Set("Call-ID", req.Header.Get("Call-ID"))

	_, err = ServerConn.WriteToUDP(buffer.Bytes(), r.Receiver)
	if err != nil {
		return err
	}
	return nil
}
