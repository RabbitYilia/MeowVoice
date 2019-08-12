package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

type account struct {
	password string
}

type authSession struct {
	nonce   string
	user    User
	Addr    *net.UDPAddr
	created time.Time
}

func generateNonce(size int) string {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

// a map[call id]authSession pair
var authSessions = make(map[string]authSession)
var authSessionMutex = new(sync.Mutex)

var ErrInvalidAuthHeader = errors.New("server: invalid authorization header")

func HandleRegister(r *Request, Addr *net.UDPAddr) {
	from, to, err := ParseUserHeader(r.Header)
	if err != nil {
		resp := NewResponse()
		resp.Receiver = r.Sender
		resp.BadRequest(r, "Failed to parse From or To header.")
		return
	}

	if to.URI.UserDomain() != from.URI.UserDomain() {
		resp := NewResponse()
		resp.Receiver = r.Sender
		resp.BadRequest(r, "User in To and From fields do not match.")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		requestAuthentication(r, from)
		return
	}

	args, err := parseAuthHeader(authHeader)
	if err != nil {
		resp := NewResponse()
		resp.Receiver = r.Sender
		resp.BadRequest(r, "Failed to parse Authorization header.")
		return
	}

	checkAuthorization(r, args, from)
}

func md5Hex(data string) string {
	sum := md5.Sum([]byte(data))
	return hex.EncodeToString(sum[:])
}

func checkAuthorization(r *Request, authArgs HeaderArgs, user User) {
	callID := r.Header.Get("Call-ID")
	authSessionMutex.Lock()
	session, found := authSessions[callID]
	authSessionMutex.Unlock()
	if !found {
		requestAuthentication(r, user)
		return
	}

	if authArgs.Get("username") != user.URI.Username {
		requestAuthentication(r, user)
		return
	}

	if authArgs.Get("nonce") != session.nonce {
		requestAuthentication(r, user)
		return
	}

	username := user.URI.Username
	account, found := accounts[username]
	if !found {
		requestAuthentication(r, user)
		return
	}

	ha1 := md5Hex(username + ":" + hostname + ":" + account.password)
	ha2 := md5Hex(MethodRegister + ":" + authArgs.Get("uri"))
	response := md5Hex(ha1 + ":" + session.nonce + ":" + authArgs.Get("nc") +
		":" + authArgs.Get("cnonce") + ":auth:" + ha2)

	if response != authArgs.Get("response") {
		requestAuthentication(r, user)
		return
	}

	if r.Header.Get("Expires") == "0" {
		registeredUsersMutex.Lock()
		delete(registeredUsers, username)
		registeredUsersMutex.Unlock()
		println("logged out " + username)
	} else {
		registerUser(session)
		println("registered " + username)
	}

	resp := NewResponse()
	resp.Receiver = r.Sender
	resp.StatusCode = StatusOK
	resp.Header.Set("From", user.String())

	user.Arguments.Set("tag", generateNonce(5))
	resp.Header.Set("To", user.String())
	resp.WriteTo(r)
	return
}

func parseAuthHeader(header string) (HeaderArgs, error) {
	if len(header) < 8 || strings.ToLower(header[:7]) != "digest " {
		return nil, ErrInvalidAuthHeader
	}

	return ParsePairs(header[7:]), nil
}

func requestAuthentication(r *Request, from User) {
	resp := NewResponse()
	resp.Receiver = r.Sender
	callID := r.Header.Get("Call-ID")
	if callID == "" {
		resp.BadRequest(r, "Missing required Call-ID header.")
		return
	}

	nonce := generateNonce(32)

	resp.StatusCode = StatusUnauthorized
	// No auth header, deny.
	resp.Header.Set("From", from.String())
	from.Arguments.Del("tag")
	resp.Header.Set("To", from.String())

	authArgs := make(HeaderArgs)
	authArgs.Set("realm", hostname)
	authArgs.Set("qop", "auth")
	authArgs.Set("nonce", nonce)
	authArgs.Set("opaque", "")
	authArgs.Set("stale", "FALSE")
	authArgs.Set("algorithm", "MD5")
	resp.Header.Set("WWW-Authenticate", "Digest "+authArgs.CommaString())

	authSessionMutex.Lock()
	authSessions[callID] = authSession{
		nonce:   nonce,
		user:    from,
		Addr:    r.Sender,
		created: time.Now(),
	}
	authSessionMutex.Unlock()

	resp.WriteTo(r)
	return
}

func registrationJanitor() {
	for {
		authSessionMutex.Lock()
		for callID, session := range authSessions {
			if time.Now().Sub(session.created) > time.Second*30 {
				delete(authSessions, callID)
			}
		}
		authSessionMutex.Unlock()
		time.Sleep(time.Second * 10)
	}
}

func init() {
	go registrationJanitor()
}
