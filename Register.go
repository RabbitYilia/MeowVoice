package main

import (
	"net"
	"sync"
)

type registeredUser struct {
	username string
	Addr     *net.UDPAddr
}

var registeredUsers = make(map[string]registeredUser)
var registeredUsersMutex = new(sync.Mutex)

func registerUser(session authSession) {
	registeredUsersMutex.Lock()
	defer registeredUsersMutex.Unlock()

	username := session.user.URI.Username
	if registeredUsers[username].Addr != nil {
		user := registeredUsers[username]
		user.Addr = nil
		registeredUsers[username] = user
	}

	newUser := registeredUser{
		username: username,
		Addr:     session.Addr,
	}

	registeredUsers[username] = newUser
}
