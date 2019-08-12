package main

import (
	"bytes"
	"io"
	"strconv"
	"strings"
)

// Header represents the headers of a SIP Request or Response.
type Header map[string]string

// Del deletes the key and its value from the header. Deleting a non-existent
// key is a no-op.
func (h Header) Del(key string) {
	delete(h, normalizeKey(key))
}

// Get returns the value at a given key. It returns an empty string if the
// key does not exist.
func (h Header) Get(key string) string {
	return h[normalizeKey(key)]
}

// Set sets a header key with a value.
func (h Header) Set(key, value string) {
	h[normalizeKey(key)] = value
}

// WriteTo writes the header data to a writer, with an additional CRLF
// (i.e. "\r\n") at the end.
func (h Header) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for key, value := range h {
		n, err := w.Write([]byte(key + ": " + value + "\r\n"))
		total += int64(n)
		if err != nil {
			return total, err
		}
	}

	n, err := w.Write([]byte("\r\n"))
	total += int64(n)
	return total, err
}

func normalizeKey(key string) string {
	return strings.Title(strings.ToLower(key))
}

func parseHeader(Data string, h Header) {
	for _, line := range strings.Split(Data, "\r\n") {
		if !strings.Contains(line, ": ") {
			continue
		}
		Key := strings.Split(line, ": ")[0]
		Value := strings.Split(line, ": ")[1]
		if Key != "" {
			h.Set(Key, Value)
		}
	}
}

type HeaderArgs map[string]string

func ParseList(value string) []string {
	var list []string
	var escape, quote bool
	b := new(bytes.Buffer)
	for _, r := range value {
		switch {
		case escape:
			b.WriteRune(r)
			escape = false
		case quote:
			if r == '\\' {
				escape = true
			} else {
				if r == '"' {
					quote = false
				}
				b.WriteRune(r)
			}
		case r == ',' || r == ';' || r == '\n':
			list = append(list, strings.TrimSpace(b.String()))
			b.Reset()
		case r == '"':
			quote = true
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	// Append last part.
	if s := b.String(); s != "" {
		list = append(list, strings.TrimSpace(s))
	}
	return list
}

// ParsePairs extracts key/value pairs from comma, semicolon, or new line
// separated values.
//
// Lifted from https://code.google.com/p/gorilla/source/browse/http/parser/parser.go
func ParsePairs(value string) HeaderArgs {
	m := make(HeaderArgs)
	for _, pair := range ParseList(strings.TrimSpace(value)) {
		if i := strings.Index(pair, "="); i < 0 {
			m[pair] = ""
		} else {
			v := pair[i+1:]
			if v[0] == '"' && v[len(v)-1] == '"' {
				v = v[1 : len(v)-1]
			}
			m[pair[:i]] = v
		}
	}
	return m
}

// ParseHeaderArgs parses header arguments from a full header.
func ParseHeaderArgs(str string) HeaderArgs {
	argLocation := strings.Index(str, ";")
	if argLocation < 0 {
		return make(HeaderArgs)
	}

	return ParsePairs(str[argLocation+1:])
}

// Del deletes the key and its value from the header arguments. Deleting a non-existent
// key is a no-op.
func (h HeaderArgs) Del(key string) {
	delete(h, key)
}

// Get returns the value at a given key. It returns an empty string if the
// key does not exist.
func (h HeaderArgs) Get(key string) string {
	return h[key]
}

// Set sets a header argument key with a value.
func (h HeaderArgs) Set(key, value string) {
	h[key] = value
}

// SemicolonString returns the header arguments as a semicolon
// separated unquoted strings with a leading semicolon.
func (h HeaderArgs) SemicolonString() string {
	var result string
	for key, value := range h {
		if value == "" {
			result += ";" + key
		} else {
			result += ";" + key + "=" + value
		}
	}
	return result
}

// CommaString returns the header arguments as a comma and space
// separated string.
func (h HeaderArgs) CommaString() string {
	if len(h) == 0 {
		return ""
	}

	var result string
	for key, value := range h {
		result += key + "=" + strconv.Quote(value) + ", "
	}
	return result[:len(result)-2]
}

// CRLFString returns the header arguments as a CRLF separated string.
func (h HeaderArgs) CRLFString() string {
	if len(h) == 0 {
		return ""
	}

	var result string
	for key, value := range h {
		result += key + "=" + value + "\r\n"
	}
	return result
}
