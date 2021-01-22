// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package fxa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type hawkCredentials struct {
	id  string
	key []byte
}

func portForURL(u *url.URL) (int, error) {
	if strings.LastIndex(u.Host, ":") == -1 {
		if u.Scheme == "http" {
			return 80, nil
		} else {
			return 443, nil
		}
	} else {
		_, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			return 0, err
		}
		return strconv.Atoi(port)
	}
}

func hostForURL(u *url.URL) (string, error) {
	if strings.LastIndex(u.Host, ":") == -1 {
		return u.Host, nil
	} else {
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			return "", err
		}
		return host, nil
	}
}

func hawkSignature(req *http.Request, payloadHash string, key []byte, ts time.Time, nonce string, ext string) (string, error) {
	port, err := portForURL(req.URL)
	if err != nil {
		return "", err
	}

	host, err := hostForURL(req.URL)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, key)
	io.WriteString(mac, "hawk.1.header\n")
	io.WriteString(mac, strconv.FormatInt(ts.Unix(), 10)+"\n")
	io.WriteString(mac, nonce+"\n")
	io.WriteString(mac, req.Method+"\n")
	io.WriteString(mac, req.URL.RequestURI()+"\n")
	io.WriteString(mac, host+"\n")
	io.WriteString(mac, strconv.Itoa(port)+"\n")
	io.WriteString(mac, payloadHash+"\n")
	io.WriteString(mac, ext+"\n")
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func hawkPayloadHash(req *http.Request, payload io.Reader) (string, error) {
	if payload == nil {
		return "", nil
	}
	hash := sha256.New()
	io.WriteString(hash, "hawk.1.payload\n")
	io.WriteString(hash, req.Header.Get("Content-Type")+"\n")
	io.Copy(hash, payload)
	io.WriteString(hash, "\n")
	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

func NewHawkCredentials(id string, key []byte) hawkCredentials {
	return hawkCredentials{id: id, key: key}
}

func (hc *hawkCredentials) AuthorizeRequest(req *http.Request, body io.Reader, ext string) error {
	payloadHash, err := hawkPayloadHash(req, body)
	if err != nil {
		return err
	}

	ts := time.Now()
	nonce := "gBhGtY"

	signature, err := hawkSignature(req, payloadHash, hc.key, ts, nonce, ext)
	if err != nil {
		return err
	}

	var authorization string
	if payloadHash != "" {
		if ext != "" {
			authorization = fmt.Sprintf(`Hawk id="%s", ts="%d", nonce="%s", ext="%s", mac="%s", hash="%s"`, hc.id, ts.Unix(), nonce, ext, signature, payloadHash)
		} else {
			authorization = fmt.Sprintf(`Hawk id="%s", ts="%d", nonce="%s", mac="%s", hash="%s"`, hc.id, ts.Unix(), nonce, signature, payloadHash)
		}
	} else {
		if ext != "" {
			authorization = fmt.Sprintf(`Hawk id="%s", ts="%d", nonce="%s", ext="%s", mac="%s"`, hc.id, ts.Unix(), nonce, ext, signature)
		} else {
			authorization = fmt.Sprintf(`Hawk id="%s", ts="%d", nonce="%s", mac="%s"`, hc.id, ts.Unix(), nonce, signature)
		}
	}

	req.Header.Add("Authorization", authorization)

	return nil
}
