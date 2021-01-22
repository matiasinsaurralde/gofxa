// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package fxa

import (
	"bytes"
	"crypto/dsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Structure that maintains the state of a Firefox Accounts Client.
type Client struct {
	email         string
	password      string
	authPW        []byte
	unwrapBKey    []byte
	uid           string // After /account/login
	sessionToken  []byte
	keyFetchToken []byte
	KeyA          []byte
	KeyB          []byte
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Errno   int    `json:"errno"`
	Err     string `json:"error"`
	Message string `json:"message"`
	Info    string `json:"info"`
}

func (e *ErrorResponse) Error() string {
	return e.Err
}

type loginRequest struct {
	Email  string `json:"email"`
	AuthPW string `json:"authPW"`
	Reason string `json:"reason"`
}

type loginResponse struct {
	Uid           string `json:"uid"`
	SessionToken  string `json:"sessionToken"`
	KeyFetchToken string `json:"keyFetchToken"`
}

type keysResponse struct {
	Bundle string `json:"bundle"`
}

type publicKey struct {
	Algorithm string `json:"algorithm"`
	Y         string `json:"y"`
	P         string `json:"p"`
	Q         string `json:"q"`
	G         string `json:"g"`
}

type signCertificateRequest struct {
	PublicKey publicKey `json:"publicKey"`
	Duration  uint64    `json:"duration"`
}

type signCertificateResponse struct {
	Certificate string `json:"cert"`
}

// Create a new client with the specified email and password.
func NewClient(email, password string) (*Client, error) {
	authPW, err := deriveAuthPWFromQuickStretchedPassword(quickStretchPassword(email, password))
	if err != nil {
		return nil, err
	}

	unwrapBKey, err := deriveUnwrapBKeyFromQuickStretchedPassword(quickStretchPassword(email, password))
	if err != nil {
		return nil, err
	}

	return &Client{
		email:      email,
		password:   password,
		authPW:     authPW,
		unwrapBKey: unwrapBKey,
	}, nil
}

// Login to the Firefox Accounts service.
func (c *Client) Login() error {
	request := loginRequest{
		Email:  c.email,
		AuthPW: hex.EncodeToString(c.authPW),
		Reason: "login",
	}
	encodedRequest, err := json.Marshal(request)
	if err != nil {
		return err
	}

	u, err := url.Parse("https://api.accounts.firefox.com/v1/account/login?keys=true")
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(encodedRequest))
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		errorResponse := &ErrorResponse{}
		if err := json.Unmarshal(body, &errorResponse); err != nil {
			return err
		} else {
			return errorResponse
		}
	}

	response := &loginResponse{}
	if err = json.Unmarshal(body, response); err != nil {
		return err
	}

	c.uid = response.Uid
	c.sessionToken, _ = hex.DecodeString(response.SessionToken)
	c.keyFetchToken, _ = hex.DecodeString(response.KeyFetchToken)

	return nil
}

// Fetch encryption keys from the Firefox Accounts service.
func (c *Client) FetchKeys() error {
	u, err := url.Parse("https://api.accounts.firefox.com/v1/account/keys")
	if err != nil {
		return err
	}

	client := &http.Client{}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}

	requestCredentials, err := newRequestCredentials(c.keyFetchToken, "keyFetchToken")
	if err != nil {
		return err
	}

	hawkCredentials := NewHawkCredentials(hex.EncodeToString(requestCredentials.TokenId), requestCredentials.RequestHMACKey)
	if err := hawkCredentials.AuthorizeRequest(req, nil, ""); err != nil {
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		errorResponse := &ErrorResponse{}
		if err := json.Unmarshal(body, &errorResponse); err != nil {
			return err
		} else {
			return errorResponse
		}
	}

	response := &keysResponse{}
	if err = json.Unmarshal(body, response); err != nil {
		return err
	}

	accountKeys, err := newAccountKeys(requestCredentials.RequestKey)
	if err != nil {
		return err
	}

	//

	bundle, err := hex.DecodeString(response.Bundle)
	if err != nil {
		return err
	}

	ct := bundle[0:64]
	respMAC := bundle[64:96]

	mac := hmac.New(sha256.New, accountKeys.HMACKey)
	mac.Write(ct)
	respMAC2 := mac.Sum(nil)

	if !bytes.Equal(respMAC, respMAC2) {
		return errors.New("Response MAC failure something bad")
	}

	// Finally derive kA and kB

	var t1 [64]byte
	for i := 0; i < 64; i++ {
		t1[i] = ct[i] ^ accountKeys.XORKey[i]
	}
	c.KeyA = t1[0:32]

	wrapKB := t1[32:64]

	var t2 [32]byte
	for i := 0; i < 32; i++ {
		t2[i] = c.unwrapBKey[i] ^ wrapKB[i]
	}
	c.KeyB = t2[:]

	return nil
}

// Sign a certificate with the given DSA key. Returns an encoded certificate.
func (c *Client) SignCertificate(key *dsa.PrivateKey) (string, error) {
	u, err := url.Parse("https://api.accounts.firefox.com/v1/certificate/sign")
	if err != nil {
		return "", err
	}

	request := signCertificateRequest{
		PublicKey: publicKey{
			Algorithm: "DS",
			Y:         fmt.Sprintf("%x", key.PublicKey.Y),
			P:         fmt.Sprintf("%x", key.PublicKey.Parameters.P),
			Q:         fmt.Sprintf("%x", key.PublicKey.Parameters.Q),
			G:         fmt.Sprintf("%x", key.PublicKey.Parameters.G),
		},
		Duration: 86400000,
	}
	encodedRequest, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	client := &http.Client{}

	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(encodedRequest))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	requestCredentials, err := newRequestCredentials(c.sessionToken, "sessionToken")
	if err != nil {
		return "", err
	}

	hawkCredentials := NewHawkCredentials(hex.EncodeToString(requestCredentials.TokenId), requestCredentials.RequestHMACKey)
	if err := hawkCredentials.AuthorizeRequest(req, bytes.NewReader(encodedRequest), ""); err != nil {
		return "", err
	}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		errorResponse := &ErrorResponse{}
		if err := json.Unmarshal(body, &errorResponse); err != nil {
			return "", err
		} else {
			return "", errorResponse
		}
	}

	response := &signCertificateResponse{}
	if err = json.Unmarshal(body, response); err != nil {
		return "", err
	}

	return response.Certificate, nil
}

func (c *Client) String() string {
	return fmt.Sprintf("<fxa.Client email=%s password=%s uid=%s sessionToken=%v keyFetchToken=%v>", c.email, c.password, c.uid, c.sessionToken, c.keyFetchToken)
}
