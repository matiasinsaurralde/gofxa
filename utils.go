// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package fxa

import (
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"io"
)

func quickStretchPassword(email, password string) []byte {
	salt := "identity.mozilla.com/picl/v1/quickStretch:" + email
	return pbkdf2.Key([]byte(password), []byte(salt), 1000, 32, sha256.New)
}

func deriveAuthPWFromQuickStretchedPassword(stretchedPassword []byte) ([]byte, error) {
	secret := make([]byte, sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, stretchedPassword, nil, []byte("identity.mozilla.com/picl/v1/authPW")), secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func deriveUnwrapBKeyFromQuickStretchedPassword(stretchedPassword []byte) ([]byte, error) {
	secret := make([]byte, sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, stretchedPassword, nil, []byte("identity.mozilla.com/picl/v1/unwrapBkey")), secret); err != nil {
		return nil, err
	}
	return secret, nil
}

type requestCredentials struct {
	TokenId        []byte
	RequestHMACKey []byte
	RequestKey     []byte
}

func newRequestCredentials(token []byte, name string) (*requestCredentials, error) {
	secret := make([]byte, 3*sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, token, nil, []byte("identity.mozilla.com/picl/v1/"+name)), secret); err != nil {
		return nil, err
	}
	return &requestCredentials{
		TokenId:        secret[0:32],
		RequestHMACKey: secret[32:64],
		RequestKey:     secret[64:96],
	}, nil
}

type accountKeys struct {
	HMACKey []byte
	XORKey  []byte
}

func newAccountKeys(requestKey []byte) (*accountKeys, error) {
	secret := make([]byte, 3*sha256.Size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, requestKey, nil, []byte("identity.mozilla.com/picl/v1/account/keys")), secret); err != nil {
		return nil, err
	}
	return &accountKeys{
		HMACKey: secret[0:32],
		XORKey:  secret[32:96],
	}, nil
}
