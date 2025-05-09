/*
Copyright 2025 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package note

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/rekor-tiles/pkg/signerverifier"
	"github.com/stretchr/testify/assert"
)

var (
	// ed25519-priv-key.pem
	ed25519PrivKey = []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGuZ8UWTFmXi/26ZgF4VYL8HfLSuW12TN5XMFQRt1Loc
-----END PRIVATE KEY-----
`)
	// ec-secp256r1-priv-key.pem
	ecdsaPrivKey = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOMZNOBbRU3CHBjZoc13R8HYNUoqsvce5UlOmRzlOZqUoAoGCCqGSM49
AwEHoUQDQgAEeLw7gX40qy1z7JUhGMAaaDITbV7p2D+C5G9xPEsy/PVAo9H0mgS4
NYzpGirkXxBht+IvvL19WR1X9ANXha5ldQ==
-----END EC PRIVATE KEY-----
`)
	// rsa-priv-key.pem
	// minimum supported RSA key size is 2048
	rsaPrivKey = []byte(`
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzuJ5Nonw8CTMK
Sz765sM1bg1ziGLv78lSZK+qrqkhYB+MatVcj9npE5Q6c2C+ORbqk4/8qQ7VhB+4
u0/zpfksPjdoix8f/dVDQvxfhbrjH8mCYD1NZBr7Dg55doV0bD6UScbLauUAveQh
if8EBuagBmHJZdAWQ9iDq+XKk3QfqpAfyFy3RJefvLpxqwiTsYHtNC3/46qSRDnm
iMz3VxdSrphiy8CMGNDAS8YZeou/A6G1sP54xzZ+nDsaUCCKJCmriSHNau25knQd
38EVk2kcf5QB11Dgm+/t1tcOKdq9XMRu8myxAA32cHf1Q8elRCf2aiMC6H+qD68M
3IQfeWIhAgMBAAECggEAALYAAFAefDFQH6ANE3qCtq0lBfo54/eXnQkTbdIrjpt9
/HT2u5tBEiw256VJsm7w4YQsa2Qy0BLp+jXZet4C9pMXboUwXhTHuXCkJW+WvevE
BQ1C6NG2zpvvYDkhDYUZGUaSb/8QAVj+9EgCt34cfvEPhXeu40uo6VpuegbrzG1D
Wr5Ad2JhQi8LZMCqlRBLvBSRPaMHv6KpkII6pPJyeVa99tVk2ivLBsoIPOLmi7i8
GDcedUXJY1r8AArH4ahxPM1QQF/CVxd4zxUUETb5LQ4XwZKxm6y7LMThv6scWFBD
+ey/GUS+u3krpGaBW2AoxS8ubYr5mjvCr0Gg24oZ/QKBgQDX4XUaQE+7RwcUnEVx
KPJj+gsrbsST82KUAR1EB/3XVK2HQweSYk14feQvo1VJL0uAc58BtZwi30IKHBNr
EUvGCee/6CxsvsHYrn4ukvVo4sx1DdjH83ByaACMjLJKDySarBuNcH+L0VCbw699
7n6MaBk+u6QJOmOhJRmtn7HjRQKBgQDVHt5I/uJznMrNSR4p1AgkPmcmaF4m/z9C
fLSz9mra/QzdNSMKTbF5wH7ENlFE6M7GtSVRi2G44eKaoCaQ/xFFhPGPoJrd8tqU
eCH65FYGH0Q3uQryOJ9rQSb/p9697orS7Fb46UQGfxRj5mLoUcmpComPYccod7UF
vfqEX7ojLQKBgQCcWCz96QuVXxhSpeZo0LXTEBicyOjXGZIQDEqMpZkCJNJTvoiy
TD09ATeMBKdUjEsK6TGEBGnim3vxZGnvxaPx9eSACH579x7edWjvBAF1h6N5NqEE
FlsekBGtuIu6tQLWfcSqh4nn0ZymYm8rLdk6iH2YAD8Ja98RqpPROXGUXQKBgHSy
uGkkGH/SBUKvnPKuhd7CxNzFHXkhH1Sa0KASeKR9GAQwyoUj0eCnRULPs2SWTlOE
cXDbb6E7H0goFbYj1SNKDrPk76hFCOdveLvXODuV91bD3niQBMtIG8C1/UPnUOD6
RQ17PaKJB3NEfjhUQKZtfLGkitdf5SHFy12cxWHpAoGAHV6Smruaku5GTLmftp7x
D0+b3FrkQeBT3OFpUVtp0iSixhoBA2YHSofC/SAnqoY7Hw23VUtWHfhPdVowNa2T
cvxSmCAcfkrJHKF1remfUOtN6Ncu9Dyr/rieoxFDqz31lezTAx3T6lLfgtspxplR
fycQ0e/nw1JkypGoL1j4cwM=
-----END PRIVATE KEY-----
`)
)

func TestKeyHash(t *testing.T) {
	origin := "testkey"
	tests := []struct {
		name             string
		key              []byte
		expectedKeyID    uint32
		expectedLogIDHex string
	}{
		{
			name:             "ed25519",
			key:              ed25519PrivKey,
			expectedKeyID:    3839787747,                                                         // echo $((0x$(printf "%s%b%b%s" "testkey" "\x0A" "\x01" "$(openssl pkey -in ed25519-priv-key.pem -pubout -out - | openssl pkey -pubin -in /dev/stdin -outform DER -out - | tail -c32)" | sha256sum | cut -d ' ' -f 1 | head -c 8)))
			expectedLogIDHex: "e4de82e34c8c270d87612a3d6a1e297e2cd0ed9cb89ea7aeec8ce4d0b54e6775", // echo $(printf "%s%b%b%s" "testkey" "\x0A" "\x01" "$(openssl pkey -in ed25519-priv-key.pem -pubout -out - | openssl pkey -pubin -in /dev/stdin -outform DER -out - | tail -c32)" | sha256sum | cut -d ' ' -f 1)
		},
		{
			name:             "ecdsa",
			key:              ecdsaPrivKey,
			expectedKeyID:    2408765216,                                                         // echo $((0x$(openssl ec -in ec-secp256r1-priv-key.pem -pubout - | openssl ec -pubin -in /dev/stdin -outform DER -out - | sha256sum | cut -d ' ' -f 1 | head -c 8)))
			expectedLogIDHex: "8f92d720f56c219e34895a76a636a3353ddbf7813f9fa317e19982eafa945328", // echo $(openssl ec -in ec-secp256r1-priv-key.pem -pubout - | openssl ec -pubin -in /dev/stdin -outform DER -out - | sha256sum | cut -d ' ' -f 1)
		},
		{
			name:             "rsa",
			key:              rsaPrivKey,
			expectedKeyID:    2918460683,                                                         // echo $((0x$({ printf "%s%b%b%s" "testkey" "\x0A" "\xFF" 'PKIX-RSA-PKCS#1v1.5' ; openssl rsa -in rsa-priv-key.pem -pubout -out - | openssl rsa -in /dev/stdin -pubin -outform DER -out - ;  } | sha256sum | cut -d ' ' -f 1 | head -c8)))
			expectedLogIDHex: "adf42d0b4478f2d07e5c8c3e63640a7e41b440c19dc47010c3a4936af75d85b6", // echo $({ printf "%s%b%b%s" "testkey" "\x0A" "\xFF" 'PKIX-RSA-PKCS#1v1.5' ; openssl rsa -in rsa-priv-key.pem -pubout -out - | openssl rsa -in /dev/stdin -pubin -outform DER -out - ;  } | sha256sum | cut -d ' ' -f 1)
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			td := t.TempDir()
			file := fmt.Sprintf("%s-priv.pem", test.name)
			keyFile := filepath.Join(td, file)
			if err := os.WriteFile(keyFile, []byte(test.key), 0644); err != nil {
				t.Fatal(err)
			}
			signer, err := signerverifier.New(ctx, signerverifier.WithFile(keyFile, ""))
			if err != nil {
				t.Fatal(err)
			}
			noteSigner, err := NewNoteSigner(ctx, origin, signer)
			if err != nil {
				t.Fatal(err)
			}
			pubKey, err := signer.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			keyID, logID, err := KeyHash(origin, pubKey)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, test.expectedKeyID, noteSigner.KeyHash())
			assert.Equal(t, test.expectedKeyID, keyID)
			expectedLogID, err := hex.DecodeString(test.expectedLogIDHex)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, expectedLogID, logID)
		})
	}
}
