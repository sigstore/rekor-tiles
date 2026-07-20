// Copyright 2026 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"filippo.io/mldsa"
	"github.com/sigstore/rekor-tiles/v2/pkg/note"
)

var oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}

type pkcs8PrivKeyInfo struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func marshalMLDSAPrivateKey(key *mldsa.PrivateKey) ([]byte, error) {
	marshaledKeyBytes, err := asn1.MarshalWithParams(key.Bytes(), "tag:0")
	if err != nil {
		return nil, err
	}
	privKey := pkcs8PrivKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidMLDSA44},
		PrivateKey: marshaledKeyBytes,
	}
	return asn1.Marshal(privKey)
}

func marshalMLDSAPublicKey(key *mldsa.PublicKey) ([]byte, error) {
	pubKey := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidMLDSA44},
		SubjectPublicKey: asn1.BitString{
			Bytes:     key.Bytes(),
			BitLength: len(key.Bytes()) * 8,
		},
	}
	return asn1.Marshal(pubKey)
}

func main() {
	// 1. Generate Log Key
	logPriv, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	logPub := logPriv.Public().(*mldsa.PublicKey)
	logID, logHashBytes, _ := note.KeyHash("rekor-local", logPub)

	// Save log private key
	logPrivDER, _ := marshalMLDSAPrivateKey(logPriv)
	logPrivFile, _ := os.Create("tests/testdata/pki/mldsa-priv-key.pem")
	if err := pem.Encode(logPrivFile, &pem.Block{Type: "PRIVATE KEY", Bytes: logPrivDER}); err != nil {
		panic(err)
	}
	logPrivFile.Close()

	// Save log public key
	logPubDER, _ := marshalMLDSAPublicKey(logPub)
	logPubFile, _ := os.Create("tests/testdata/pki/mldsa-pub-key.pem")
	if err := pem.Encode(logPubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: logPubDER}); err != nil {
		panic(err)
	}
	logPubFile.Close()

	logPubNoteBytes := append([]byte{0x06}, logPub.Bytes()...)
	logPubNote := fmt.Sprintf("rekor-local+%08x+%s", logID, base64.StdEncoding.EncodeToString(logPubNoteBytes))
	fmt.Printf("Log Note Pub Key: %s\n", logPubNote)
	fmt.Printf("Log ID Hex: %s\n", hex.EncodeToString(logHashBytes))

	// 2. Generate Witness Key
	witPriv, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	witPub := witPriv.Public().(*mldsa.PublicKey)
	witID, _, _ := note.KeyHash("rekor-witness-test", witPub)

	witPubNoteBytes := append([]byte{0x06}, witPub.Bytes()...)
	witPubNote := fmt.Sprintf("rekor-witness-test+%08x+%s", witID, base64.StdEncoding.EncodeToString(witPubNoteBytes))
	witPrivNoteBytes := append([]byte{0x06}, witPriv.Bytes()...)
	witPrivNote := fmt.Sprintf("PRIVATE+KEY+rekor-witness-test+%08x+%s", witID, base64.StdEncoding.EncodeToString(witPrivNoteBytes))

	if err := os.WriteFile("tests/testdata/witness/mldsa-private.key", []byte(witPrivNote+"\n"), 0600); err != nil {
		panic(err)
	}
	fmt.Printf("Witness Note Pub Key: %s\n", witPubNote)

	// Write configs
	configYAML := fmt.Sprintf("Logs:\n  - Origin: rekor-local\n    URL: http://ignored\n    PublicKey: %s\n    Feeder: tiles\n", logPubNote)
	if err := os.WriteFile("tests/testdata/witness/mldsa-config.yaml", []byte(configYAML), 0600); err != nil {
		panic(err)
	}

	policyYAML := fmt.Sprintf("witness o1 %s http://witness:8100 \nquorum o1\n", witPubNote)
	if err := os.WriteFile("tests/testdata/witness/mldsa-policy.yaml", []byte(policyYAML), 0600); err != nil {
		panic(err)
	}
}
