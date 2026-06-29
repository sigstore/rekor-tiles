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

package mldsa

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"filippo.io/mldsa"
)

var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
)

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// MarshalMLDSAPublicKey encodes an ML-DSA public key as a SubjectPublicKeyInfo
// structure in DER format.
func MarshalMLDSAPublicKey(key *mldsa.PublicKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("empty ML-DSA public key")
	}

	var oid asn1.ObjectIdentifier
	switch key.Parameters() {
	case mldsa.MLDSA44():
		oid = oidMLDSA44
	default:
		return nil, errors.New("unknown or unsupported ML-DSA parameter set")
	}

	pubKey := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     key.Bytes(),
			BitLength: len(key.Bytes()) * 8,
		},
	}

	return asn1.Marshal(pubKey)
}

// UnmarshalMLDSAPublicKey decodes an ML-DSA public key from a
// SubjectPublicKeyInfo structure in DER format.
func UnmarshalMLDSAPublicKey(derBytes []byte) (*mldsa.PublicKey, error) {
	var spki subjectPublicKeyInfo
	if remain, err := asn1.Unmarshal(derBytes, &spki); err != nil {
		return nil, err
	} else if len(remain) > 0 {
		return nil, errors.New("trailing data after ML-DSA public key structure")
	}

	var params *mldsa.Parameters
	switch {
	case spki.Algorithm.Algorithm.Equal(oidMLDSA44):
		params = mldsa.MLDSA44()
	default:
		return nil, errors.New("unknown or unsupported ML-DSA parameter set OID")
	}

	return mldsa.NewPublicKey(params, spki.SubjectPublicKey.Bytes)
}
