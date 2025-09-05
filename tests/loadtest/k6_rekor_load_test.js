// Copyright 2025 The Sigstore Authors
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

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { b64encode } from 'k6/encoding';

// Custom metrics
const errorRate = new Rate('errors');
const latency = new Trend('latency', true);

// Store keys per VU to avoid re-importing
const vuKeys = {};

// Test configuration
export const options = {
  scenarios: {
    load_test: {
      executor: 'ramping-vus',
      stages: [
        { duration: '30s', target: 5 },
        { duration: '1m', target: 20 },
        { duration: '30s', target: 100 },
        { duration: '2m', target: 100 },
        { duration: '30s', target: 0 },
      ],
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<10000'],
    errors: ['rate<0.1'],
  },
};

const BASE_URL = __ENV.REKOR_URL || 'http://localhost:3003/api/v2';
const BASE_READ_URL = __ENV.GCS_URL || 'http://localhost:7080/tiles';

async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

async function createUniqueDataHash() {
  const uniqueContent = `test-artifact-${Date.now()}-${__VU}-${__ITER}-${Math.random()}`;
  // k6 does not have a global TextEncoder. We can manually encode the string
  // to a Uint8Array as it only contains ASCII characters.
  const bytes = [];
  for (let i = 0; i < uniqueContent.length; i++) {
    bytes.push(uniqueContent.charCodeAt(i));
  }
  const data = new Uint8Array(bytes);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  // Return the raw digest (for the API) and the original data (for signing)
  return { hash: hashBuffer, originalData: data };
}

/**
 * Converts a raw ECDSA signature (r and s values concatenated) to ASN.1 DER format.
 * @param {Uint8Array} rawSignature The 64-byte raw signature.
 * @returns {Uint8Array} The DER-encoded signature.
 */
function rawSignatureToDER(rawSignature) {
    const r = rawSignature.slice(0, 32);
    const s = rawSignature.slice(32, 64);

    // Helper to encode an integer in DER format
    const encodeInteger = (integer) => {
        // Remove leading zeros
        let offset = 0;
        while (offset < integer.length && integer[offset] === 0) {
            offset++;
        }

        // Handle case where integer is all zeros
        if (offset === integer.length) {
            return new Uint8Array([0x02, 0x01, 0x00]);
        }

        const trimmed = integer.slice(offset);

        // If the high bit is set, prepend a zero byte to keep it positive
        const needsPadding = trimmed[0] >= 0x80;
        const length = trimmed.length + (needsPadding ? 1 : 0);

        const result = new Uint8Array(2 + length);
        result[0] = 0x02; // INTEGER tag
        result[1] = length; // length

        let pos = 2;
        if (needsPadding) {
            result[pos++] = 0x00;
        }
        result.set(trimmed, pos);

        return result;
    };

    const rDer = encodeInteger(r);
    const sDer = encodeInteger(s);

    // Create SEQUENCE containing the two INTEGERs
    const totalLength = rDer.length + sDer.length;
    const result = new Uint8Array(2 + totalLength);

    result[0] = 0x30; // SEQUENCE tag
    result[1] = totalLength; // length
    result.set(rDer, 2);
    result.set(sDer, 2 + rDer.length);

    return result;
}

async function signDataECDSA(originalData, privateKey) {
  // Sign the original data - crypto.subtle.sign will hash it automatically
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    originalData
  );
  const derSignature = rawSignatureToDER(new Uint8Array(signature));
  return b64encode(derSignature);
}

async function createHashedRekordEntry(privateKey, publicKeyContent) {
  const { hash, originalData } = await createUniqueDataHash();
  const signature = await signDataECDSA(originalData, privateKey);

  return {
    proposedEntry: {
      digest: b64encode(hash),
      signature: {
        content: signature,
        verifier: {
          publicKey: {
            rawBytes: publicKeyContent,
          },
          keyDetails: 'PKIX_ECDSA_P256_SHA_256',
        },
      }
    },
  };
}

export default async function(data) {
  const startTime = Date.now();
  try {
    // Import private key once per VU
    if (!vuKeys[__VU]) {
      vuKeys[__VU] = await crypto.subtle.importKey(
        'jwk',
        data.privateKeyJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
      );
    }

    // Use pre-computed public key content from setup
    const { proposedEntry } = await createHashedRekordEntry(vuKeys[__VU], data.publicKeyContent)

    const response = http.post(
      `${BASE_URL}/log/entries`,
      JSON.stringify({ hashedRekordRequestV002: proposedEntry }),
      { headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' } }
    );

    const duration = Date.now() - startTime;
    latency.add(duration);

    const success = check(response, { 'status is 201 or 409': (r) => r.status === 201 || r.status === 409 });
    errorRate.add(!success);

    if (!success) {
      console.log(`❌ Failed: ${response.status} ${response.body}`);
    } else if (response.status === 201) {
      console.log(`✅ Created (${duration}ms)`);
    }

  } catch (e) {
    errorRate.add(1);
    console.log(`💥 Exception: ${e.message}`);
  }
  sleep(0.05);
}

export async function setup() {
  console.log(`🚀 Starting Rekor Load Test | Target: ${BASE_URL}`);
  const health = http.get(`${BASE_READ_URL}/checkpoint`);
  if (health.status !== 200) throw new Error(`Health check failed`);
  console.log('✅ Health check passed');

  console.log('🔑 Generating key pair...');
  const keyPair = await generateKeyPair();

  // Pre-compute the expensive public key operations once
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicKeyContent = b64encode(publicKeyBuffer);

  console.log('🔑 Key pair generated and processed.');

  return {
    startTime: Date.now(),
    privateKeyJwk,
    publicKeyContent
  };
}

export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`🏁 Test completed in ${duration.toFixed(1)}s`);
}
