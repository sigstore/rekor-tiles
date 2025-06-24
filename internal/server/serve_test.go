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

package server

import (
	"context"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestServe(t *testing.T) {
	wg := sync.WaitGroup{}
	var pid atomic.Uint64
	shutdownFn := func(context.Context) error {
		wg.Done()
		return nil
	}
	go func() {
		pid.Store(uint64(syscall.Getpid())) // Process IDs are positive ints
		Serve(context.Background(), NewHTTPConfig(), NewGRPCConfig(), nil, shutdownFn)
		wg.Done()
	}()
	// One for Serve returning, one for shutdown function being invoked
	wg.Add(2)

	i := 0
	for {
		if i == 5 {
			t.Fatalf("could not get process ID in 5 seconds")
		}
		if pid.Load() != 0 {
			break
		}
		i++
		time.Sleep(1 * time.Second)
	}

	// Shutdown server gracefully to test that Serve shuts down gRPC and HTTP servers and Tessera connection
	if err := syscall.Kill(int(pid.Load()), syscall.SIGTERM); err != nil {
		t.Fatalf("Could not kill server")
	}
	wg.Wait()
}
