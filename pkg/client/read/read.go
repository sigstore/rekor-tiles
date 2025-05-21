//
// Copyright 2025 The Sigstore Authors.
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

package read

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sigstore/rekor-tiles/pkg/client"
	rekornote "github.com/sigstore/rekor-tiles/pkg/note"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/formats/log"
	tclient "github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

// Client reads checkpoints, tiles, and entry bundles from the tile storage service.
type Client interface {
	ReadCheckpoint(context.Context) (*log.Checkpoint, *note.Note, error)
	ReadTile(context.Context, uint64, uint64, uint8) ([]byte, error)
	ReadEntryBundle(context.Context, uint64, uint8) ([]byte, error)
}

type readClient struct {
	baseURL  *url.URL
	client   *tclient.HTTPFetcher
	origin   string
	verifier note.Verifier
}

// NewReader creates a new reader client.
func NewReader(readURL, origin string, verifier signature.Verifier, opts ...client.Option) (Client, error) {
	cfg := &client.Config{}
	for _, o := range opts {
		o(cfg)
	}
	baseURL, err := url.Parse(readURL)
	if err != nil {
		return nil, fmt.Errorf("parsing url %s: %w", readURL, err)
	}
	noteVerifier, err := rekornote.NewNoteVerifier(origin, verifier)
	if err != nil {
		return nil, fmt.Errorf("creating note verifier: %w", err)
	}
	httpClient := &http.Client{
		Transport: client.CreateRoundTripper(http.DefaultTransport, cfg.UserAgent),
		Timeout:   cfg.Timeout,
	}
	tileClient, err := tclient.NewHTTPFetcher(baseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating tile client: %w", err)
	}
	return &readClient{
		baseURL:  baseURL,
		client:   tileClient,
		origin:   origin,
		verifier: noteVerifier,
	}, nil
}

// ReadCheckpoint returns the current checkpoint.
func (r *readClient) ReadCheckpoint(ctx context.Context) (*log.Checkpoint, *note.Note, error) {
	readCheckpoint := r.client.ReadCheckpoint
	cp, _, n, err := tclient.FetchCheckpoint(ctx, readCheckpoint, r.verifier, r.origin)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching checkpoint: %w", err)
	}
	return cp, n, nil
}

// ReadTile returns the tile at the given level, index, and tile segment.
func (r *readClient) ReadTile(ctx context.Context, level, index uint64, p uint8) ([]byte, error) {
	tile, err := r.client.ReadTile(ctx, level, index, p)
	if err != nil {
		return nil, fmt.Errorf("reading tile: %w", err)
	}
	return tile, nil
}

// ReadEntryBundle returns the entries at the given index.
func (r *readClient) ReadEntryBundle(ctx context.Context, index uint64, p uint8) ([]byte, error) {
	bundle, err := r.client.ReadEntryBundle(ctx, index, p)
	if err != nil {
		return nil, fmt.Errorf("reading entry bundle: %w", err)
	}
	return bundle, nil
}
