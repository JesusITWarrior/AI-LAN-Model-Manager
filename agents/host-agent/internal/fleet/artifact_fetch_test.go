package fleet

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchArtifactUsesFixedRouteTicketAndExactRange(t *testing.T) {
	ticket := "a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != artifactDownloadPath || r.URL.RawQuery != "" || r.Header.Get("X-LANMM-Download-Ticket") != ticket || r.Header.Get("Range") != "bytes=4-" {
			t.Errorf("unexpected request %s?%s ticket=%q range=%q", r.URL.Path, r.URL.RawQuery, r.Header.Get("X-LANMM-Download-Ticket"), r.Header.Get("Range"))
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "6")
		w.Header().Set("Content-Range", "bytes 4-9/10")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("efghij"))
	}))
	defer server.Close()
	client := &HTTPSClient{http: server.Client(), base: server.URL}
	result, err := client.FetchArtifact(context.Background(), ticket, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	body, _ := io.ReadAll(result.Body)
	if string(body) != "efghij" || result.Offset != 4 || result.Total != 10 || result.Length != 6 {
		t.Fatalf("bad result %#v %q", result, body)
	}
}

func TestFetchArtifactRejectsRangeMismatchAndOpaqueTicketAbuse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "6")
		w.Header().Set("Content-Range", "bytes 3-8/10")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("defghi"))
	}))
	defer server.Close()
	client := &HTTPSClient{http: server.Client(), base: server.URL}
	valid := "a123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if _, err := client.FetchArtifact(context.Background(), valid, 4); err == nil {
		t.Fatal("accepted mismatched range")
	}
	if _, err := client.FetchArtifact(context.Background(), "../path?url=https://evil", 0); err == nil {
		t.Fatal("accepted non-opaque ticket")
	}
}
