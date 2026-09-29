package fleet

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/JesusITWarrior/AI-LAN-Model-Manager/agents/host-agent/internal/command"
)

const artifactDownloadPath = "/agent/v1/artifacts/download"

// FetchArtifact uses the already enrolled, pinned mTLS client and a compile-time
// controller-relative route. The opaque ticket can authorize that single route;
// it can never supply a URL, host, path, or arbitrary header.
func (c *HTTPSClient) FetchArtifact(ctx context.Context, ticket string, offset int64) (command.ArtifactFetch, error) {
	if c == nil || c.http == nil || len(ticket) != 64 || offset < 0 {
		return command.ArtifactFetch{}, ErrHTTPClient
	}
	for _, ch := range ticket {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return command.ArtifactFetch{}, ErrHTTPClient
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+artifactDownloadPath, nil)
	if err != nil {
		return command.ArtifactFetch{}, ErrHTTPClient
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("X-LANMM-Download-Ticket", ticket)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	doer := c.artifactHTTP
	if doer == nil { // dependency-injected tests and legacy constructed clients
		doer = c.http
	}
	response, err := doer.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return command.ArtifactFetch{}, ctx.Err()
		}
		return command.ArtifactFetch{}, ErrHTTPClient
	}
	if response == nil || response.Body == nil {
		return command.ArtifactFetch{}, ErrHTTPClient
	}
	fail := func() (command.ArtifactFetch, error) {
		response.Body.Close()
		return command.ArtifactFetch{}, ErrHTTPClient
	}
	media := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if media != "application/octet-stream" {
		return fail()
	}
	length, err := strconv.ParseInt(response.Header.Get("Content-Length"), 10, 64)
	if err != nil || length < 1 {
		return fail()
	}
	var total int64
	if response.StatusCode == http.StatusPartialContent {
		start, end, size, ok := parseContentRange(response.Header.Get("Content-Range"))
		if !ok || start != offset || end-start+1 != length {
			return fail()
		}
		total = size
	} else if response.StatusCode == http.StatusOK && offset == 0 {
		total = length
	} else {
		return fail()
	}
	if total < 1 || offset+length != total {
		return fail()
	}
	return command.ArtifactFetch{Body: response.Body, Offset: offset, Total: total, Length: length}, nil
}

func parseContentRange(value string) (int64, int64, int64, bool) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, false
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(parts) != 2 {
		return 0, 0, 0, false
	}
	rangeParts := strings.Split(parts[0], "-")
	if len(rangeParts) != 2 {
		return 0, 0, 0, false
	}
	start, e1 := strconv.ParseInt(rangeParts[0], 10, 64)
	end, e2 := strconv.ParseInt(rangeParts[1], 10, 64)
	total, e3 := strconv.ParseInt(parts[1], 10, 64)
	return start, end, total, e1 == nil && e2 == nil && e3 == nil && start >= 0 && end >= start && total > end
}

var _ command.ArtifactFetcher = (*HTTPSClient)(nil)
