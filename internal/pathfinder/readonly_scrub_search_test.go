package pathfinder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
)

// A grid matches its search phrase against every field of a row as stored, the
// secret included, and answers with the rows that matched. The proxy forwards the
// search as it came and blanks the secret out of the rows that come back, so which
// rows come back can still say whether a phrase occurs in a blanked secret: the
// accepted residual recorded in CLAUDE.md. These tests pin both halves, that a
// search reaches OPNsense untouched and that the answer is still cleaned.

const (
	formMedia = "application/x-www-form-urlencoded; charset=UTF-8"
	jsonMedia = "application/json"
	noRows    = `{"rows":[],"rowCount":0,"total":0,"current":1}`
)

// gridRequest is what reached the grid.
type gridRequest struct {
	method, uri, body, phrase string
}

// storedGrid stands in for the controller of a grid that searches every stored
// field. It answers with its row, as OPNsense sends it with the secret in it, when
// every token of the phrase occurs in the row (UIModelGrid::fetch keeps a row on a
// case-insensitive substring of a field), and with no rows otherwise.
type storedGrid struct {
	row  string
	mu   sync.Mutex
	seen []gridRequest
}

func (g *storedGrid) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	phrase := searchPhraseOf(r, body)
	g.mu.Lock()
	g.seen = append(g.seen, gridRequest{r.Method, r.RequestURI, string(body), phrase})
	g.mu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	for _, token := range strings.Fields(phrase) {
		if !strings.Contains(strings.ToLower(g.row), strings.ToLower(token)) {
			_, _ = io.WriteString(w, noRows)
			return
		}
	}
	_, _ = io.WriteString(w, g.row)
}

func (g *storedGrid) last() gridRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.seen) == 0 {
		return gridRequest{}
	}
	return g.seen[len(g.seen)-1]
}

// searchPhraseOf reads the phrase from where a client sends it: the query string, a
// JSON body or a form body.
func searchPhraseOf(r *http.Request, body []byte) string {
	if phrase := r.URL.Query().Get("searchPhrase"); phrase != "" {
		return phrase
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), jsonMedia) {
		var doc struct {
			SearchPhrase string `json:"searchPhrase"`
		}
		_ = json.Unmarshal(body, &doc)
		return doc.SearchPhrase
	}
	form, _ := url.ParseQuery(string(body))
	return form.Get("searchPhrase")
}

// searchedGrids are the grids of the audit whose rows carry a secret: the scrubCases
// that POST to a search action and plant one.
func searchedGrids() []scrubCase {
	var grids []scrubCase
	for _, tt := range scrubCases {
		if tt.method == "POST" && len(tt.secrets) > 0 && strings.HasPrefix(path.Base(tt.target), "search") {
			grids = append(grids, tt)
		}
	}
	return grids
}

// exchangeOn puts one request on a stream of its own and returns what the client got.
func exchangeOn(t *testing.T, proxy *HTTPProxy, raw string) *exchange {
	t.Helper()
	stream, cap := newHandleStreamTestStream()
	done := runHandleStream(proxy, stream)
	stream.readBuf <- []byte(raw)

	resp := waitForHandleStreamResponse(t, cap)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response the client got: %v", err)
	}
	ex := &exchange{resp: resp, body: string(body), raw: append([]byte(nil), cap.dataBytes()...), closed: cap.closeSent()}
	closeHandleStreamTestStream(stream)
	if err := waitHandleStreamDone(t, done); err != nil {
		t.Errorf("HandleStream returned %v", err)
	}
	return ex
}

// assertCleaned fails when a secret of the case is in what reached the client, or
// when what must stay is gone.
func assertCleaned(t *testing.T, label string, tt scrubCase, ex *exchange) {
	t.Helper()
	if ex.resp.StatusCode != http.StatusOK {
		t.Errorf("%s: status = %d (%s), want 200", label, ex.resp.StatusCode, ex.body)
		return
	}
	if ex.closed {
		t.Errorf("%s: the stream was closed after a response that was fine", label)
	}
	for _, secret := range tt.secrets {
		if bytes.Contains(ex.raw, []byte(secret)) {
			t.Errorf("%s: %q reached the client: %.300s", label, secret, ex.raw)
		}
	}
	if bytes.Contains(ex.raw, []byte("SECRET")) {
		t.Errorf("%s: a secret reached the client: %.300s", label, ex.raw)
	}
	for _, keep := range tt.keeps {
		if !strings.Contains(ex.body, keep) {
			t.Errorf("%s: %q is gone from %.300s", label, keep, ex.body)
		}
	}
}

// A search of rows that hold a secret reaches OPNsense as the client sent it, and the
// answer is cleaned: the row the stored secret selected is there, the secret is not.
// That is the accepted residual, pinned as it is: the phrase is a piece of a secret
// the client never sees, and it selects the row all the same. A read-write session,
// which is not cleaned, gets the secret from the same search, so the blanking is the
// proxy's and not the fake grid's.
func TestHandleStream_ReadOnlyForwardsASearchOfRowsThatHoldASecret(t *testing.T) {
	grids := searchedGrids()
	if len(grids) == 0 {
		t.Fatal("scrubCases holds no grid whose rows carry a secret")
	}
	for _, tt := range grids {
		t.Run(tt.target, func(t *testing.T) {
			grid := &storedGrid{row: tt.body}
			ts := httptest.NewTLSServer(grid)
			defer ts.Close()
			readOnly := newHandleStreamTestProxy(t, ts, true)

			phrase := tt.secrets[0]
			quoted, _ := json.Marshal(phrase)
			form := "current=1&rowCount=-1&searchPhrase=" + url.QueryEscape(phrase)
			spellings := []struct{ name, target, contentType, body string }{
				{"form", tt.target, formMedia, form},
				{"JSON", tt.target, jsonMedia, `{"current":1,"rowCount":-1,"searchPhrase":` + string(quoted) + `}`},
				{"query", tt.target + "?searchPhrase=" + url.QueryEscape(phrase), "", ""},
			}
			for _, s := range spellings {
				ex := exchangeOn(t, readOnly, rawRequest("POST", s.target, s.contentType, s.body))
				if got, want := grid.last(), (gridRequest{"POST", s.target, s.body, phrase}); got != want {
					t.Errorf("%s: the grid saw %+v, want %+v", s.name, got, want)
				}
				assertCleaned(t, s.name, tt, ex)
			}

			ex := exchangeOn(t, readOnly, rawRequest("POST", tt.target, formMedia, "current=1&rowCount=-1&searchPhrase=zzz-in-no-row"))
			if ex.resp.StatusCode != http.StatusOK || ex.body != noRows {
				t.Errorf("a phrase that occurs in no row: got %d %s, want 200 %s", ex.resp.StatusCode, ex.body, noRows)
			}

			ex = exchangeOn(t, newHandleStreamTestProxy(t, ts, false), rawRequest("POST", tt.target, formMedia, form))
			if !strings.Contains(ex.body, phrase) {
				t.Errorf("a read-write session was not given the secret the search selected: %.300s", ex.body)
			}
		})
	}
}

// The proxy reads nothing of a search request. Whatever its spelling, a request the
// route denylist lets through reaches OPNsense byte for byte, and the answer is
// cleaned.
func TestHandleStream_ReadOnlyForwardsASearchWhateverItsSpelling(t *testing.T) {
	const alias = "/api/firewall/alias/search_item"
	var aliasGrid scrubCase
	for _, tt := range searchedGrids() {
		if tt.target == alias {
			aliasGrid = tt
		}
	}
	if aliasGrid.body == "" {
		t.Fatal("scrubCases holds no alias grid")
	}

	const phrase = "SECRET-ALIAS"
	chunkedBody := "searchPhrase=" + phrase
	multipart := "--b\r\nContent-Disposition: form-data; name=\"searchPhrase\"\r\n\r\n" + phrase + "\r\n--b--\r\n"
	spellings := []struct {
		name, raw, method, uri, body string
	}{
		{"the query of a GET", rawRequest("GET", alias+"?searchPhrase="+phrase, "", ""), "GET", alias + "?searchPhrase=" + phrase, ""},
		{"the query of a PUT", rawRequest("PUT", alias+"?searchPhrase="+phrase, "", ""), "PUT", alias + "?searchPhrase=" + phrase, ""},
		{"an array", rawRequest("POST", alias, formMedia, "searchPhrase[]="+phrase), "POST", alias, "searchPhrase[]=" + phrase},
		{"a name in capitals and percent-encoding", rawRequest("POST", alias, formMedia, "%53EARCHPHRASE="+phrase), "POST", alias, "%53EARCHPHRASE=" + phrase},
		{"a form declared as JSON", rawRequest("POST", alias, jsonMedia, "searchPhrase="+phrase), "POST", alias, "searchPhrase=" + phrase},
		{"JSON declared as a form", rawRequest("POST", alias, formMedia, `{"searchPhrase":"`+phrase+`"}`), "POST", alias, `{"searchPhrase":"` + phrase + `"}`},
		{"JSON that is not valid", rawRequest("POST", alias, jsonMedia, `{"searchPhrase":"`+phrase+`"`), "POST", alias, `{"searchPhrase":"` + phrase + `"`},
		{"multipart", rawRequest("POST", alias, "multipart/form-data; boundary=b", multipart), "POST", alias, multipart},
		{"a body of more than a MiB", rawRequest("POST", alias, formMedia, "x="+strings.Repeat("a", 2<<20)+"&searchPhrase="+phrase), "POST", alias, "x=" + strings.Repeat("a", 2<<20) + "&searchPhrase=" + phrase},
		{
			"a chunked body",
			"POST " + alias + " HTTP/1.1\r\nHost: x\r\nContent-Type: " + formMedia + "\r\nTransfer-Encoding: chunked\r\n\r\n" +
				fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(chunkedBody), chunkedBody),
			"POST", alias, chunkedBody,
		},
	}

	grid := &storedGrid{row: aliasGrid.body}
	ts := httptest.NewTLSServer(grid)
	defer ts.Close()
	proxy := newHandleStreamTestProxy(t, ts, true)
	for _, s := range spellings {
		ex := exchangeOn(t, proxy, s.raw)
		got := grid.last()
		if got.method != s.method || got.uri != s.uri || got.body != s.body {
			t.Errorf("%s: the grid saw %s %.80q with a body of %d bytes, want %s %.80q with %d", s.name, got.method, got.uri, len(got.body), s.method, s.uri, len(s.body))
		}
		assertCleaned(t, s.name, aliasGrid, ex)
	}
}
