package github_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// mockGitHub is an in-memory stand-in for the subset of the GitHub REST API the Tier 1
// sinks use (issue comments + issues). It mirrors the statestore httptest pattern from
// Phase 3 Item 1: a status-returning handler over an in-memory store, driven entirely
// hermetically — no live network. The sinks reach it via Env{ServerURL: srv.URL} (the
// apiClient maps a non-github.com server URL to {server}/api/v3).
type mockGitHub struct {
	mu sync.Mutex

	owner, repo string

	commentsByIssue map[int][]mockComment // issue/PR number → comments
	nextCommentID   int64

	issues     []mockIssue
	nextIssue  int
	createdCmt int // count of POST comment calls (spam detector)
	createdIss int // count of POST issue calls (spam detector)
}

type mockComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

type mockIssue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
}

func newMockGitHub() *mockGitHub {
	return &mockGitHub{
		owner:           "owner",
		repo:            "repo",
		commentsByIssue: map[int][]mockComment{},
		nextCommentID:   1000,
		nextIssue:       1,
	}
}

// server starts an httptest server backed by the mock and returns it; callers defer
// Close. The handler understands only the routes the Tier 1 sinks exercise.
func (m *mockGitHub) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(srv.Close)
	return srv
}

const repoPrefix = "/api/v3/repos/owner/repo"

func (m *mockGitHub) handle(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !strings.HasPrefix(r.URL.Path, repoPrefix) {
		http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, repoPrefix)

	switch {
	// PATCH /issues/comments/{id}
	case r.Method == http.MethodPatch && strings.HasPrefix(p, "/issues/comments/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(p, "/issues/comments/"), 10, 64)
		m.patchComment(w, r, id)

	// GET|POST /issues/{n}/comments
	case strings.HasPrefix(p, "/issues/") && strings.HasSuffix(p, "/comments"):
		nStr := strings.TrimSuffix(strings.TrimPrefix(p, "/issues/"), "/comments")
		n, _ := strconv.Atoi(nStr)
		if r.Method == http.MethodGet {
			m.listComments(w, r, n)
		} else {
			m.createComment(w, r, n)
		}

	// GET|POST /issues
	case p == "/issues":
		if r.Method == http.MethodGet {
			m.listIssues(w, r)
		} else {
			m.createIssue(w, r)
		}

	// PATCH /issues/{n}
	case r.Method == http.MethodPatch && strings.HasPrefix(p, "/issues/"):
		n, _ := strconv.Atoi(strings.TrimPrefix(p, "/issues/"))
		m.patchIssue(w, r, n)

	default:
		http.Error(w, "unhandled route: "+r.Method+" "+p, http.StatusNotFound)
	}
}

func (m *mockGitHub) listComments(w http.ResponseWriter, r *http.Request, issue int) {
	page := pageParam(r)
	out := []mockComment{}
	if page <= 1 {
		out = m.commentsByIssue[issue]
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *mockGitHub) createComment(w http.ResponseWriter, r *http.Request, issue int) {
	var in struct {
		Body string `json:"body"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	m.nextCommentID++
	m.createdCmt++
	c := mockComment{ID: m.nextCommentID, Body: in.Body}
	m.commentsByIssue[issue] = append(m.commentsByIssue[issue], c)
	writeJSON(w, http.StatusCreated, c)
}

func (m *mockGitHub) patchComment(w http.ResponseWriter, r *http.Request, id int64) {
	var in struct {
		Body string `json:"body"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	for issue, list := range m.commentsByIssue {
		for i := range list {
			if list[i].ID == id {
				m.commentsByIssue[issue][i].Body = in.Body
				writeJSON(w, http.StatusOK, m.commentsByIssue[issue][i])
				return
			}
		}
	}
	http.Error(w, "comment not found", http.StatusNotFound)
}

func (m *mockGitHub) listIssues(w http.ResponseWriter, r *http.Request) {
	page := pageParam(r)
	out := []mockIssue{}
	if page <= 1 {
		out = m.issues
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *mockGitHub) createIssue(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	m.createdIss++
	iss := mockIssue{Number: m.nextIssue, Title: in.Title, Body: in.Body, State: "open"}
	m.nextIssue++
	m.issues = append(m.issues, iss)
	writeJSON(w, http.StatusCreated, iss)
}

func (m *mockGitHub) patchIssue(w http.ResponseWriter, r *http.Request, number int) {
	var in struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	for i := range m.issues {
		if m.issues[i].Number == number {
			if in.Title != "" {
				m.issues[i].Title = in.Title
			}
			m.issues[i].Body = in.Body
			writeJSON(w, http.StatusOK, m.issues[i])
			return
		}
	}
	http.Error(w, "issue not found", http.StatusNotFound)
}

func pageParam(r *http.Request) int {
	p, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || p < 1 {
		return 1
	}
	return p
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
