package community_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeLoginDoesNotCreateEmulatorBridge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.yml")
	// Stale lab environment must not add a second authentication channel.
	t.Setenv("NP_PIER_SESSION_FILE", path)
	t.Setenv("NP_PIER_RPCN_HOST", "127.0.0.1:31313")
	t.Setenv("NP_PIER_BACKEND_KEY", strings.Repeat("k", 32))
	_, _, _, handler := setup(t)
	response := login(handler, "a@example.org", "pw")
	if response.Code != http.StatusOK || response.Header().Get("X-I-5-Status") != "OK" || response.Body.Len() == 0 {
		t.Fatal("native sign-in failed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("native sign-in exported an emulator session")
	}
	request := httptest.NewRequest(http.MethodPost, "/internal/pier/verify", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("k", 32))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("obsolete bridge endpoint remains reachable: %d", recorder.Code)
	}
}
