//go:build windows

package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type codedErr struct{ code, msg string }

func (e codedErr) Error() string               { return e.msg }
func (e codedErr) ErrorCode() (string, string) { return e.code, e.msg }

func TestRoundTrip(t *testing.T) {
	name, err := PipeName("-test-" + time.Now().Format("150405.000"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, name, func(_ context.Context, token, method string, params json.RawMessage) (any, error) {
		if token != "good" {
			return nil, codedErr{"unauthorized", "bad token"}
		}
		switch method {
		case "echo":
			var p map[string]string
			json.Unmarshal(params, &p)
			return p, nil
		case "boom":
			return nil, errors.New("internal detail that must not leak")
		}
		return nil, codedErr{"invalid", "unknown"}
	})
	time.Sleep(200 * time.Millisecond)

	var out map[string]string
	if err := Call(ctx, name, "good", "echo", map[string]string{"a": "b"}, &out); err != nil || out["a"] != "b" {
		t.Fatalf("echo: %v %v", out, err)
	}
	var ie *Error
	if err := Call(ctx, name, "bad", "echo", nil, nil); !errors.As(err, &ie) || ie.Code != "unauthorized" {
		t.Fatalf("bad token: %v", err)
	}
	if err := Call(ctx, name, "good", "boom", nil, nil); !errors.As(err, &ie) || ie.Code != "internal" || ie.Message == "internal detail that must not leak" {
		t.Fatalf("internal error: %v", err)
	}
	if err := Call(ctx, name+"-missing", "good", "echo", nil, nil); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("not running: %v", err)
	}
}
