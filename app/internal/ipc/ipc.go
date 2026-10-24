//go:build windows

// Package ipc is the local channel between the Keyward app and keyward-mcp.exe:
// a named pipe only the current Windows user can open, one JSON request per connection.
package ipc

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const maxMessage = 1 << 20 // snapshots can be large; requests are small

type Request struct {
	Token  string          `json:"token"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

func currentSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// PipeName is per Windows user, so two people on one PC do not share it. suffix separates test instances.
func PipeName(suffix string) (string, error) {
	sid, err := currentSID()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(sid))
	return `\\.\pipe\keyward-` + hex.EncodeToString(h[:6]) + suffix, nil
}

// Handler answers one request. It returns a value to send as the result, or an error;
// errors that carry a code (see Coded) are passed to the client as is.
type Handler func(ctx context.Context, token, method string, params json.RawMessage) (any, error)

// Coded lets a handler error choose the code the client sees.
type Coded interface {
	ErrorCode() (code, message string)
}

// Serve accepts connections until ctx ends.
func Serve(ctx context.Context, name string, h Handler) error {
	sid, err := currentSID()
	if err != nil {
		return err
	}
	l, err := winio.ListenPipe(name, &winio.PipeConfig{
		// Protected DACL: full access for this user only. No one else, not even administrators by default.
		SecurityDescriptor: "D:P(A;;GA;;;" + sid + ")",
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go handle(ctx, c, h)
	}
}

func handle(ctx context.Context, c net.Conn, h Handler) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var req Request
	if err := json.NewDecoder(io.LimitReader(c, maxMessage)).Decode(&req); err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var resp Response
	res, err := h(cctx, req.Token, req.Method, req.Params)
	if err != nil {
		var ce Coded
		if errors.As(err, &ce) {
			code, msg := ce.ErrorCode()
			resp.Error = &Error{Code: code, Message: msg}
		} else {
			resp.Error = &Error{Code: "internal", Message: "Keyward could not handle the request."}
		}
	} else if resp.Result, err = json.Marshal(res); err != nil {
		resp.Error = &Error{Code: "internal", Message: "Keyward could not encode the result."}
	}
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	json.NewEncoder(c).Encode(resp)
}

// ErrNotRunning means Keyward is closed (nothing listens on the pipe).
var ErrNotRunning = errors.New("Keyward is not running")

// Call sends one request and decodes the result into out.
func Call(ctx context.Context, name, token, method string, params, out any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	c, err := winio.DialPipeContext(dctx, name)
	cancel()
	if err != nil {
		return ErrNotRunning
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(90 * time.Second))
	}
	if err := json.NewEncoder(c).Encode(Request{Token: token, Method: method, Params: raw}); err != nil {
		return err
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(bufio.NewReader(c), maxMessage)).Decode(&resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return resp.Error
	}
	if out != nil {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}
