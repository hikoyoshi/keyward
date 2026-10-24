package core

import (
	"context"
	"encoding/json"
	"time"
)

// ErrorCode lets the pipe server pass a UserError's code to the AI tool.
func (e *UserError) ErrorCode() (string, string) { return e.Code, e.Msg }

// How long a call may wait for a decision before returning the current status.
const agentWait = 25 * time.Second

type agentParams struct {
	ItemID    string `json:"item_id"`
	RequestID string `json:"request_id"`
	Ref       string `json:"ref"`
	Text      string `json:"text"`
	URL       string `json:"url"`
	// fill_credentials: fields chosen by the AI from the latest snapshot (optional)
	AccountRef  string `json:"account_ref"`
	PasswordRef string `json:"password_ref"`
}

// HandleAgent serves one request from keyward-mcp.exe. Every call is authenticated by the pairing token,
// and every request_id is checked against the tool that created it.
func (s *Service) HandleAgent(ctx context.Context, token, method string, raw json.RawMessage) (any, error) {
	clientID, _, err := s.AuthClient(token)
	if err != nil {
		return nil, err
	}
	var p agentParams
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, uerr(CodeInvalid, "Invalid parameters.")
		}
	}
	ok := map[string]string{"result": "ok"}
	switch method {
	case "list_logins":
		return s.AIListLogins(clientID)
	case "request_login":
		return s.AIRequestLogin(ctx, clientID, p.ItemID, agentWait)
	case "get_status":
		return s.AIGetStatus(ctx, clientID, p.RequestID, agentWait)
	case "snapshot":
		return s.AISnapshot(ctx, clientID, p.RequestID)
	case "click":
		return ok, s.AIClick(ctx, clientID, p.RequestID, p.Ref)
	case "type":
		return ok, s.AIType(ctx, clientID, p.RequestID, p.Ref, p.Text)
	case "navigate":
		return ok, s.AINavigate(ctx, clientID, p.RequestID, p.URL)
	case "fill_credentials":
		res, err := s.AIFillCredentials(ctx, clientID, p.RequestID, p.AccountRef, p.PasswordRef)
		return map[string]string{"result": res}, err
	case "close_session":
		return ok, s.AIClose(clientID, p.RequestID)
	}
	return nil, uerr(CodeInvalid, "Unknown method.")
}
