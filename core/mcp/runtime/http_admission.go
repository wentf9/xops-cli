package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const maxMCPBodyBytes = 4 << 20

// protocolAdmission runs after service authentication. Bodies are classified
// through a separately bounded, short-lived read/parse lane so an SSE stream or
// waiting tool POST cannot consume capacity needed for handshake completion,
// replies or cancellation.
// The SDK still validates session ownership, response IDs and protocol details.
func (r *Runtime) protocolAdmission(next http.Handler, requests chan struct{}) http.Handler {
	parsers := make(chan struct{}, r.http.MaxRequests)
	controls := make(chan struct{}, r.http.MaxRequests)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		slots := requests
		message := "request_limit"
		if req.URL.Path == "/mcp" && req.Method == http.MethodPost {
			control, ok := classifyMCPBody(w, req, parsers)
			if !ok {
				return
			}
			if control {
				slots = controls
				message = "control_limit"
			}
		}
		if !acquireHTTPAdmission(w, slots, message) {
			return
		}
		defer func() { <-slots }()
		next.ServeHTTP(w, req)
	})
}

func acquireHTTPAdmission(w http.ResponseWriter, slots chan struct{}, message string) bool {
	select {
	case slots <- struct{}{}:
		return true
	default:
		http.Error(w, message, http.StatusTooManyRequests)
		return false
	}
}

func classifyMCPBody(w http.ResponseWriter, req *http.Request, parsers chan struct{}) (control, ok bool) {
	if !acquireHTTPAdmission(w, parsers, "body_admission_limit") {
		return false, false
	}
	defer func() { <-parsers }()
	body := http.MaxBytesReader(w, req.Body, maxMCPBodyBytes)
	data, err := io.ReadAll(body)
	err = errors.Join(err, body.Close())
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "mcp_body_limit", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid_mcp_body", http.StatusBadRequest)
		}
		return false, false
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	return isMCPControl(data), true
}

func isMCPControl(data []byte) bool {
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  json.RawMessage `json:"method"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
		Params  json.RawMessage `json:"params"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.JSONRPC != "2.0" {
		return false
	}
	if len(envelope.Method) != 0 {
		// Notifications have no top-level ID/result/error. The SDK still
		// validates their session and parameters after admission.
		if len(envelope.ID) != 0 || len(envelope.Result) != 0 || len(envelope.Error) != 0 {
			return false
		}
		return isMCPControlNotification(envelope.Method, envelope.Params)
	}
	if (len(envelope.Result) == 0) == (len(envelope.Error) == 0) {
		return false
	}
	var id any
	if json.Unmarshal(envelope.ID, &id) != nil {
		return false
	}
	switch id.(type) {
	case string, float64:
		return true
	default:
		return false
	}
}

func isMCPControlNotification(rawMethod, params json.RawMessage) bool {
	var method string
	if json.Unmarshal(rawMethod, &method) != nil {
		return false
	}
	switch method {
	case "notifications/initialized":
		// The initialize response may still hold a request slot after it is
		// flushed and the client opens standalone SSE. Handshake completion
		// must not contend with those requests. Params are optional objects.
		return len(params) == 0 || params[0] == '{'
	case "notifications/cancelled":
		return validMCPCancellation(params)
	default:
		return false
	}
}

func validMCPCancellation(data []byte) bool {
	var params struct {
		RequestID json.RawMessage `json:"requestId"`
		Reason    json.RawMessage `json:"reason"`
	}
	if json.Unmarshal(data, &params) != nil || len(params.RequestID) == 0 {
		return false
	}
	if len(params.Reason) != 0 {
		var reason string
		if params.Reason[0] != '"' || json.Unmarshal(params.Reason, &reason) != nil {
			return false
		}
	}
	if params.RequestID[0] == '"' {
		var id string
		return json.Unmarshal(params.RequestID, &id) == nil
	}
	// null unmarshals into a zero integer without error; reject it explicitly.
	if bytes.Equal(params.RequestID, []byte("null")) {
		return false
	}
	var id int64
	return json.Unmarshal(params.RequestID, &id) == nil
}
