package desec

import (
	"io"
	"net/http"
)

const baseURL = "https://desec.io/api/v1"

// API is the basic implemenataion of an API client for desec.io
type API struct {
	Token string
}

// TODO: Use correct response type to return
func (a *API) Request(method, path string, body io.Reader) (*http.Response, error) {
	if path[0] != '/' {
		path = "/" + path
	}

	url := baseURL + path

	client := &http.Client{}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token "+a.Token)
	req.Header.Set("Content-Type", "application/json")

	// TODO: add k8s logging
	// klog.V(6).Infof("%s %s", method, url)
	rawResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return rawResp, nil
}
