package desec

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const baseURL = "https://desec.io/api/v1"

// API is the basic implemenataion of an API client for desec.io
type API struct {
	Token string
}

// ErrorResponse defines the error response format
type ErrorResponse struct {
	Detail string `json:"detail,omitempty"`
}

// DNSDomain defines the format of a Domain object
type DNSDomain struct {
	Created    string `json:"created,omitempty"`
	Published  string `json:"published,omitempty"`
	Name       string `json:"name,omitempty"`
	MinimumTTL int    `json:"minimum_ttl,omitempty"`
	Touched    string `json:"touched,omitempty"`
}

// DNSDomains is an array of Domain objects
type DNSDomains []DNSDomain

// Request builds the raw request
func (a *API) request(method, path string, body io.Reader) (*http.Response, error) {
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
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// TODO: add k8s logging
	// klog.V(6).Infof("%s %s", method, url)
	rawResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return rawResp, nil
}

// GetDomains gets an array of domains
func (a *API) GetDomains() (DNSDomains, error) {
	method, path := "GET", "domains/"
	resp, err := a.request(method, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		var domains DNSDomains
		if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
			return nil, fmt.Errorf("%s %s response parsing error: %v", method, path, err)
		}
		return domains, nil
	}
	var errResp ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return nil, fmt.Errorf("%s %s unknown error occured", method, path)
	}
	return nil, fmt.Errorf("%s %s error: %s", method, path, errResp.Detail)
}

/*
var resp APIResponse
	if err := json.NewDecoder(rawResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("%s %s response parsing error: %v", method, path, err)
	}

	// rawJSON, _ := json.Marshal(resp)
	// TODO: klog.V(8).Infof("Response status: `%s` json response: `%v`", rawResp.Status, string(rawJSON))
*/
