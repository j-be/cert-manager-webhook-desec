package desec

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
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
func (a *API) request(method, path string, body io.Reader, target interface{}) error {
	if path[0] != '/' {
		path = "/" + path
	}

	url := baseURL + path

	client := &http.Client{Timeout: time.Second * 10}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+a.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// TODO: add k8s logging
	// klog.V(6).Infof("%s %s", method, url)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return fmt.Errorf("%s %s unknown error occured", method, path)
		}
		return fmt.Errorf("%s %s error: %s", method, path, errResp.Detail)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("%s %s response parsing error: %v", method, path, err)
	}

	return nil
}

// GetDomains - returns all dns domains managed by deSEC
func (a *API) GetDomains() (DNSDomains, error) {
	method, path := "GET", "domains/"
	domains := new(DNSDomains)
	err := a.request(method, path, nil, domains)
	if err != nil {
		return nil, err
	}
	return *domains, nil
}

/*
var resp APIResponse
	if err := json.NewDecoder(rawResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("%s %s response parsing error: %v", method, path, err)
	}

	// rawJSON, _ := json.Marshal(resp)
	// TODO: klog.V(8).Infof("Response status: `%s` json response: `%v`", rawResp.Status, string(rawJSON))
*/
