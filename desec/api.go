package desec

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// DNSDomains is a slice of Domain objects
type DNSDomains []DNSDomain

// RRSet defines the format of a Resource Record Set object
type RRSet struct {
	Domain  string   `json:"domain,omitempty"`
	SubName string   `json:"subname,omitempty"`
	Name    string   `json:"name,omitempty"`
	Type    string   `json:"type,omitempty"`
	Records []string `json:"records,omitempty"`
	TTL     int      `json:"ttl,omitempty"`
}

// RRSets is a slice of Resource Record Set objects
type RRSets []RRSet

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

// GetDNSDomains - returns all dns domains managed by deSEC
func (a *API) getDNSDomains() (DNSDomains, error) {
	method, path := "GET", "domains/"
	domains := new(DNSDomains)
	err := a.request(method, path, nil, domains)
	if err != nil {
		return nil, err
	}
	return *domains, nil
}

// GetDNSDomain - get the dns domain that matches the target fqdn
func (a *API) GetDNSDomain(fqdn string) (*DNSDomain, error) {
	domains, err := a.getDNSDomains()
	if err != nil {
		return nil, err
	}
	for _, v := range domains {
		if strings.HasSuffix(fqdn, v.Name) {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("domain not found")
}

// GetRRSets returns all TXT records for the subdomain portion of fqdn
func (a *API) GetRRSets(fqdn string) (RRSets, error) {
	dnsDomain, err := a.GetDNSDomain(fqdn)
	if err != nil {
		return nil, err
	}
	domain := dnsDomain.Name
	subname := fqdn[:len(fqdn)-len(domain)-1]
	method := "GET"
	path := "domains/" + domain + "/rrsets/?subname=" + subname + "&type=TXT"

	rrsets := new(RRSets)
	err = a.request(method, path, nil, rrsets)
	if err != nil {
		return nil, err
	}
	return *rrsets, nil
}
