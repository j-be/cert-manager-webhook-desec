package desec

import (
	"bytes"
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
	Records []string `json:"records"`
	TTL     int      `json:"ttl,omitempty"`
	Created string   `json:"created,omitempty"`
	Touched string   `json:"touched,omitempty"`
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

	//if resp.StatusCode != http.StatusOK {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
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
func (a *API) GetDNSDomains() (DNSDomains, error) {
	method, path := "GET", "domains/"
	domains := new(DNSDomains)
	err := a.request(method, path, nil, domains)
	if err != nil {
		return nil, err
	}
	return *domains, nil
}

// GetDNSDomain - get the dns domain associated with the given subdomain
func (a *API) GetDNSDomain(subdomain string) (*DNSDomain, error) {
	domains, err := a.GetDNSDomains()
	if err != nil {
		return nil, err
	}
	for _, v := range domains {
		if strings.HasSuffix(subdomain, v.Name) {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("domain not found")
}

// GetRRSets returns all resource record sets for a given domain, subdomain and type
func (a *API) GetRRSets(subName, domainName, rtype string) (RRSets, error) {
	method := "GET"
	path := "domains/" + domainName + "/rrsets/?subname=" + subName + "&type=" + rtype

	rrsets := new(RRSets)
	err := a.request(method, path, nil, rrsets)
	if err != nil {
		return nil, err
	}
	return *rrsets, nil
}

// AddRecord - Adds a resource record to a new or existing RRSet
func (a *API) AddRecord(subName, domainName, rtype, content string, ttl int) (RRSets, error) {
	// First check if there's already and existing RRSet
	rrsets, err := a.GetRRSets(subName, domainName, rtype)
	if err != nil {
		return nil, err
	}
	var rrset RRSet
	if len(rrsets) > 0 {
		// RRSet exists, so see if we need to append a new record
		rrset = rrsets[0]
		for _, r := range rrset.Records {
			if r == content {
				// record already exist so just return
				return rrsets, nil
			}
		}
		// record doesn't exit so append it
		rrset.Records = append(rrset.Records, content)
	} else {
		// No existing RRSet found, so create a new one
		records := []string{content}
		rrset = RRSet{SubName: subName, Type: rtype, Records: records, TTL: ttl}
	}
	// write RRSet to deSEC
	rrsets, err = a.updateRRSet(rrset, domainName)
	if err != nil {
		return nil, err
	}
	return rrsets, nil
}

// DeleteRecord - Deletes a record from an existing RRSet if exists
func (a *API) DeleteRecord(subName, domainName, rtype, content string) (RRSets, error) {
	// Check if RRSet actually exists
	rrsets, err := a.GetRRSets(subName, domainName, rtype)
	if err != nil {
		return nil, err
	}
	if len(rrsets) > 0 {
		rrset := rrsets[0]
		var records []string
		// Create a new records slice containing all records except for the one to be deleted
		for _, r := range rrset.Records {
			if r != content {
				records = append(records, r)
			}
		}
		// Check that records have actually changed before sending update to the API
		if len(rrset.Records) != len(records) {
			// Fix empty slice from being marshalled as null
			if len(records) == 0 {
				records = make([]string, 0)
			}
			rrset.Records = records
			rrsets, err := a.updateRRSet(rrset, domainName)
			if err != nil {
				return nil, err
			}
			return rrsets, nil
		}
		return rrsets, nil
	}
	// No existing RRSet found so just return an empty RRSets object
	return RRSets{}, nil
}

func (a *API) updateRRSet(rrset RRSet, domainName string) (RRSets, error) {
	rrsets := RRSets{}
	rrsets = append(rrsets, rrset)
	rawJSON, err := json.Marshal(rrsets)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("rawJSON = %s\n", string(rawJSON)) // debug
	method := "PUT"
	path := "domains/" + domainName + "/rrsets/"
	err = a.request(method, path, bytes.NewBuffer(rawJSON), &rrsets)
	if err != nil {
		return nil, err
	}
	return rrsets, nil
}
