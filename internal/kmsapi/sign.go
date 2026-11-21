// SPDX-License-Identifier: MPL-2.0

package kmsapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The EXO2 transcript and header layout follow egoscale v3 SignHTTPRequest.
func sign(req *http.Request, body []byte, apiKey, secret string, expiration time.Time) {
	query := req.URL.Query()
	names := make([]string, 0, len(query))
	for name, values := range query {
		if len(values) == 1 {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	exp := strconv.FormatInt(expiration.Unix(), 10)
	header := "EXO2-HMAC-SHA256 credential=" + apiKey
	mac := hmac.New(sha256.New, []byte(secret))
	// hash.Hash.Write always accepts the complete input and returns no error.
	mac.Write([]byte(req.Method + " " + req.URL.EscapedPath() + "\n"))
	mac.Write(body)
	mac.Write([]byte("\n"))
	for _, name := range names {
		mac.Write([]byte(query.Get(name)))
	}
	if len(names) != 0 {
		header += ",signed-query-args=" + strings.Join(names, ";")
	}
	mac.Write([]byte("\n\n" + exp))
	req.Header.Set("Authorization", header+",expires="+exp+",signature="+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}
