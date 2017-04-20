// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/common/log"
)

const (
	CUSTOM_HEADER_SPLIT             = "||"
	CUSTOM_RANGE_STATUS_CODES_SPLIT = "-"
)

func matchRegularExpressions(reader io.Reader, config HTTPProbe) bool {
	body, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Errorf("Error reading HTTP body: %s", err)
		return false
	}
	for _, expression := range config.FailIfMatchesRegexp {
		re, err := regexp.Compile(expression)
		if err != nil {
			log.Errorf("Could not compile expression %q as regular expression: %s", expression, err)
			return false
		}
		if re.Match(body) {
			return false
		}
	}
	for _, expression := range config.FailIfNotMatchesRegexp {
		re, err := regexp.Compile(expression)
		if err != nil {
			log.Errorf("Could not compile expression %q as regular expression: %s", expression, err)
			return false
		}
		if !re.Match(body) {
			return false
		}
	}
	return true
}

func matchRangeStatusCodes(respCode int, validRangeStatusCode string) bool {
	range_status_codes := strings.Split(validRangeStatusCode, CUSTOM_RANGE_STATUS_CODES_SPLIT)
	if len(range_status_codes) == 2 && len(range_status_codes[0]) > 0 && len(range_status_codes[1]) > 0 {
		start_valid_range_status_code, err := strconv.Atoi(range_status_codes[0])
		if err != nil {
			log.Errorf("Could not parse valid_range_status_codes to int: %s", err)
			return false
		}

		end_valid_range_status_code, err := strconv.Atoi(range_status_codes[1])
		if err != nil {
			log.Errorf("Could not parse valid_range_status_codes to int: %s", err)
			return false
		}

		if respCode >= start_valid_range_status_code && respCode <= end_valid_range_status_code {
			return true
		} else {
			return false
		}
	} else {
		log.Errorf("Could not parse valid_range_status_codes: %s", validRangeStatusCode)
		return false
	}
}

func loadCustomHTTPConfig(cfg *HTTPProbe, targetParams ...url.Values) (success bool) {
	// overwrite cfg params
	var (
		customValidStatusCodes       = []int{}
		customValidRangeStatusCodes  = []string{}
		customFailIfMatchesRegexp    = []string{}
		customFailIfNotMatchesRegexp = []string{}
		customBody                   = ""
	)

	for _, targetHeadersParam := range targetParams[0]["headers"] {
		header := strings.Split(targetHeadersParam, CUSTOM_HEADER_SPLIT)
		if len(header) == 2 && len(header[0]) > 0 && len(header[1]) > 0 {
			if cfg.Headers == nil {
				cfg.Headers = make(map[string]string, 10)
			}
			cfg.Headers[header[0]] = header[1]
		} else {
			log.Errorf("Could not parse headers: %s", targetHeadersParam)
			return false
		}
	}

	for _, targetValidStatusCodesParam := range targetParams[0]["valid_status_codes"] {
		valid_status_code, err := strconv.Atoi(targetValidStatusCodesParam)
		if err != nil {
			log.Errorf("Could not parse valid_status_codes to int: %s", err)
			return false
		}
		customValidStatusCodes = append(customValidStatusCodes, valid_status_code)
	}

	if len(customValidStatusCodes) > 0 {
		cfg.ValidStatusCodes = customValidStatusCodes
	}

	for _, targetValidRangeStatusCodesParam := range targetParams[0]["valid_range_status_codes"] {
		customValidRangeStatusCodes = append(customValidRangeStatusCodes, targetValidRangeStatusCodesParam)
	}

	if len(customValidRangeStatusCodes) > 0 {
		cfg.ValidRangeStatusCodes = customValidRangeStatusCodes
	}

	for _, targetFailIfMatchesRegexpParam := range targetParams[0]["fail_if_matches_regexp"] {
		customFailIfMatchesRegexp = append(customFailIfMatchesRegexp, targetFailIfMatchesRegexpParam)
	}

	if len(customFailIfMatchesRegexp) > 0 {
		cfg.FailIfMatchesRegexp = customFailIfMatchesRegexp
	}

	for _, targetFailIfNotMatchesRegexpParam := range targetParams[0]["fail_if_not_matches_regexp"] {
		customFailIfNotMatchesRegexp = append(customFailIfMatchesRegexp, targetFailIfNotMatchesRegexpParam)
	}

	if len(customFailIfNotMatchesRegexp) > 0 {
		cfg.FailIfNotMatchesRegexp = customFailIfNotMatchesRegexp
	}

	customBody = targetParams[0].Get("body")
	if customBody != "" {
		cfg.Body = customBody
	}

	return true
}

func probeHTTP(target string, w http.ResponseWriter, module Module, params ...url.Values) (success bool) {
	var isSSL, redirects int
	var dialProtocol, fallbackProtocol string

	config := module.HTTP
	if params != nil {
		if ok := loadCustomHTTPConfig(&config, params...); !ok {
			log.Errorf("Failed loading custom http config for target %s")
			return false
		}
	}

	if module.HTTP.Protocol == "" {
		module.HTTP.Protocol = "tcp"
	}

	if module.HTTP.Protocol == "tcp" && module.HTTP.PreferredIPProtocol == "" {
		module.HTTP.PreferredIPProtocol = "ip6"
	}
	if module.HTTP.PreferredIPProtocol == "ip6" {
		fallbackProtocol = "ip4"
	} else {
		fallbackProtocol = "ip6"
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	dialProtocol = module.HTTP.Protocol
	if module.HTTP.Protocol == "tcp" {
		targetURL, err := url.Parse(target)
		if err != nil {
			return false
		}
		targetHost, _, err := net.SplitHostPort(targetURL.Host)
		// If split fails, assuming it's a hostname without port part
		if err != nil {
			targetHost = targetURL.Host
		}
		ip, err := net.ResolveIPAddr(module.HTTP.PreferredIPProtocol, targetHost)
		if err != nil {
			ip, err = net.ResolveIPAddr(fallbackProtocol, targetHost)
			if err != nil {
				return false
			}
		}

		if ip.IP.To4() == nil {
			dialProtocol = "tcp6"
		} else {
			dialProtocol = "tcp4"
		}
	}

	if dialProtocol == "tcp6" {
		fmt.Fprintln(w, "probe_ip_protocol 6")
	} else {
		fmt.Fprintln(w, "probe_ip_protocol 4")
	}

	client := &http.Client{
		Timeout: module.Timeout,
	}

	tlsconfig, err := module.HTTP.TLSConfig.GenerateConfig()
	if err != nil {
		log.Errorf("Error generating TLS config: %s", err)
		return false
	}
	dial := func(network, address string) (net.Conn, error) {
		return net.Dial(dialProtocol, address)
	}
	client.Transport = &http.Transport{
		TLSClientConfig:   tlsconfig,
		Dial:              dial,
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
	}

	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		redirects = len(via)
		if redirects > 10 || config.NoFollowRedirects {
			return errors.New("Don't follow redirects")
		}
		return nil
	}

	if config.Method == "" {
		config.Method = "GET"
	}

	request, err := http.NewRequest(config.Method, target, nil)
	if err != nil {
		log.Errorf("Error creating request for target %s: %s", target, err)
		return
	}

	for key, value := range config.Headers {
		if strings.Title(key) == "Host" {
			request.Host = value
			continue
		}
		request.Header.Set(key, value)
	}

	// If a body is configured, add it to the request
	if config.Body != "" {
		request.Body = ioutil.NopCloser(strings.NewReader(config.Body))
	}

	resp, err := client.Do(request)
	// Err won't be nil if redirects were turned off. See https://github.com/golang/go/issues/3795
	if err != nil && resp == nil {
		log.Warnf("Error for HTTP request to %s: %s", target, err)
	} else {
		defer resp.Body.Close()

		if len(config.ValidStatusCodes) != 0 {
			for _, code := range config.ValidStatusCodes {
				if resp.StatusCode == code {
					success = true
					break
				}
			}

			if !success {
				for _, rangeCode := range config.ValidRangeStatusCodes {
					if matchRangeStatusCodes(resp.StatusCode, rangeCode) {
						success = true
						break
					}
				}
			}
		} else if 200 <= resp.StatusCode && resp.StatusCode < 300 {
			success = true
		}

		if success && (len(config.FailIfMatchesRegexp) > 0 || len(config.FailIfNotMatchesRegexp) > 0) {
			success = matchRegularExpressions(resp.Body, config)
		}
	}

	if resp == nil {
		resp = &http.Response{}
	}

	if resp.TLS != nil {
		isSSL = 1
		fmt.Fprintf(w, "probe_ssl_earliest_cert_expiry %f\n",
			float64(getEarliestCertExpiry(resp.TLS).UnixNano())/1e9)
		if config.FailIfSSL {
			success = false
		}
	} else if config.FailIfNotSSL {
		success = false
	}
	fmt.Fprintf(w, "probe_http_status_code %d\n", resp.StatusCode)
	fmt.Fprintf(w, "probe_http_content_length %d\n", resp.ContentLength)
	fmt.Fprintf(w, "probe_http_redirects %d\n", redirects)
	fmt.Fprintf(w, "probe_http_ssl %d\n", isSSL)
	return
}
