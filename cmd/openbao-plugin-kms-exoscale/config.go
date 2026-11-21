// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	upstream "github.com/openbao/go-kms-wrapping/wrappers/exoscalekms/v2"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

func validUUID(id string) bool {
	return kmsapi.ValidKeyID(strings.ToLower(id))
}

func resolveConfig(ctx context.Context, options ...wrapping.Option) (map[string]string, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, errors.New("invalid Exoscale KMS options")
	}
	key := opts.WithKeyId
	if configured, ok := opts.WithConfigMap["key_id"]; ok {
		key = configured
	}
	key = fromEnv(opts, upstream.EnvExoscaleKmsKeyId, key)
	if !validUUID(key) {
		return nil, errors.New("configure a valid Exoscale KMS key UUID")
	}
	zone := fromEnv(opts, upstream.EnvExoscaleKmsZone, opts.WithConfigMap["zone"])
	endpoint := fromEnv(opts, upstream.EnvExoscaleKmsEndpoint, opts.WithConfigMap["endpoint"])
	if (zone != "" || endpoint == "") && !kmsapi.ValidZone(zone) {
		return nil, errors.New("configure a valid Exoscale KMS zone or HTTPS endpoint")
	}
	if endpoint == "" {
		// Use the documented zone endpoint. Avoid discovery and the use
		// of an API response as the destination of signed requests.
		endpoint = "https://api-" + zone + ".exoscale.com/v2"
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(endpoint, "#") {
		return nil, errors.New("Exoscale KMS endpoint must be HTTPS without credentials, query or fragment")
	}
	if u.EscapedPath() != "/v2" && u.EscapedPath() != "/v2/" {
		return nil, errors.New("Exoscale KMS endpoint path must be /v2")
	}
	apiKey := fromEnv(opts, upstream.EnvExoscaleApiKey, "")
	secret := fromEnv(opts, upstream.EnvExoscaleApiSecret, "")
	apiKey, err = credential(ctx, opts, "api_key", apiKey)
	if err != nil {
		return nil, err
	}
	secret, err = credential(ctx, opts, "api_secret", secret)
	if err != nil {
		return nil, err
	}
	return map[string]string{"key_id": key, "zone": zone, "endpoint": strings.TrimRight(endpoint, "/"),
		"api_key": apiKey, "api_secret": secret}, nil
}

func fromEnv(opts *wrapping.Options, name, fallback string) string {
	if !opts.WithDisallowEnvVars {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return fallback
}

func credential(ctx context.Context, opts *wrapping.Options, name, envValue string) (string, error) {
	if envValue != "" {
		return envValue, nil
	}
	ref := opts.WithConfigMap[name]
	if path, ok := strings.CutPrefix(ref, "file://"); ok && filepath.IsAbs(path) {
		return kmsapi.ReadExactCredentialFile(ctx, path)
	}
	if env, ok := strings.CutPrefix(ref, "env://"); ok && !opts.WithDisallowEnvVars {
		if value := os.Getenv(env); value != "" {
			return value, nil
		}
	}
	return "", errors.New("configure Exoscale credentials in the environment or with file:// paths")
}
