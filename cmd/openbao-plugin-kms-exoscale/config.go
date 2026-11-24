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
	if strings.TrimSuffix(u.EscapedPath(), "/") != "/v2" {
		return nil, errors.New("Exoscale KMS endpoint path must be /v2 with at most one trailing slash")
	}
	endpoint = strings.TrimSuffix(endpoint, "/")
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
	return map[string]string{"key_id": key, "zone": zone, "endpoint": endpoint,
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
	ref := opts.WithConfigMap[name]
	if envValue != "" {
		// The reference must resolve, but its content is unused.
		if err := checkOverriddenReference(ctx, ref); err != nil {
			return "", err
		}
		return envValue, nil
	}
	value, err := credentialReference(ctx, ref, opts.WithDisallowEnvVars)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", errors.New("configure Exoscale credentials in the environment or with file:// paths")
	}
	return value, nil
}

func checkOverriddenReference(ctx context.Context, ref string) error {
	if path, ok := strings.CutPrefix(ref, "file://"); ok {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !filepath.IsAbs(path) {
			return errors.New("Exoscale credential file path must be absolute")
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 {
			return errors.New("cannot resolve Exoscale credential file reference")
		}
		f, err := os.Open(path)
		if err != nil || f.Close() != nil {
			return errors.New("cannot resolve Exoscale credential file reference")
		}
	}
	if name, ok := strings.CutPrefix(ref, "env://"); ok {
		if _, set := os.LookupEnv(name); !set {
			return errors.New("cannot resolve Exoscale credential environment reference")
		}
	}
	return nil
}

func credentialReference(ctx context.Context, ref string, disallowEnv bool) (string, error) {
	if path, ok := strings.CutPrefix(ref, "file://"); ok {
		if !filepath.IsAbs(path) {
			return "", errors.New("Exoscale credential file path must be absolute")
		}
		return kmsapi.ReadExactCredentialFile(ctx, path)
	}
	if name, ok := strings.CutPrefix(ref, "env://"); ok {
		if !disallowEnv {
			if value := os.Getenv(name); value != "" {
				return value, nil
			}
		}
		return "", errors.New("cannot resolve Exoscale credential environment reference")
	}
	return "", nil
}
