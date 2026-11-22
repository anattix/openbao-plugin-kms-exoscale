// SPDX-License-Identifier: MPL-2.0

package kmsapi

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// KeySize is the AES-256 data key length in bytes.
	KeySize = 32
	// MaxWrappedKey bounds the size of the opaque ciphertext accepted from KMS.
	MaxWrappedKey = 32 << 10
)

var (
	uuidPattern   = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
	zonePattern   = regexp.MustCompile("^[a-z]{2}-[a-z]{2,3}-[0-9]{1,3}$")
	apiKeyPattern = regexp.MustCompile("^[A-Za-z0-9_-]+$")
)

// Config holds the credentials and routing for a single Exoscale zone.
type Config struct {
	KeyID, Zone       string
	APIKey, APISecret string
	CAFile            string
	// EncryptionContext binds wrapped data keys to a caller-chosen nonsecret name.
	EncryptionContext string
	Timeout           time.Duration
	AllowedKeyIDs     []string
	// DialContext permits local TLS integration tests without replacing URL or trust checks.
	DialContext func(context.Context, string, string) (net.Conn, error)
}

// ValidKeyID reports whether id is a canonical lower-case UUID.
func ValidKeyID(id string) bool { return uuidPattern.MatchString(id) }

// ValidZone reports whether zone is a supported API hostname label.
func ValidZone(zone string) bool { return zonePattern.MatchString(zone) }

// Resolve applies explicit settings before environment defaults and reads credentials.
func Resolve(ctx context.Context, settings map[string]string, keyID string, disallowEnv bool) (Config, error) {
	if keyID == "" {
		keyID = setting(settings, "key_id", "EXOSCALEKMS_KEY_ID", disallowEnv)
	}
	cfg := Config{
		KeyID:             strings.ToLower(keyID),
		Zone:              setting(settings, "zone", "EXOSCALE_ZONE", disallowEnv),
		CAFile:            setting(settings, "ca_file", "EXOSCALEKMS_CA_FILE", disallowEnv),
		EncryptionContext: setting(settings, "encryption_context", "EXOSCALEKMS_ENCRYPTION_CONTEXT", disallowEnv),
		Timeout:           3 * time.Second,
	}
	if !ValidKeyID(cfg.KeyID) || !ValidZone(cfg.Zone) {
		return Config{}, errors.New("configure a KMS key UUID and an Exoscale zone")
	}
	if value := cfg.EncryptionContext; len(value) > 1024 ||
		!utf8.ValidString(value) || strings.ContainsFunc(value, unicode.IsControl) {
		return Config{}, errors.New("EXOSCALEKMS_ENCRYPTION_CONTEXT must be at most 1024 bytes of printable UTF-8")
	}
	if err := resolveLimits(settings, disallowEnv, &cfg); err != nil {
		return Config{}, err
	}
	var err error
	cfg.APIKey, err = credential(ctx, settings, "api_key_file", "EXOSCALEKMS_API_KEY_FILE", "EXOSCALE_API_KEY", disallowEnv)
	if err != nil {
		return Config{}, err
	}
	cfg.APISecret, err = credential(ctx, settings, "api_secret_file", "EXOSCALEKMS_API_SECRET_FILE", "EXOSCALE_API_SECRET", disallowEnv)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func resolveLimits(settings map[string]string, disallowEnv bool, cfg *Config) error {
	if value := setting(settings, "timeout", "EXOSCALEKMS_TIMEOUT", disallowEnv); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout <= 0 || timeout > 10*time.Second {
			return errors.New("KMS timeout must be a positive duration no greater than 10s")
		}
		cfg.Timeout = timeout
	}
	switch value := strings.ToLower(setting(settings, "allow_other_keys", "EXOSCALEKMS_ALLOW_OTHER_KEYS", disallowEnv)); value {
	case "", "false", "0", "f":
	default:
		return errors.New("allow_other_keys is not supported; use allowed_key_ids")
	}
	if value := setting(settings, "allowed_key_ids", "EXOSCALEKMS_ALLOWED_KEY_IDS", disallowEnv); value != "" {
		for item := range strings.SplitSeq(value, ",") {
			id := strings.ToLower(strings.TrimSpace(item))
			if !ValidKeyID(id) {
				return errors.New("allowed_key_ids must be a comma-separated list of KMS key UUIDs")
			}
			cfg.AllowedKeyIDs = append(cfg.AllowedKeyIDs, id)
		}
	}
	return nil
}

// ResolveDecryptionKey checks the stored key against the active key policy.
func ResolveDecryptionKey(active, stored string, allowed []string) (string, error) {
	if !ValidKeyID(stored) {
		return "", errors.New("invalid stored KMS key UUID")
	}
	if active != stored && !slices.Contains(allowed, stored) {
		return "", errors.New("stored KMS key UUID is not allowed")
	}
	return stored, nil
}

func setting(settings map[string]string, key, env string, disallowEnv bool) string {
	if value, ok := settings[key]; ok {
		return value
	}
	if !disallowEnv {
		return os.Getenv(env)
	}
	return ""
}

func credential(ctx context.Context, settings map[string]string, key, fileEnv, valueEnv string, disallowEnv bool) (string, error) {
	if path := setting(settings, key, fileEnv, disallowEnv); path != "" {
		return ReadCredentialFile(ctx, path)
	}
	if !disallowEnv {
		return os.Getenv(valueEnv), nil
	}
	return "", nil
}

// ReadCredentialFile reads a bounded, nonempty credential from a regular file.
func ReadCredentialFile(ctx context.Context, path string) (string, error) {
	raw, err := readFile(ctx, path, 8192)
	if err != nil {
		return "", errors.New("cannot read or validate Exoscale credential file")
	}
	defer clear(raw)
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", errors.New("empty Exoscale credential file")
	}
	return value, nil
}

// ReadExactCredentialFile reads a bounded credential that must have no
// surrounding whitespace. The upstream wrapper reads file:// values without
// trimming, so the seal refuses files that only work after trimming.
func ReadExactCredentialFile(ctx context.Context, path string) (string, error) {
	raw, err := readFile(ctx, path, 8192)
	if err != nil {
		return "", errors.New("cannot read or validate Exoscale credential file")
	}
	defer clear(raw)
	value := string(raw)
	if value == "" || strings.TrimSpace(value) != value {
		return "", errors.New("Exoscale credential file must be nonempty and have no surrounding whitespace or newline")
	}
	return value, nil
}

func readFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid configuration file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open configuration file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	closeErr := f.Close()
	if err != nil || closeErr != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("cannot read configuration file")
	}
	return data, nil
}
