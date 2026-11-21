// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	exoscale "github.com/exoscale/egoscale/v3"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	upstream "github.com/openbao/go-kms-wrapping/wrappers/exoscalekms/v2"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

const (
	callTimeout    = 15 * time.Second
	attemptTimeout = 5 * time.Second
)

func serveOptions() *plugin.ServeOpts {
	return &plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return &guardedWrapper{
				Wrapper: upstream.NewWrapper(), timeout: callTimeout, attemptTimeout: attemptTimeout,
			}
		},
	}
}

type guardedWrapper struct {
	*upstream.Wrapper
	timeout, attemptTimeout time.Duration
}

var _ wrapping.Wrapper = (*guardedWrapper)(nil)

// retryStalled retries an upstream call that exhausted its own deadline while
// the operation can still proceed. The SDK handles other eligible HTTP retries.
func retryStalled[T any](ctx context.Context, timeout time.Duration, call func(context.Context) (T, error)) (T, error) {
	var zero T
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, timeout)
		result, err := call(attempt)
		stalled := errors.Is(attempt.Err(), context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded)
		cancel()
		if ctx.Err() == nil && !stalled {
			return result, err
		}
	}
	return zero, ctx.Err()
}

// SetConfig validates configuration before passing it to a fresh upstream wrapper.
func (w *guardedWrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	settings, err := resolveConfig(ctx, options...)
	if err != nil {
		return nil, err
	}
	var next *upstream.Wrapper
	config, err := retryStalled(ctx, w.attemptTimeout, func(attempt context.Context) (*wrapping.WrapperConfig, error) {
		next = upstream.NewWrapper()
		return next.SetConfig(attempt, wrapping.WithConfigMap(settings), wrapping.WithDisallowEnvVars(true))
	})
	if err != nil {
		return nil, publicError(ctx, "configure", err)
	}
	w.Wrapper = next
	return config, nil
}

// Encrypt delegates construction of the stored blob entirely to the upstream wrapper.
func (w *guardedWrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	blob, err := retryStalled(ctx, w.attemptTimeout, func(attempt context.Context) (*wrapping.BlobInfo, error) {
		return w.Wrapper.Encrypt(attempt, plaintext, options...)
	})
	if err != nil {
		return nil, publicError(ctx, "encrypt", err)
	}
	if len(blob.GetKeyInfo().GetWrappedKey()) == 0 {
		return nil, errors.New("Exoscale KMS encrypt returned an empty wrapped key")
	}
	return blob, nil
}

// Decrypt checks the fields used to build the request and forwards the original blob.
func (w *guardedWrapper) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	key := blob.GetKeyInfo()
	if len(key.GetWrappedKey()) == 0 || (key.GetKeyId() != "" && !validUUID(key.GetKeyId())) {
		return nil, errors.New("invalid Exoscale KMS envelope key information")
	}
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	plaintext, err := retryStalled(ctx, w.attemptTimeout, func(attempt context.Context) ([]byte, error) {
		return w.Wrapper.Decrypt(attempt, blob, options...)
	})
	if err != nil {
		return nil, publicError(ctx, "decrypt", err)
	}
	return plaintext, nil
}

// Never forward SDK error text or an error chain containing a remote body.
func publicError(ctx context.Context, op string, err error) error {
	if cause := ctx.Err(); cause != nil {
		return fmt.Errorf("Exoscale KMS %s: %w", op, cause)
	}
	var status *exoscale.APIError
	if errors.As(err, &status) {
		return &kmsapi.StatusError{Operation: op, Code: status.StatusCode, Reason: kmsapi.ProblemReason(status.Title)}
	}
	return fmt.Errorf("Exoscale KMS %s: request failed or invalid response", op)
}
