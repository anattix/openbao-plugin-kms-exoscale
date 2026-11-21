// SPDX-License-Identifier: MPL-2.0

package kmsapi

import "context"

// ProbeOnce records the result of a single HTTP attempt for conformance tests.
func ProbeOnce(ctx context.Context, c *Client, id, operation string, body []byte) error {
	data, _, err := c.attempt(ctx, id, operation, body)
	clear(data)
	return err
}

// ProbeLifecycle exercises the production retry dispatcher without exposing it to callers.
func ProbeLifecycle(ctx context.Context, c *Client, id, operation string) error {
	return c.post(ctx, id, operation, nil, &response{})
}
