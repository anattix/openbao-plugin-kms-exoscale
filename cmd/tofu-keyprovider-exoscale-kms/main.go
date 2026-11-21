// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Stdin, os.Stdout, loadKMS)
	stop()
	if err != nil {
		// Errors from the protocol and the KMS client exclude request and response data.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadKMS(ctx context.Context) (*kmsapi.Client, kmsapi.Config, error) {
	cfg, err := kmsapi.Resolve(ctx, nil, "", false)
	if err != nil {
		return nil, kmsapi.Config{}, err
	}
	client, err := kmsapi.New(ctx, cfg)
	return client, cfg, err
}
