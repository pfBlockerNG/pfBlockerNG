package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// maintenance owns a separate worker lane; a canceled Core stops observing, not the transaction.
func maintenance(path, stateDir string) func(context.Context) error {
	if path == "" {
		return nil
	}
	command := update.Command{Path: path}
	logPath := filepath.Join(stateDir, "maintenance.log")
	return func(ctx context.Context) error {
		log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("the maintenance log cannot be opened: %w", err)
		}
		defer log.Close()
		_, err = command.Run(ctx, update.Request{}, log)
		if errors.Is(err, update.ErrRunning) || errors.Is(err, update.ErrDeferred) {
			return nil
		}
		return err
	}
}
