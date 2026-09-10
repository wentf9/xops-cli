package cmd

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/internal/credentialfile"
	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/internal/kdfhelper"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

type storeCommandOptions struct {
	unlock, keyFile, to, from, sourceID, sourceUnlock, sourceKey, backup, operation string
	timeout                                                                         time.Duration
	verify, apply, json                                                             bool
}

type storeCommandResult struct {
	Code       string                           `json:"code"`
	Op         string                           `json:"op"`
	Outcome    credentialfile.MaintenanceResult `json:"outcome"`
	Inspection *credentialfile.Inspection       `json:"inspection,omitempty"`
	Revisions  []uint64                         `json:"revisions,omitempty"`
}

func newOfflineStoreCommand(op string) *cobra.Command {
	o := &storeCommandOptions{timeout: 30 * time.Minute}
	cmd := &cobra.Command{Use: op + " <storeID>", Short: "Offline encrypted store: " + op, Args: cobra.ExactArgs(1), SilenceErrors: true, SilenceUsage: true}
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return runOfflineStore(cmd, op, args[0], o) }
	cmd.Flags().BoolVar(&o.json, "json", false, "Print metadata-only JSON result")
	switch op {
	case "inspect":
		cmd.Flags().BoolVar(&o.verify, "verify", false, "Authenticate using permitted unlock material")
	case "prune":
		cmd.Flags().BoolVar(&o.apply, "apply", false, "Apply the revalidated cleanup plan")
	case "rewrap", "resume":
		cmd.Flags().StringVar(&o.unlock, "unlock", "", "Target unlock mode: prompt or key-file")
		cmd.Flags().StringVar(&o.keyFile, "key-file", "", "Target key file (never key bytes)")
	}
	if op != "inspect" {
		cmd.Flags().DurationVar(&o.timeout, "maintenance-timeout", 30*time.Minute, "Total maintenance deadline")
	}
	if op == "clone" {
		cmd.Flags().StringVar(&o.to, "to", "", "Configured uninitialized target StoreID")
	}
	if op == "restore" || op == "resume" {
		cmd.Flags().StringVar(&o.from, "from", "", "Explicit source vault working directory")
		cmd.Flags().StringVar(&o.sourceUnlock, "source-unlock", "", "Source mode: prompt or key-file")
		cmd.Flags().StringVar(&o.sourceKey, "source-key-file", "", "Source key file path")
	}
	if op == "resume" {
		cmd.Flags().StringVar(&o.sourceID, "source-store", "", "Source StoreID for cross-vault resume")
		cmd.Flags().StringVar(&o.operation, "operation", "", "Require this operation ID")
	}
	if op == "restore" {
		cmd.Flags().StringVar(&o.backup, "backup-config", "", "Trusted schema-v2 backup configuration (required)")
	}
	return cmd
}

func runOfflineStore(cmd *cobra.Command, op, id string, o *storeCommandOptions) (err error) {
	result := storeCommandResult{Op: op}
	defer func() {
		result.Code = offlineErrorCode(err)
		if o.json {
			err = errors.Join(err, json.NewEncoder(cmd.OutOrStdout()).Encode(result))
		}
	}()
	if err := validateOfflineFlags(op, o); err != nil {
		return err
	}
	_, _, cfg, err := utils.GetConfigStore()
	if err != nil {
		return err
	}
	path, _, err := utils.GetConfigFilePath()
	if err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	selected, err := offlineConfig(cfg, id, path)
	if err != nil {
		return err
	}
	if selected.ReadOnly && op != "inspect" && (op != "prune" || o.apply) && op != "clone" {
		return credential.ErrCredentialStoreReadOnly
	}
	owner, err := utils.CredentialRuntime()
	if err != nil {
		owner = config.NewEncryptedRuntime(cmd.Context(), path, newCLIInteractionHandler())
		defer func() { err = errors.Join(err, owner.Close()) }()
	}
	duration := o.timeout
	if op == "inspect" {
		duration = selected.Timeout
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), duration)
	defer cancel()
	if selected.NonInteractive {
		ctx = credential.WithoutInteraction(ctx)
	}
	work := offlineCommand{cmd: cmd, ctx: ctx, owner: owner, cfg: cfg, configPath: path, id: id, selected: selected, options: o}
	err = work.run(op, &result)
	if !o.json && err == nil {
		if result.Inspection != nil {
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "revision=%d generation=%d unlock=%s authenticated=%t\n", result.Inspection.Revision, result.Inspection.Generation, result.Inspection.Unlock, result.Inspection.Authenticated)
		} else {
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s: revision=%d generation=%d applied=%t durable=%t cleanup=%v\n", op, result.Outcome.Revision, result.Outcome.Generation, result.Outcome.Applied, result.Outcome.Durable, result.Revisions)
		}
	}
	return err
}

type offlineCommand struct {
	cmd            *cobra.Command
	ctx            context.Context
	owner          *config.EncryptedRuntime
	cfg            *config.Configuration
	configPath, id string
	selected       config.StoreConfig
	options        *storeCommandOptions
}

func offlineConfig(cfg *config.Configuration, id, path string) (config.StoreConfig, error) {
	if cfg.Credential == nil {
		return config.StoreConfig{}, credential.ErrStoreNotFound
	}
	selected, ok := cfg.Credential.Stores[id]
	if !ok {
		return selected, credential.ErrStoreNotFound
	}
	if selected.Type != config.StoreTypeEncryptedFile {
		return selected, fmt.Errorf("store must have type encrypted-file")
	}
	return config.ResolveFileStore(selected, path)
}

func (w *offlineCommand) run(op string, result *storeCommandResult) (err error) {
	if op == "init" {
		material, err := w.material(w.selected, w.id, true)
		if err != nil {
			return err
		}
		defer clear(material.Password)
		result.Outcome, err = w.owner.Vaults().Init(w.ctx, w.selected.Path, w.id, material)
		return err
	}
	if op == "restore" {
		return w.restore(result)
	}
	s, err := w.owner.Store(w.ctx, w.id, w.selected)
	if err != nil {
		return err
	}
	switch op {
	case "inspect":
		info, e := s.Inspect(w.ctx, w.options.verify)
		result.Inspection = &info
		return e
	case "prune":
		plan, e := s.Prune(w.ctx, w.options.apply)
		result.Outcome = plan.Maintenance
		result.Revisions = plan.Revisions
		return e
	case "clone":
		return w.clone(s, result)
	case "resume":
		return w.resume(s, result)
	case "rewrap", "reencrypt":
		return w.upgrade(s, op, result)
	default:
		return fmt.Errorf("unknown offline operation")
	}
}

func (w *offlineCommand) material(cfg config.StoreConfig, id string, confirm bool) (credentialfile.Wrapping, error) {
	material := credentialfile.Wrapping{Mode: cfg.Unlock, KeyFile: cfg.KeyFile}
	if cfg.Unlock != "prompt" {
		return material, nil
	}
	ctx := w.ctx
	if cfg.NonInteractive {
		ctx = credential.WithoutInteraction(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.PromptTimeout)
	defer cancel()
	prompt := newCLIInteractionHandler()
	password, err := prompt.Password(ctx, id)
	if err != nil {
		return material, err
	}
	if confirm {
		second, e := prompt.Password(ctx, id+" (confirm new password)")
		equal := subtle.ConstantTimeCompare(password, second) == 1
		clear(second)
		if e != nil || !equal {
			clear(password)
			return material, errors.Join(e, fmt.Errorf("new password confirmation failed"))
		}
	}
	material.Password = password
	return material, nil
}

func (w *offlineCommand) targetConfig() (config.StoreConfig, error) {
	target := w.selected
	if w.options.unlock != "" {
		target.Unlock = w.options.unlock
		target.KeyFile = ""
	}
	if w.options.keyFile != "" {
		target.KeyFile = w.options.keyFile
	}
	return config.ResolveFileStore(target, w.configPath)
}

func (w *offlineCommand) upgrade(s *credentialfile.Store, op string, result *storeCommandResult) (err error) {
	target, err := w.targetConfig()
	if err != nil {
		return err
	}
	// Authenticate the configured source before requesting new wrapping material.
	if err := s.Unlock(w.ctx); err != nil {
		return err
	}
	material, err := w.material(target, w.id, op == "rewrap")
	if err != nil {
		return err
	}
	defer clear(material.Password)
	if op == "rewrap" {
		result.Outcome, err = s.Rewrap(w.ctx, material)
	} else {
		result.Outcome, err = s.Reencrypt(w.ctx, material)
	}
	if err == nil && op == "rewrap" && !w.options.json {
		_, err = fmt.Fprintf(w.cmd.OutOrStdout(), "Update store configuration explicitly: unlock: %s, key_file: %q\n", target.Unlock, target.KeyFile)
	}
	return err
}

func (w *offlineCommand) clone(s *credentialfile.Store, result *storeCommandResult) (err error) {
	target, err := offlineConfig(w.cfg, w.options.to, w.configPath)
	if err != nil {
		return err
	}
	if target.ReadOnly {
		return credential.ErrCredentialStoreReadOnly
	}
	material, err := w.material(target, w.options.to, true)
	if err != nil {
		return err
	}
	defer clear(material.Password)
	result.Outcome, err = s.Clone(w.ctx, target.Path, w.options.to, material)
	return err
}

func (w *offlineCommand) sourceConfig() (config.StoreConfig, error) {
	source := w.selected
	if w.options.from == "" {
		return source, nil
	}
	source.Path = w.options.from
	source.ReadOnly = true
	if w.options.sourceUnlock == "" {
		return source, fmt.Errorf("--source-unlock is required with --from")
	}
	source.Unlock = w.options.sourceUnlock
	source.KeyFile = w.options.sourceKey
	return config.ResolveFileStore(source, w.configPath)
}

func (w *offlineCommand) restore(result *storeCommandResult) (err error) {
	if w.options.from == "" || w.options.backup == "" {
		return fmt.Errorf("restore requires --from and --backup-config")
	}
	refs, err := config.BackupReferences(w.options.backup, w.id)
	if err != nil {
		return err
	}
	cfg, err := w.sourceConfig()
	if err != nil {
		return err
	}
	source, err := w.owner.Store(w.ctx, w.id, cfg)
	if err != nil {
		return err
	}
	material, err := w.material(w.selected, w.id, true)
	if err != nil {
		return err
	}
	defer clear(material.Password)
	result.Outcome, err = source.Restore(w.ctx, w.selected.Path, material, refs)
	return err
}

func (w *offlineCommand) resume(s *credentialfile.Store, result *storeCommandResult) (err error) {
	target, err := w.targetConfig()
	if err != nil {
		return err
	}
	sourceCfg, err := w.sourceConfig()
	if err != nil {
		return err
	}
	source := s
	sourceID := w.id
	if w.options.from != "" {
		if w.options.sourceID != "" {
			sourceID = w.options.sourceID
		}
		source, err = w.owner.Store(w.ctx, sourceID, sourceCfg)
		if err != nil {
			return err
		}
	}
	to, err := w.material(target, w.id, false)
	if err != nil {
		return err
	}
	defer clear(to.Password)
	from := credentialfile.Wrapping{Mode: sourceCfg.Unlock, KeyFile: sourceCfg.KeyFile}
	// Only prepublication non-init recovery needs source material. Inspection is
	// advisory here; ResumeOperation authenticates and rechecks all state under lock.
	needsSource, inspectErr := s.RecoveryNeedsSource(w.ctx)
	if inspectErr != nil {
		return inspectErr
	}
	if needsSource {
		from, err = w.material(sourceCfg, sourceID, false)
		if err != nil {
			return err
		}
		defer clear(from.Password)
	}
	result.Outcome, err = s.ResumeOperation(w.ctx, w.options.operation, source, from, to)
	return err
}

func offlineErrorCode(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, credential.ErrCredentialStoreLocked):
		return "locked"
	case errors.Is(err, credentialfile.ErrUnsupported), errors.Is(err, format.ErrUnsupported):
		return "unsupported"
	case errors.Is(err, credentialfile.ErrMaintenanceRequired):
		return "maintenance_required"
	case errors.Is(err, credentialfile.ErrRevisionChanged):
		return "revision_changed"
	case errors.Is(err, credentialfile.ErrConflict):
		return "conflict"
	case errors.Is(err, format.ErrCorrupt), errors.Is(err, format.ErrIdentity):
		return "corrupt"
	case errors.Is(err, credentialfile.ErrResourceBusy):
		return "resource_busy"
	case errors.Is(err, kdfhelper.ErrResource):
		return "resource_exhausted"
	case errors.Is(err, credential.ErrCredentialStoreUnavailable):
		return "unavailable"
	case errors.Is(err, credential.ErrCredentialStoreReadOnly):
		return "read_only"
	case errors.Is(err, credentialfile.ErrKeyUsageExhausted):
		return "key_usage_exhausted"
	case errors.Is(err, credential.ErrCredentialAccessDenied):
		return "access_denied"
	default:
		return "failed"
	}
}

func validateOfflineFlags(op string, o *storeCommandOptions) error {
	if o.timeout <= 0 {
		return fmt.Errorf("maintenance timeout must be positive")
	}
	if op == "clone" && o.to == "" {
		return fmt.Errorf("clone requires --to")
	}
	if o.from == "" && (o.sourceID != "" || o.sourceUnlock != "" || o.sourceKey != "") {
		return fmt.Errorf("source flags require --from")
	}
	if o.operation != "" {
		if len(o.operation) != 32 {
			return fmt.Errorf("operation must be 32 lowercase hexadecimal characters")
		}
		for _, c := range o.operation {
			if !strings.ContainsRune("0123456789abcdef", c) {
				return fmt.Errorf("operation must be lowercase hexadecimal")
			}
		}
	}
	return nil
}
