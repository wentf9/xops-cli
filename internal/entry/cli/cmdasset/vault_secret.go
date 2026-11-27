package cmdasset

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

func runVaultRefs(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, pos, err := parseVaultPositionalArgs("refs", args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	if len(pos) != 1 {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: vault refs 需要恰好 1 个 <store>/<item> 引用", clikit.ErrUsage))
	}
	ref, err := secret.ParseRef(pos[0])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: 凭据引用非法: %w", clikit.ErrUsage, err))
	}
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		refs, err := client.FindSecretReferences(ctx, engine.FindSecretReferencesRequest{Ref: ref})
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		type view struct {
			OK         bool                        `json:"ok"`
			Ref        secret.Ref                  `json:"ref"`
			References []inventory.SecretReference `json:"references"`
		}
		return rt.WriteResult(jsonOut, view{OK: true, Ref: ref, References: refs}, func(w io.Writer) {
			_, _ = fmt.Fprintf(w, "ref=%s references=%d\n", ref, len(refs))
			for _, r := range refs {
				_, _ = fmt.Fprintf(w, "  %s owner=%s\n", r.Location, r.OwnerID)
			}
		})
	})
}

func runVaultDelete(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, pos, err := parseVaultPositionalArgs("delete", args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	if len(pos) != 1 {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: vault delete 需要恰好 1 个 <store>/<item> 引用", clikit.ErrUsage))
	}
	ref, err := secret.ParseRef(pos[0])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: 凭据引用非法: %w", clikit.ErrUsage, err))
	}
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		if err := client.DeleteSecret(ctx, engine.DeleteSecretRequest{Ref: ref}); err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		type view struct {
			OK      bool       `json:"ok"`
			Deleted secret.Ref `json:"deleted"`
		}
		return rt.WriteResult(jsonOut, view{OK: true, Deleted: ref}, func(w io.Writer) {
			_, _ = fmt.Fprintf(w, "deleted secret %s\n", ref)
		})
	})
}

func runVaultGC(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, pos, err := parseVaultPositionalArgs("gc", args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	if len(pos) == 0 {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: vault gc 至少需要 1 个候选 <store>/<item> 引用", clikit.ErrUsage))
	}
	candidates := make([]secret.Ref, 0, len(pos))
	for _, raw := range pos {
		ref, err := secret.ParseRef(raw)
		if err != nil {
			return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: 候选引用 %q 非法: %w", clikit.ErrUsage, raw, err))
		}
		candidates = append(candidates, ref)
	}
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireVaultClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		res, err := client.GCUnreferencedSecrets(ctx, engine.GCUnreferencedRequest{Candidates: candidates})
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		type view struct {
			OK       bool                    `json:"ok"`
			Deleted  []secret.Ref            `json:"deleted,omitzero"`
			Retained []engine.RetainedSecret `json:"retained,omitzero"`
			Missing  []secret.Ref            `json:"missing,omitzero"`
		}
		return rt.WriteResult(jsonOut, view{OK: true, Deleted: res.Deleted, Retained: res.Retained, Missing: res.Missing}, func(w io.Writer) {
			_, _ = fmt.Fprintf(w, "gc complete: deleted=%d retained=%d missing=%d\n", len(res.Deleted), len(res.Retained), len(res.Missing))
		})
	})
}

type enrollKeyFlags struct {
	common    clikit.CommonFlags
	idRaw     string
	userRaw   string
	keyRaw    string
	certPaths []string
	store     string
	fpRaw     string
	desc      string
	tags      []inventory.Tag
	expRevRaw string
	replace   bool
}

func runVaultEnrollKey(ctx context.Context, rt *clikit.Runtime, args []string) int {
	f, err := parseEnrollKeyFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.Global.JSON, err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	req, err := buildEnrollKeyRequest(f)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		res, err := client.EnrollEncryptedPrivateKeyIdentity(ctx, req)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		type view struct {
			OK            bool                     `json:"ok"`
			IdentityID    inventory.IdentityID     `json:"identity_id"`
			Fingerprint   inventory.KeyFingerprint `json:"fingerprint"`
			PassphraseRef secret.Ref               `json:"passphrase_ref"`
			Revision      engine.Revision          `json:"revision"`
		}
		return rt.WriteResult(jsonOut, view{
			OK: true, IdentityID: res.Identity().ID(), Fingerprint: res.Fingerprint(),
			PassphraseRef: res.PassphraseRef(), Revision: res.Revision(),
		}, func(w io.Writer) {
			_, _ = fmt.Fprintf(w, "enrolled identity=%s fingerprint=%s ref=%s revision=%s\n",
				res.Identity().ID(), res.Fingerprint(), res.PassphraseRef(), res.Revision())
		})
	})
}

func parseEnrollKeyFlags(args []string) (enrollKeyFlags, error) {
	var f enrollKeyFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseEnrollKeyToken(cur, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseEnrollKeyToken(cur *clikit.FlagCursor, f *enrollKeyFlags) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &f.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	if tok == "-h" {
		f.common.ShowHelp = true
		return nil
	}
	name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
	if name == "replace" {
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		f.replace = v
		return err
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	return applyEnrollKeyFlag(name, val, tok, f)
}

func applyEnrollKeyFlag(name, val, rawTok string, f *enrollKeyFlags) error {
	switch name {
	case "id", "identity-id":
		f.idRaw = val
	case "user":
		f.userRaw = val
	case "key", "key-path":
		f.keyRaw = val
	case "cert", "cert-path":
		f.certPaths = append(f.certPaths, val)
	case "store":
		f.store = val
	case "fingerprint":
		f.fpRaw = val
	case "desc", "description":
		f.desc = val
	case "tag", "tags":
		return parseTagsCSV(val, &f.tags)
	case "expected-revision":
		f.expRevRaw = val
	default:
		return fmt.Errorf("%w: enroll-key 未知选项 %q", clikit.ErrUsage, rawTok)
	}
	return nil
}

func buildEnrollKeyRequest(f enrollKeyFlags) (engine.EnrollEncryptedPrivateKeyRequest, error) {
	id, err := inventory.ParseIdentityID(f.idRaw)
	if err != nil {
		return engine.EnrollEncryptedPrivateKeyRequest{}, fmt.Errorf("%w: --id 非法: %w", clikit.ErrUsage, err)
	}
	user, err := option.ParseUsername(f.userRaw)
	if err != nil {
		return engine.EnrollEncryptedPrivateKeyRequest{}, fmt.Errorf("%w: --user 非法: %w", clikit.ErrUsage, err)
	}
	keySpec, err := inventory.ParseKeyPathSpec(f.keyRaw)
	if err != nil {
		return engine.EnrollEncryptedPrivateKeyRequest{}, fmt.Errorf("%w: --key-path 非法: %w", clikit.ErrUsage, err)
	}
	var certs []inventory.CertPathSpec
	for _, raw := range f.certPaths {
		c, err := inventory.ParseCertPathSpec(raw)
		if err != nil {
			return engine.EnrollEncryptedPrivateKeyRequest{}, fmt.Errorf("%w: --cert-path %q 非法: %w", clikit.ErrUsage, raw, err)
		}
		certs = append(certs, c)
	}
	var fpOpt algebraic.Option[inventory.KeyFingerprint]
	if strings.TrimSpace(f.fpRaw) != "" {
		fp, err := inventory.ParseKeyFingerprint(f.fpRaw)
		if err != nil {
			return engine.EnrollEncryptedPrivateKeyRequest{}, fmt.Errorf("%w: --fingerprint 非法: %w", clikit.ErrUsage, err)
		}
		fpOpt = algebraic.Some(fp)
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return engine.EnrollEncryptedPrivateKeyRequest{}, err
	}
	prompt, err := engine.NewSecretPromptRequest(engine.SecretPromptRequestSpec{
		Title: "Private Key Passphrase", Prompt: "Enter private key passphrase", Subject: keySpec.String(),
	})
	if err != nil {
		return engine.EnrollEncryptedPrivateKeyRequest{}, err
	}
	return engine.EnrollEncryptedPrivateKeyRequest{
		IdentityID: id, User: user, KeyPath: keySpec, CertPaths: certs,
		Description: f.desc, Tags: f.tags, TargetStore: strings.TrimSpace(f.store),
		ExpectedFingerprint: fpOpt, ReplaceExisting: f.replace,
		ExpectedRevision: expRev, Prompt: prompt,
	}, nil
}
