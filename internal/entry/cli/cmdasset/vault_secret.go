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
	"github.com/wentf9/xops-cli/internal/i18n"
)

func runVaultRefs(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, pos, err := parseVaultPositionalArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	if len(pos) != 1 {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "vault refs"), i18n.Int("count", 1), i18n.Str("usage", "<store>/<item>")))
	}
	ref, err := secret.ParseRef(pos[0])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Str("field", "secret ref"), i18n.BoundStr("value", pos[0])))
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
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, view{OK: true, Ref: ref, References: refs}, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLIVaultRefsSummary, i18n.BoundStr("ref", ref.String()), i18n.Int("count", len(refs))))
			for _, r := range refs {
				_, _ = fmt.Fprintf(w, "  %s owner=%s\n", r.Location, r.OwnerID)
			}
		})
	})
}

func runVaultDelete(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, pos, err := parseVaultPositionalArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	if len(pos) != 1 {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "vault delete"), i18n.Int("count", 1), i18n.Str("usage", "<store>/<item>")))
	}
	ref, err := secret.ParseRef(pos[0])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Str("field", "secret ref"), i18n.BoundStr("value", pos[0])))
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
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, view{OK: true, Deleted: ref}, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLIVaultDeleted, i18n.BoundStr("ref", ref.String())))
		})
	})
}

func runVaultGC(ctx context.Context, rt *clikit.Runtime, args []string) int {
	common, pos, err := parseVaultPositionalArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	if len(pos) == 0 {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountAtLeast, i18n.Str("cmd", "vault gc"), i18n.Int("count", 1), i18n.Str("usage", "<store>/<item>...")))
	}
	candidates := make([]secret.Ref, 0, len(pos))
	for _, raw := range pos {
		ref, err := secret.ParseRef(raw)
		if err != nil {
			return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Str("field", "secret ref"), i18n.BoundStr("value", raw)))
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
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, view{OK: true, Deleted: res.Deleted, Retained: res.Retained, Missing: res.Missing}, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(
				i18n.KeyCLIVaultGCComplete,
				i18n.Int("deleted", len(res.Deleted)),
				i18n.Int("retained", len(res.Retained)),
				i18n.Int("missing", len(res.Missing)),
			))
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
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, VaultHelpText(rt.Loc()))
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
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, view{
			OK: true, IdentityID: res.Identity().ID(), Fingerprint: res.Fingerprint(),
			PassphraseRef: res.PassphraseRef(), Revision: res.Revision(),
		}, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(
				i18n.KeyCLIVaultEnrolled,
				i18n.BoundStr("identity", res.Identity().ID().String()),
				i18n.BoundStr("fingerprint", res.Fingerprint().String()),
				i18n.BoundStr("ref", res.PassphraseRef().String()),
				i18n.BoundStr("revision", res.Revision().String()),
			))
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
	name, inlineVal, hasEq, isLong := clikit.ParseLongFlagName(tok)
	if !isLong {
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok))
	}
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
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", rawTok))
	}
	return nil
}

func buildEnrollKeyRequest(f enrollKeyFlags) (engine.EnrollEncryptedPrivateKeyRequest, error) {
	id, err := inventory.ParseIdentityID(f.idRaw)
	if err != nil {
		return engine.EnrollEncryptedPrivateKeyRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--id"), i18n.BoundStr("value", f.idRaw))
	}
	user, err := option.ParseUsername(f.userRaw)
	if err != nil {
		return engine.EnrollEncryptedPrivateKeyRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--user"), i18n.BoundStr("value", f.userRaw))
	}
	keySpec, err := inventory.ParseKeyPathSpec(f.keyRaw)
	if err != nil {
		return engine.EnrollEncryptedPrivateKeyRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--key-path"), i18n.BoundStr("value", f.keyRaw))
	}
	var certs []inventory.CertPathSpec
	for _, raw := range f.certPaths {
		c, err := inventory.ParseCertPathSpec(raw)
		if err != nil {
			return engine.EnrollEncryptedPrivateKeyRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--cert-path"), i18n.BoundStr("value", raw))
		}
		certs = append(certs, c)
	}
	var fpOpt algebraic.Option[inventory.KeyFingerprint]
	if strings.TrimSpace(f.fpRaw) != "" {
		fp, err := inventory.ParseKeyFingerprint(f.fpRaw)
		if err != nil {
			return engine.EnrollEncryptedPrivateKeyRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--fingerprint"), i18n.BoundStr("value", f.fpRaw))
		}
		fpOpt = algebraic.Some(fp)
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return engine.EnrollEncryptedPrivateKeyRequest{}, err
	}
	prompt, err := newVaultSecretPrompt(i18n.KeyInteractVaultEnrollKeyTitle, i18n.KeyInteractVaultEnrollKeyPrompt, keySpec.String())
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
