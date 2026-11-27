package cmdasset

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type mutationView struct {
	OK              bool                     `json:"ok"`
	Action          string                   `json:"action"`
	Revision        engine.Revision          `json:"revision"`
	Durability      engine.DurabilityOutcome `json:"durability"`
	DeletedSecrets  []secret.Ref             `json:"deleted_secrets,omitzero"`
	RetainedSecrets []engine.RetainedSecret  `json:"retained_secrets,omitzero"`
}

func renderMutationResult(rt *clikit.Runtime, action string, res engine.MutationResult, jsonOut bool) int {
	v := mutationView{
		OK:              true,
		Action:          action,
		Revision:        res.Revision(),
		Durability:      res.Durability(),
		DeletedSecrets:  res.DeletedSecrets(),
		RetainedSecrets: res.RetainedSecrets(),
	}
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, v, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(
			i18n.KeyCLIHostsMutationOK,
			i18n.Str("action", action),
			i18n.BoundStr("revision", res.Revision().String()),
			i18n.Str("durability", res.Durability().Status().String()),
		))
	})
}

type hostUpsertFlags struct {
	common    clikit.CommonFlags
	idRaw     string
	addrRaw   string
	aliasRaw  string
	desc      string
	tags      []inventory.Tag
	expRevRaw string
}

func runHostUpsert(ctx context.Context, rt *clikit.Runtime, isUpdate bool, args []string) int {
	f, err := parseHostUpsertFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("hosts", args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	req, err := buildHostMutationReq(f)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		var res engine.MutationResult
		action := "create_host"
		if isUpdate {
			action = "update_host"
			res, err = client.UpdateHost(ctx, req)
		} else {
			res, err = client.CreateHost(ctx, req)
		}
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		return renderMutationResult(rt, action, res, jsonOut)
	})
}

func parseHostUpsertFlags(args []string) (hostUpsertFlags, error) {
	var f hostUpsertFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &f.common); err != nil || consumed {
			if err != nil {
				return f, err
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			f.common.ShowHelp = true
			return f, nil
		}
		name, inlineVal, hasEq, isLong := clikit.ParseLongFlagName(tok)
		if !isLong {
			return f, i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok))
		}
		val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return f, err
		}
		if err := applyHostFlagValue(name, val, tok, &f); err != nil {
			return f, err
		}
	}
	return f, nil
}

func applyHostFlagValue(name, val, rawTok string, f *hostUpsertFlags) error {
	switch name {
	case "id":
		f.idRaw = val
	case "address", "endpoint":
		f.addrRaw = val
	case "alias":
		f.aliasRaw = val
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

func buildHostMutationReq(f hostUpsertFlags) (engine.HostMutationRequest, error) {
	id, err := inventory.ParseHostID(f.idRaw)
	if err != nil {
		return engine.HostMutationRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--id"), i18n.BoundStr("value", f.idRaw))
	}
	ep, err := netaddr.ParseEndpoint(f.addrRaw)
	if err != nil {
		return engine.HostMutationRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--address"), i18n.BoundStr("value", f.addrRaw))
	}
	var aliasOpt algebraic.Option[inventory.Alias]
	if strings.TrimSpace(f.aliasRaw) != "" {
		a, err := inventory.ParseAlias(f.aliasRaw)
		if err != nil {
			return engine.HostMutationRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--alias"), i18n.BoundStr("value", f.aliasRaw))
		}
		aliasOpt = algebraic.Some(a)
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return engine.HostMutationRequest{}, err
	}
	host, err := inventory.NewHost(inventory.HostSpec{ID: id, Endpoint: ep, Alias: aliasOpt, Description: f.desc, Tags: f.tags})
	if err != nil {
		return engine.HostMutationRequest{}, domi18n.WrapSentinel(clikit.ErrUsage, err)
	}
	return engine.HostMutationRequest{Host: host, ExpectedRevision: expRev}, nil
}

type identityUpsertFlags struct {
	common     clikit.CommonFlags
	idRaw      string
	userRaw    string
	authKind   string
	passRefRaw string
	keyPaths   []string
	certPaths  []string
	passphrase string
	keyFP      string
	agentSpec  string
	desc       string
	tags       []inventory.Tag
	expRevRaw  string
	gcOld      bool
}

func runIdentityUpsert(ctx context.Context, rt *clikit.Runtime, isUpdate bool, args []string) int {
	f, err := parseIdentityUpsertFlags(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("hosts", args)), err)
	}
	if f.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, HostsHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(f.common.JSON)
	req, err := buildIdentityMutationReq(f)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(f.common.ConfigFile, f.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireInventoryClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		var res engine.MutationResult
		action := "create_identity"
		if isUpdate {
			action = "update_identity"
			res, err = client.UpdateIdentity(ctx, req)
		} else {
			res, err = client.CreateIdentity(ctx, req)
		}
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		return renderMutationResult(rt, action, res, jsonOut)
	})
}

func parseIdentityUpsertFlags(args []string) (identityUpsertFlags, error) {
	f := identityUpsertFlags{authKind: "agent"}
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if err := parseIdentityToken(cur, &f); err != nil {
			return f, err
		}
		if f.common.ShowHelp {
			return f, nil
		}
	}
	return f, nil
}

func parseIdentityToken(cur *clikit.FlagCursor, f *identityUpsertFlags) error {
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
	if name == "gc-old-secrets" {
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		f.gcOld = v
		return err
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	return applyIdentityFlagValue(name, val, tok, f)
}

func applyIdentityFlagValue(name, val, rawTok string, f *identityUpsertFlags) error {
	switch name {
	case "id":
		f.idRaw = val
	case "user":
		f.userRaw = val
	case "auth-kind":
		f.authKind = strings.ToLower(strings.TrimSpace(val))
	case "password-ref":
		f.passRefRaw = val
	case "key-path":
		f.keyPaths = append(f.keyPaths, val)
	case "cert-path":
		f.certPaths = append(f.certPaths, val)
	case "passphrase-ref":
		f.passphrase = val
	case "key-fingerprint":
		f.keyFP = val
	case "agent-spec":
		f.agentSpec = val
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

func buildIdentityMutationReq(f identityUpsertFlags) (engine.IdentityMutationRequest, error) {
	id, err := inventory.ParseIdentityID(f.idRaw)
	if err != nil {
		return engine.IdentityMutationRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--id"), i18n.BoundStr("value", f.idRaw))
	}
	user, err := option.ParseUsername(f.userRaw)
	if err != nil {
		return engine.IdentityMutationRequest{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--user"), i18n.BoundStr("value", f.userRaw))
	}
	auth, err := buildAuthMethod(f)
	if err != nil {
		return engine.IdentityMutationRequest{}, err
	}
	expRev, err := parseOptionalRevision(f.expRevRaw)
	if err != nil {
		return engine.IdentityMutationRequest{}, err
	}
	ident, err := inventory.NewIdentity(inventory.IdentitySpec{ID: id, User: user, Auth: auth, Description: f.desc, Tags: f.tags})
	if err != nil {
		return engine.IdentityMutationRequest{}, domi18n.WrapSentinel(clikit.ErrUsage, err)
	}
	return engine.IdentityMutationRequest{Identity: ident, ExpectedRevision: expRev, GCUnreferencedOldSecrets: f.gcOld}, nil
}

func buildAuthMethod(f identityUpsertFlags) (inventory.AuthMethod, error) {
	switch f.authKind {
	case "agent":
		var specOpt algebraic.Option[inventory.AgentSpec]
		if strings.TrimSpace(f.agentSpec) != "" {
			s, err := inventory.ParseAgentSpec(f.agentSpec)
			if err != nil {
				return nil, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--agent-spec"), i18n.BoundStr("value", f.agentSpec))
			}
			specOpt = algebraic.Some(s)
		}
		return inventory.NewAuthAgent(specOpt)
	case "password":
		ref, err := secret.ParseRef(f.passRefRaw)
		if err != nil {
			return nil, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--password-ref"), i18n.BoundStr("value", f.passRefRaw))
		}
		return inventory.NewAuthPassword(ref)
	case "private_key":
		return buildPrivateKeyAuth(f)
	default:
		return nil, i18n.EF(clikit.ErrUsage, i18n.KeyCLIInvalidFlagValueEnum, i18n.Str("flag", "--auth-kind"), i18n.Str("allowed", "agent|password|private_key"), i18n.BoundStr("value", f.authKind))
	}
}

func buildPrivateKeyAuth(f identityUpsertFlags) (inventory.AuthMethod, error) {
	if len(f.keyPaths) == 0 {
		return nil, i18n.EF(clikit.ErrUsage, i18n.KeyCLIMissingRequiredFlag, i18n.Str("cmd", "private_key"), i18n.Str("flag", "--key-path"))
	}
	var keys []inventory.KeyPathSpec
	for _, raw := range f.keyPaths {
		k, err := inventory.ParseKeyPathSpec(raw)
		if err != nil {
			return nil, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--key-path"), i18n.BoundStr("value", raw))
		}
		keys = append(keys, k)
	}
	neKeys, err := algebraic.NonEmptyFromSlice(keys)
	if err != nil {
		return nil, domi18n.WrapSentinel(clikit.ErrUsage, err)
	}
	var certs []inventory.CertPathSpec
	for _, raw := range f.certPaths {
		c, err := inventory.ParseCertPathSpec(raw)
		if err != nil {
			return nil, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--cert-path"), i18n.BoundStr("value", raw))
		}
		certs = append(certs, c)
	}
	pbOpt, err := buildPassphraseBinding(f.passphrase, f.keyFP)
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthPrivateKey(neKeys, pbOpt, certs)
}

func buildPassphraseBinding(passphraseRaw, keyFPRaw string) (algebraic.Option[inventory.KeyPassphraseBinding], error) {
	if strings.TrimSpace(passphraseRaw) == "" && strings.TrimSpace(keyFPRaw) == "" {
		return algebraic.None[inventory.KeyPassphraseBinding](), nil
	}
	ref, err := secret.ParseRef(passphraseRaw)
	if err != nil {
		return algebraic.None[inventory.KeyPassphraseBinding](), i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--passphrase-ref"), i18n.BoundStr("value", passphraseRaw))
	}
	fp, err := inventory.ParseKeyFingerprint(keyFPRaw)
	if err != nil {
		return algebraic.None[inventory.KeyPassphraseBinding](), i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--key-fingerprint"), i18n.BoundStr("value", keyFPRaw))
	}
	pb, err := inventory.NewKeyPassphraseBinding(ref, fp)
	if err != nil {
		return algebraic.None[inventory.KeyPassphraseBinding](), domi18n.WrapSentinel(clikit.ErrUsage, err)
	}
	return algebraic.Some(pb), nil
}
