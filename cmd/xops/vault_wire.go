package main

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/store"
	"github.com/wentf9/xops-cli/internal/host/vault"
	"github.com/wentf9/xops-cli/internal/host/vault/helper"
	"github.com/wentf9/xops-cli/internal/host/vault/offline"
)

const (
	defaultVaultDirName        = "vault"
	defaultOfflineStoreName    = "offline"
	defaultOSKeychainStoreName = "os_keychain"
)

type wiredVault struct {
	router      *vault.RouterVault
	control     ports.VaultControlPort
	knownStores []string
}

type vaultWireDeps struct {
	scopedFS ports.ScopedRootFS
	stateDir pathalg.LocalDir
	homeDir  pathalg.LocalDir
	env      ports.EnvPort
	entropy  ports.Entropy
	proc     ports.ProcessPort
}

// disabledVault 对应 YAML vNext vault.stores.<name>.kind="none" 的显式禁用存储槽位，
// 零副作用且全部读写操作严格失败关闭返回 ports.ErrUnsupported。
type disabledVault struct{}

var _ ports.SecretVault = disabledVault{}

//xops:syncclosure
//xops:borrowed
func (disabledVault) WithSecret(ctx context.Context, ref secret.Ref, fn func(box *secret.SecretBox) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !ref.IsValid() {
		return ports.ErrInvalidArgument
	}
	return ports.ErrUnsupported
}

func (disabledVault) PutAndVerify(
	ctx context.Context,
	ref secret.Ref,
	//xops:borrowed
	box *secret.SecretBox,
) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !ref.IsValid() || !box.IsValid() {
		return ports.ErrInvalidArgument
	}
	return ports.ErrUnsupported
}

func (disabledVault) Delete(ctx context.Context, ref secret.Ref) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !ref.IsValid() {
		return ports.ErrInvalidArgument
	}
	return ports.ErrUnsupported
}

// buildVaultAdapters 依据 ConfigDocument.Vault 装配多后端 RouterVault（offline_aead、os_keychain、
// external_helper、none）与可选 VaultControlPort；未配置 stores 时自动装配默认 offline + 平台原生 os_keychain，
// 并严格尊重显式 vault.default_store（对未知默认存储名失败关闭）。
func buildVaultAdapters(
	cfg *store.VaultConfigDTO,
	invKnownStores []string,
	deps vaultWireDeps,
) (wiredVault, error) {
	if cfg == nil || len(cfg.Stores) == 0 {
		defaultName := ""
		if cfg != nil {
			defaultName = strings.TrimSpace(cfg.DefaultStore)
		}
		return buildDefaultVaultAdapters(defaultName, invKnownStores, deps)
	}
	return buildConfiguredVaultAdapters(cfg, invKnownStores, deps)
}

func buildDefaultVaultAdapters(defaultName string, invKnownStores []string, deps vaultWireDeps) (wiredVault, error) {
	vaultDir, err := deps.stateDir.JoinComponent(defaultVaultDirName)
	if err != nil {
		return wiredVault{}, fmt.Errorf("resolve default vault directory failed: %w", err)
	}
	offVault, err := offline.NewVault(offline.Spec{
		ScopedFS:   deps.scopedFS,
		RootDir:    vaultDir,
		Entropy:    deps.entropy,
		StoreNames: []string{defaultOfflineStoreName},
	})
	if err != nil {
		return wiredVault{}, fmt.Errorf("initialize default offline vault failed: %w", err)
	}
	osKeychain, err := vault.NewPlatformOSKeychain(deps.env, deps.entropy)
	if err != nil {
		return wiredVault{}, fmt.Errorf("initialize platform os_keychain vault failed: %w", err)
	}
	stores := map[string]ports.SecretVault{
		defaultOfflineStoreName:    offVault,
		defaultOSKeychainStoreName: osKeychain,
	}
	defaultBackend := ports.SecretVault(offVault)
	if defaultName != "" {
		selected, ok := stores[defaultName]
		if !ok {
			closeBuiltVaults(stores)
			return wiredVault{}, fmt.Errorf("vault.default_store %q is not a known default store", defaultName)
		}
		defaultBackend = selected
	}
	router, err := vault.NewRouterVault(vault.RouterSpec{
		Stores:       stores,
		DefaultStore: defaultBackend,
	})
	if err != nil {
		closeBuiltVaults(stores)
		return wiredVault{}, fmt.Errorf("initialize router vault failed: %w", err)
	}
	return wiredVault{
		router:      router,
		control:     offVault,
		knownStores: mergeStoreNames(router.KnownStores(), invKnownStores),
	}, nil
}

func buildConfiguredVaultAdapters(
	cfg *store.VaultConfigDTO,
	invKnownStores []string,
	deps vaultWireDeps,
) (wiredVault, error) {
	stores := make(map[string]ports.SecretVault, len(cfg.Stores))
	var firstControl ports.VaultControlPort
	for _, name := range slices.Sorted(maps.Keys(cfg.Stores)) {
		backend, ctrl, err := instantiateVaultStore(name, cfg.Stores[name], deps)
		if err != nil {
			closeBuiltVaults(stores)
			return wiredVault{}, err
		}
		stores[name] = backend
		if firstControl == nil && ctrl != nil {
			firstControl = ctrl
		}
	}

	defaultBackend, selectedCtrl := selectDefaultVaultBackend(cfg.DefaultStore, stores, firstControl)
	router, err := vault.NewRouterVault(vault.RouterSpec{
		Stores:       stores,
		DefaultStore: defaultBackend,
	})
	if err != nil {
		closeBuiltVaults(stores)
		return wiredVault{}, fmt.Errorf("initialize configured router vault failed: %w", err)
	}
	return wiredVault{
		router:      router,
		control:     selectedCtrl,
		knownStores: mergeStoreNames(router.KnownStores(), invKnownStores),
	}, nil
}

func instantiateVaultStore(
	name string,
	dto store.VaultStoreDTO,
	deps vaultWireDeps,
) (ports.SecretVault, ports.VaultControlPort, error) {
	switch dto.Kind {
	case "offline_aead":
		dir, err := resolveVaultDir(dto.Path, deps.stateDir, deps.homeDir)
		if err != nil {
			return nil, nil, fmt.Errorf("vault store %q path invalid: %w", name, err)
		}
		v, err := offline.NewVault(offline.Spec{
			ScopedFS:   deps.scopedFS,
			RootDir:    dir,
			Entropy:    deps.entropy,
			StoreNames: []string{name},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("initialize offline_aead vault %q failed: %w", name, err)
		}
		return v, v, nil
	case "os_keychain":
		v, err := vault.NewPlatformOSKeychain(deps.env, deps.entropy)
		if err != nil {
			return nil, nil, fmt.Errorf("initialize os_keychain vault %q failed: %w", name, err)
		}
		return v, nil, nil
	case "external_helper":
		var timeoutOpt algebraic.Option[algebraic.Duration]
		if dto.Timeout != nil {
			timeoutOpt = algebraic.Some(*dto.Timeout)
		}
		v, err := helper.NewHelperVault(helper.HelperSpec{
			Process: deps.proc,
			Command: dto.Command,
			Args:    dto.Args,
			Timeout: timeoutOpt,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("initialize external_helper vault %q failed: %w", name, err)
		}
		return v, nil, nil
	case "none":
		return disabledVault{}, nil, nil
	default:
		return nil, nil, fmt.Errorf("unsupported vault store %q kind %q", name, dto.Kind)
	}
}

func selectDefaultVaultBackend(
	defaultName string,
	stores map[string]ports.SecretVault,
	fallbackCtrl ports.VaultControlPort,
) (ports.SecretVault, ports.VaultControlPort) {
	var def ports.SecretVault
	if trimmed := strings.TrimSpace(defaultName); trimmed != "" {
		def = stores[trimmed]
	} else if off, ok := stores[defaultOfflineStoreName]; ok {
		def = off
	} else if len(stores) == 1 {
		for _, b := range stores {
			def = b
		}
	}
	ctrl := fallbackCtrl
	if def != nil {
		if c, ok := def.(ports.VaultControlPort); ok {
			ctrl = c
		}
	}
	return def, ctrl
}

func resolveVaultDir(raw string, stateDir, homeDir pathalg.LocalDir) (pathalg.LocalDir, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return stateDir.JoinComponent(defaultVaultDirName)
	}
	expanded := expandTildePrefix(trimmed, homeDir)
	if rel, err := pathalg.ParseLocalRootedDest(expanded); err == nil {
		return joinRootedDestDir(stateDir, rel)
	}
	return pathalg.ParseLocalDir(expanded)
}

func closeBuiltVaults(stores map[string]ports.SecretVault) {
	if len(stores) == 0 {
		return
	}
	if r, err := vault.NewRouterVault(vault.RouterSpec{Stores: stores}); err == nil {
		_ = r.Close()
	}
}

func mergeStoreNames(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		if t := strings.TrimSpace(s); t != "" {
			seen[t] = struct{}{}
		}
	}
	for _, s := range b {
		if t := strings.TrimSpace(s); t != "" {
			seen[t] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(seen))
}
