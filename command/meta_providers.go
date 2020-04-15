package command

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	hclog "github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"

	"github.com/hashicorp/terraform/addrs"
	terraformProvider "github.com/hashicorp/terraform/builtin/providers/terraform"
	"github.com/hashicorp/terraform/internal/getproviders"
	"github.com/hashicorp/terraform/internal/providercache"
	tfplugin "github.com/hashicorp/terraform/plugin"
	"github.com/hashicorp/terraform/providers"
)

// The TF_DISABLE_PLUGIN_TLS environment variable is intended only for use by
// the plugin SDK test framework, to reduce startup overhead when rapidly
// launching and killing lots of instances of the same provider.
//
// This is not intended to be set by end-users.
var enableProviderAutoMTLS = os.Getenv("TF_DISABLE_PLUGIN_TLS") == ""

// providerInstaller returns an object that knows how to install providers and
// how to recover the selections from a prior installation process.
//
// The resulting provider installer is constructed from the results of
// the other methods providerLocalCacheDir, providerGlobalCacheDir, and
// providerInstallSource.
//
// Only one object returned from this method should be live at any time,
// because objects inside contain caches that must be maintained properly.
// Because this method wraps a result from providerLocalCacheDir, that
// limitation applies also to results from that method.
func (m *Meta) providerInstaller() *providercache.Installer {
	return m.providerInstallerCustomSource(m.providerInstallSource())
}

// providerInstallerCustomSource is a variant of providerInstaller that
// allows the caller to specify a different installation source than the one
// that would naturally be selected.
//
// The result of this method has the same dependencies and constraints as
// providerInstaller.
//
// The result of providerInstallerCustomSource differs from
// providerInstaller only in how it determines package installation locations
// during EnsureProviderVersions. A caller that doesn't call
// EnsureProviderVersions (anything other than "terraform init") can safely
// just use the providerInstaller method unconditionally.
func (m *Meta) providerInstallerCustomSource(source getproviders.Source) *providercache.Installer {
	targetDir := m.providerLocalCacheDir()
	globalCacheDir := m.providerGlobalCacheDir()
	inst := providercache.NewInstaller(targetDir, source)
	if globalCacheDir != nil {
		inst.SetGlobalCacheDir(globalCacheDir)
	}
	var builtinProviderTypes []string
	for ty := range m.internalProviders() {
		builtinProviderTypes = append(builtinProviderTypes, ty)
	}
	inst.SetBuiltInProviderTypes(builtinProviderTypes)
	return inst
}

// providerCustomLocalDirectorySource produces a provider source that consults
// only the given local filesystem directories for plugins to install.
//
// This is used to implement the -plugin-dir option for "terraform init", where
// the result of this method is used instead of what would've been returned
// from m.providerInstallSource.
//
// If the given list of directories is empty then the resulting source will
// have no providers available for installation at all.
func (m *Meta) providerCustomLocalDirectorySource(dirs []string) getproviders.Source {
	var ret getproviders.MultiSource
	for _, dir := range dirs {
		ret = append(ret, getproviders.MultiSourceSelector{
			Source: getproviders.NewFilesystemMirrorSource(dir),
		})
	}
	return ret
}

// providerLocalCacheDir returns an object representing the
// configuration-specific local cache directory. This is the
// only location consulted for provider plugin packages for Terraform
// operations other than provider installation.
//
// Only the provider installer (in "terraform init") is permitted to make
// modifications to this cache directory. All other commands must treat it
// as read-only.
//
// Only one object returned from this method should be live at any time,
// because objects inside contain caches that must be maintained properly.
func (m *Meta) providerLocalCacheDir() *providercache.Dir {
	dir := filepath.Join(m.DataDir(), "plugins")
	if dir == "" {
		return nil // cache disabled
	}
	return providercache.NewDir(dir)
}

// providerGlobalCacheDir returns an object representing the shared global
// provider cache directory, used as a read-through cache when installing
// new provider plugin packages.
//
// This function may return nil, in which case there is no global cache
// configured and new packages should be downloaded directly into individual
// configuration-specific cache directories.
//
// Only one object returned from this method should be live at any time,
// because objects inside contain caches that must be maintained properly.
func (m *Meta) providerGlobalCacheDir() *providercache.Dir {
	dir := m.PluginCacheDir
	if dir == "" {
		return nil // cache disabled
	}
	return providercache.NewDir(dir)
}

// providerInstallSource returns an object that knows how to consult one or
// more external sources to determine the availability of and package
// locations for versions of Terraform providers that are available for
// automatic installation.
//
// This returns the standard provider install source that consults a number
// of directories selected either automatically or via the CLI configuration.
// Users may choose to override this during a "terraform init" command by
// specifying one or more -plugin-dir options, in which case the installation
// process will construct its own source consulting only those directories
// and use that instead.
func (m *Meta) providerInstallSource() getproviders.Source {
	// A provider source should always be provided in normal use, but our
	// unit tests might not always populate Meta fully and so we'll be robust
	// by returning a non-nil source that just always answers that no plugins
	// are available.
	if m.ProviderSource == nil {
		// A multi-source with no underlying sources is effectively an
		// always-empty source.
		return getproviders.MultiSource(nil)
	}
	return m.ProviderSource
}

// providerFactories uses the selections made previously by an installer in
// the local cache directory (m.providerLocalCacheDir) to produce a map
// from provider addresses to factory functions to create instances of
// those providers.
//
// providerFactories will return an error if the installer's selections cannot
// be honored with what is currently in the cache, such as if a selected
// package has been removed from the cache or if the contents of a selected
// package have been modified outside of the installer. If it returns an error,
// the returned map may be incomplete or invalid.
func (m *Meta) providerFactories() (map[addrs.Provider]providers.Factory, error) {
	// We don't have to worry about potentially calling
	// providerInstallerCustomSource here because we're only using this
	// installer for its SelectedPackages method, which does not consult
	// any provider sources.
	inst := m.providerInstaller()
	selected, err := inst.SelectedPackages()
	if err != nil {
		return nil, fmt.Errorf("failed to recall provider packages selected by earlier 'terraform init': %s", err)
	}

	// The internal providers are _always_ available, even if the configuration
	// doesn't request them, because they don't need any special installation
	// and they'll just be ignored if not used.
	internalFactories := m.internalProviders()

	factories := make(map[addrs.Provider]providers.Factory, len(selected)+len(internalFactories))
	for name, factory := range internalFactories {
		factories[addrs.NewBuiltInProvider(name)] = factory
	}
	for provider, cached := range selected {
		factories[provider] = providerFactory(cached)
	}
	return factories, nil
}

func (m *Meta) internalProviders() map[string]providers.Factory {
	return map[string]providers.Factory{
		"terraform": func() (providers.Interface, error) {
			return terraformProvider.NewProvider(), nil
		},
	}
}

type reattachConfig struct {
	protocol     plugin.Protocol
	addr         net.Addr
	pid          int
	protoVersion int
}

func (r reattachConfig) Set() bool {
	if r.protocol == "" {
		return false
	}
	if r.addr == nil {
		return false
	}
	if r.addr.Network() == "" {
		return false
	}
	if r.addr.String() == "" {
		return false
	}
	if r.pid == 0 {
		return false
	}
	if r.protoVersion == 0 {
		return false
	}
	return true
}

// parse the reattach config info we need from an environment variable value
// the value should have the following format:
//
// hashicorp/random=5|unix|/tmp/plugin451906754|grpc|1234,hashicorp/local=5|unix|tmp/plugin451906755|grpc|1234
func parseReattachFromEnv(env string) (map[string]reattachConfig, error) {
	resp := map[string]reattachConfig{}
	if env == "" {
		return resp, nil
	}
	providerConfigs := strings.Split(env, ",")
	for _, conf := range providerConfigs {
		kv := strings.SplitN(conf, "=", 2)
		if len(kv) < 2 {
			return nil, errors.New("invalid reattach config format")
		}
		provider := kv[0]
		pieces := strings.Split(kv[1], "|")
		if len(pieces) < 5 {
			return nil, fmt.Errorf("invalid reattach config format for %q", kv[0])
		}
		protoStr := pieces[0]
		netType := pieces[1]
		netAddr := pieces[2]
		rpcType := pieces[3]
		pidStr := pieces[4]
		var addr net.Addr
		var err error
		switch netType {
		case "unix":
			addr, err = net.ResolveUnixAddr("unix", netAddr)
			if err != nil {
				return nil, fmt.Errorf("invalid unix socket path for %q", provider)
			}
		case "tcp":
			addr, err = net.ResolveTCPAddr("tcp", netAddr)
			if err != nil {
				return nil, fmt.Errorf("invalid TCP address for %q", provider)
			}
		default:
			return nil, fmt.Errorf("unknown address type %q for %q", netType, provider)
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PID for %q", provider)
		}
		protoVersion, err := strconv.Atoi(protoStr)
		if err != nil {
			return nil, fmt.Errorf("invalid protocol version %q for %q", protoStr, provider)
		}
		resp[kv[0]] = reattachConfig{
			protocol:     plugin.Protocol(rpcType),
			addr:         addr,
			pid:          pid,
			protoVersion: protoVersion,
		}
	}
	return resp, nil
}

// providerFactory produces a provider factory that runs up the executable
// file in the given cache package and uses go-plugin to implement
// providers.Interface against it.
func providerFactory(meta *providercache.CachedProvider) providers.Factory {
	return func() (providers.Interface, error) {
		logger := hclog.New(&hclog.LoggerOptions{
			Name:   "plugin",
			Level:  hclog.Trace,
			Output: os.Stderr,
		})

		logger.Trace("starting plugin", "provider", meta.Provider.ForDisplay())

		reattachConfigs, err := parseReattachFromEnv(os.Getenv("TF_PROVIDER_REATTACH"))
		if err != nil {
			return nil, err
		}

		logger.Trace("got reattach config", "config", spew.Sdump(reattachConfigs))

		config := &plugin.ClientConfig{
			HandshakeConfig:  tfplugin.Handshake,
			Logger:           logger,
			AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		}

		// if we have reattach information for this provider, we want
		// to connect to an already running process, instead of
		// starting a new one.
		if reattach, ok := reattachConfigs[meta.Provider.ForDisplay()]; ok && reattach.Set() {
			config.Reattach = &plugin.ReattachConfig{
				Protocol: reattach.protocol,
				Addr:     reattach.addr,
				Pid:      reattach.pid,
			}
			if plugins, ok := tfplugin.VersionedPlugins[reattach.protoVersion]; !ok {
				return nil, fmt.Errorf("unknown protocol version %d in reattach config for %q", reattach.protoVersion, meta.Provider.ForDisplay())
			} else {
				config.Plugins = plugins
			}
		} else {
			config.Cmd = exec.Command(meta.ExecutableFile)
			// we can only use AutoMTLS if we're not using reattach
			config.AutoMTLS = enableProviderAutoMTLS
			// VersionedPlugins only work when the go-plugin
			// handshake is initiated by terraform; if we start a
			// process outside of terraform, we need it to not be
			// set and to use the plugins for the protocol version
			// passed in.
			config.VersionedPlugins = tfplugin.VersionedPlugins
		}

		// when shutting down providers by stopping the server, we
		// shouldn't consider the client "managed", as go-plugin will
		// then try to kill the process at the end of Terraform's run.
		// So we only set config.Managed to true if the soft stop
		// environment variable isn't set.
		if os.Getenv("TF_PROVIDER_SOFT_STOP") == "" {
			config.Managed = true
		}

		client := plugin.NewClient(config)
		rpcClient, err := client.Client()
		if err != nil {
			return nil, err
		}

		raw, err := rpcClient.Dispense(tfplugin.ProviderPluginName)
		if err != nil {
			return nil, err
		}

		// store the client so that the plugin can kill the child process
		p := raw.(*tfplugin.GRPCProvider)
		p.PluginClient = client
		return p, nil
	}
}
