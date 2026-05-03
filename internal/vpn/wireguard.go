package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	dnsdoh "github.com/qdm12/dns/v2/pkg/doh"
	dnsdot "github.com/qdm12/dns/v2/pkg/dot"
	dnsprovider "github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/qdm12/gosettings"
)

// setupWireguard sets Wireguard up using the configurators and settings given.
// It returns a serverName for port forwarding (PIA) and an error if it fails.
func setupWireguard(ctx context.Context, netlinker NetLinker,
	fw Firewall, providerConf provider.Provider,
	settings settings.VPN, ipv6SupportLevel netlink.IPv6SupportLevel, logger wireguard.Logger) (
	wireguarder *wireguard.Wireguard, connection models.Connection, err error,
) {
	ipv6Internet := ipv6SupportLevel == netlink.IPv6Internet
	connection, err = providerConf.GetConnection(settings.Provider.ServerSelection, ipv6Internet)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("finding a VPN server: %w", err)
	}

	connection, err = resolveWireguardEndpoint(ctx, connection, ipv6SupportLevel.IsSupported(), logger)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("resolving WireGuard endpoint: %w", err)
	}

	wireguardSettings := buildWireguardSettings(connection, settings.Wireguard, ipv6SupportLevel.IsSupported())

	logger.Debug("Wireguard server public key: " + wireguardSettings.PublicKey)
	logger.Debug("Wireguard client private key: " + gosettings.ObfuscateKey(wireguardSettings.PrivateKey))
	logger.Debug("Wireguard pre-shared key: " + gosettings.ObfuscateKey(wireguardSettings.PreSharedKey))

	wireguarder, err = wireguard.New(wireguardSettings, netlinker, logger)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("creating Wireguard: %w", err)
	}

	err = fw.SetVPNConnection(ctx, connection, settings.Wireguard.Interface)
	if err != nil {
		return nil, models.Connection{}, fmt.Errorf("setting firewall: %w", err)
	}

	return wireguarder, connection, nil
}

type lookupIPAddrFunc func(ctx context.Context, host string) (ips []netip.Addr, err error)
type ipAddrResolver interface {
	LookupIPAddr(ctx context.Context, host string) (ips []net.IPAddr, err error)
}

type namedIPAddrResolver struct {
	name     string
	resolver ipAddrResolver
}

func resolveWireguardEndpoint(ctx context.Context, connection models.Connection,
	ipv6Supported bool, logger wireguard.Logger,
) (connectionWithResolvedIP models.Connection, err error) {
	return resolveWireguardEndpointWithLookup(ctx, connection, ipv6Supported, logger, lookupIPAddrs)
}

func resolveWireguardEndpointWithLookup(ctx context.Context, connection models.Connection,
	ipv6Supported bool, logger wireguard.Logger, lookup lookupIPAddrFunc,
) (connectionWithResolvedIP models.Connection, err error) {
	if connection.Hostname == "" {
		return connection, nil
	}

	logger.Info("🔎 resolving WireGuard endpoint hostname " + connection.Hostname)

	ips, err := lookup(ctx, connection.Hostname)
	if err != nil {
		logger.Error("❌ failed to resolve WireGuard endpoint hostname " + connection.Hostname +
			": " + err.Error() + " (fail-closed)")
		return models.Connection{}, fmt.Errorf("resolving hostname %q: %w (fail-closed)",
			connection.Hostname, err)
	}

	connection.IP, err = pickWireguardEndpointIP(ips, ipv6Supported)
	if err != nil {
		logger.Error("❌ failed to resolve WireGuard endpoint hostname " + connection.Hostname +
			": " + err.Error() + " (fail-closed)")
		return models.Connection{}, fmt.Errorf("resolving hostname %q: %w (fail-closed)",
			connection.Hostname, err)
	}

	logger.Info("✅ resolved WireGuard endpoint hostname " + connection.Hostname +
		" to " + connection.IP.String())
	return connection, nil
}

func lookupIPAddrs(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ips, err = lookupIPAddrsWithResolver(ctx, host, net.DefaultResolver)
	if err == nil && len(ips) > 0 {
		return ips, nil
	}

	systemResolverErr := errors.New("system DNS: no addresses returned")
	if err != nil {
		systemResolverErr = fmt.Errorf("system DNS: %w", err)
	}

	encryptedResolvers, err := newEncryptedFallbackResolvers()
	if err != nil {
		return nil, errors.Join(systemResolverErr,
			fmt.Errorf("creating public encrypted DNS resolvers: %w", err))
	}

	errs := make([]error, 0, 1+len(encryptedResolvers))
	errs = append(errs, systemResolverErr)

	ips, err = lookupIPAddrsWithResolvers(ctx, host, encryptedResolvers...)
	if err != nil {
		errs = append(errs, err)
		return nil, errors.Join(errs...)
	}

	return ips, nil
}

func newEncryptedFallbackResolvers() (resolvers []namedIPAddrResolver, err error) {
	upstreamResolvers := []dnsprovider.Provider{
		dnsprovider.Cloudflare(),
		dnsprovider.Quad9Secured(),
	}

	doHDialer, err := dnsdoh.New(dnsdoh.Settings{
		UpstreamResolvers: upstreamResolvers,
	})
	if err != nil {
		return nil, fmt.Errorf("creating DoH resolver: %w", err)
	}

	doTDialer, err := dnsdot.New(dnsdot.Settings{
		UpstreamResolvers: upstreamResolvers,
	})
	if err != nil {
		return nil, fmt.Errorf("creating DoT resolver: %w", err)
	}

	return []namedIPAddrResolver{
		{
			name: "public DoH fallback",
			resolver: &net.Resolver{
				PreferGo: true,
				Dial:     doHDialer.Dial,
			},
		},
		{
			name: "public DoT fallback",
			resolver: &net.Resolver{
				PreferGo: true,
				Dial:     doTDialer.Dial,
			},
		},
	}, nil
}

func lookupIPAddrsWithResolvers(ctx context.Context, host string,
	resolvers ...namedIPAddrResolver,
) (ips []netip.Addr, err error) {
	errs := make([]error, 0, len(resolvers))
	for _, namedResolver := range resolvers {
		ips, err = lookupIPAddrsWithResolver(ctx, host, namedResolver.resolver)
		switch {
		case err == nil && len(ips) > 0:
			return ips, nil
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", namedResolver.name, err))
		default:
			errs = append(errs, fmt.Errorf("%s: no IP addresses found", namedResolver.name))
		}
	}

	return nil, errors.Join(errs...)
}

func lookupIPAddrsWithResolver(ctx context.Context, host string,
	resolver ipAddrResolver,
) (ips []netip.Addr, err error) {
	ipAddrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	ips = make([]netip.Addr, 0, len(ipAddrs))
	for i := range ipAddrs {
		ip, ok := netip.AddrFromSlice(ipAddrs[i].IP)
		if !ok {
			continue
		}
		ips = append(ips, ip.Unmap())
	}

	return ips, nil
}

func pickWireguardEndpointIP(ips []netip.Addr, ipv6Supported bool) (ip netip.Addr, err error) {
	if ipv6Supported {
		for _, candidate := range ips {
			if candidate.Is6() {
				return candidate, nil
			}
		}
	}

	for _, candidate := range ips {
		if candidate.Is4() {
			return candidate, nil
		}
	}

	if ipv6Supported {
		return netip.Addr{}, fmt.Errorf("no suitable IP address found")
	}
	return netip.Addr{}, fmt.Errorf("no IPv4 address found")
}

func buildWireguardSettings(connection models.Connection,
	userSettings settings.Wireguard, ipv6Supported bool,
) (settings wireguard.Settings) {
	settings.PrivateKey = *userSettings.PrivateKey
	settings.PublicKey = connection.PubKey
	settings.PreSharedKey = *userSettings.PreSharedKey
	settings.InterfaceName = userSettings.Interface
	settings.Implementation = userSettings.Implementation
	if *userSettings.MTU > 0 {
		settings.MTU = *userSettings.MTU
	} else {
		// The default is 1320 which is NOT the wireguard-go default
		// of 1420 because this impacts bandwidth a lot on some
		// VPN providers, see https://github.com/qdm12/gluetun/issues/1650.
		// It has been lowered to 1320 following quite a bit of
		// investigation in the issue: https://github.com/qdm12/gluetun/issues/2533.
		const defaultMTU = 1320
		settings.MTU = defaultMTU
	}
	settings.IPv6 = &ipv6Supported

	const rulePriority = 101 // 100 is to receive external connections
	settings.RulePriority = rulePriority

	settings.Endpoint = netip.AddrPortFrom(connection.IP, connection.Port)

	settings.Addresses = make([]netip.Prefix, 0, len(userSettings.Addresses))
	for _, address := range userSettings.Addresses {
		if !ipv6Supported && address.Addr().Is6() {
			continue
		}
		addressCopy := netip.PrefixFrom(address.Addr(), address.Bits())
		settings.Addresses = append(settings.Addresses, addressCopy)
	}

	settings.AllowedIPs = make([]netip.Prefix, 0, len(userSettings.AllowedIPs))
	for _, allowedIP := range userSettings.AllowedIPs {
		if !ipv6Supported && allowedIP.Addr().Is6() {
			continue
		}
		settings.AllowedIPs = append(settings.AllowedIPs, allowedIP)
	}

	settings.PersistentKeepaliveInterval = *userSettings.PersistentKeepaliveInterval

	return settings
}
