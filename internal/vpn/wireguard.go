package vpn

import (
	"context"
	"fmt"
	"net"
	"net/netip"

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
		return nil, models.Connection{}, fmt.Errorf("resolving Wireguard endpoint: %w", err)
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

func resolveWireguardEndpoint(ctx context.Context, connection models.Connection,
	ipv6Supported bool, logger wireguard.Logger,
) (resolved models.Connection, err error) {
	return resolveWireguardEndpointWithLookup(ctx, connection, ipv6Supported, logger, lookupIPAddrs)
}

func resolveWireguardEndpointWithLookup(ctx context.Context, connection models.Connection,
	ipv6Supported bool, logger wireguard.Logger, lookup lookupIPAddrFunc,
) (resolved models.Connection, err error) {
	if connection.Hostname == "" {
		return connection, nil
	}

	logger.Info("🔎 resolving Wireguard endpoint hostname " + connection.Hostname)

	ips, err := lookup(ctx, connection.Hostname)
	if err != nil {
		logger.Error("❌ failed to resolve Wireguard endpoint hostname " + connection.Hostname +
			": " + err.Error() + " (fail-closed)")
		return models.Connection{}, fmt.Errorf("resolving hostname %q: %w (fail-closed)",
			connection.Hostname, err)
	}

	connection.IP, err = pickWireguardEndpointIP(ips, ipv6Supported)
	if err != nil {
		logger.Error("❌ failed to resolve Wireguard endpoint hostname " + connection.Hostname +
			": " + err.Error() + " (fail-closed)")
		return models.Connection{}, fmt.Errorf("resolving hostname %q: %w (fail-closed)",
			connection.Hostname, err)
	}

	logger.Info("✅ resolved Wireguard endpoint hostname " + connection.Hostname +
		" to " + connection.IP.String())
	return connection, nil
}

func lookupIPAddrs(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
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
		return netip.Addr{}, fmt.Errorf("no IPv4 or IPv6 address found")
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
