package vpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopWireguardLogger struct{}

func (noopWireguardLogger) Debug(string)                  {}
func (noopWireguardLogger) Debugf(string, ...interface{}) {}
func (noopWireguardLogger) Info(string)                   {}
func (noopWireguardLogger) Error(string)                  {}
func (noopWireguardLogger) Errorf(string, ...any)         {}

func Test_buildWireguardSettings(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		connection    models.Connection
		userSettings  settings.Wireguard
		ipv6Supported bool
		settings      wireguard.Settings
	}{
		"some_settings": {
			connection: models.Connection{
				IP:     netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:   51821,
				PubKey: "public",
			},
			userSettings: settings.Wireguard{
				PrivateKey:   ptrTo("private"),
				PreSharedKey: ptrTo("pre-shared"),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 32),
					netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 32),
				},
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
					netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 32),
				},
				PersistentKeepaliveInterval: ptrTo(time.Hour),
				Interface:                   "wg1",
				MTU:                         ptrTo(uint32(1000)),
			},
			ipv6Supported: false,
			settings: wireguard.Settings{
				InterfaceName: "wg1",
				PrivateKey:    "private",
				PublicKey:     "public",
				PreSharedKey:  "pre-shared",
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51821),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 32),
				},
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				},
				PersistentKeepaliveInterval: time.Hour,
				RulePriority:                101,
				IPv6:                        ptrTo(false),
				MTU:                         1000,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := buildWireguardSettings(testCase.connection,
				testCase.userSettings, testCase.ipv6Supported)

			assert.Equal(t, testCase.settings, settings)
		})
	}
}

func Test_resolveWireguardEndpointWithLookup(t *testing.T) {
	t.Parallel()

	const hostname = "vpn.example.com"

	testCases := map[string]struct {
		connection    models.Connection
		ipv6Supported bool
		lookup        lookupIPAddrFunc
		expected      models.Connection
		errMessage    string
	}{
		"ip_only_regression": {
			connection: models.Connection{
				IP:   netip.MustParseAddr("1.2.3.4"),
				Port: 51820,
			},
			lookup: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return nil, errors.New("lookup should not be called")
			},
			expected: models.Connection{
				IP:   netip.MustParseAddr("1.2.3.4"),
				Port: 51820,
			},
		},
		"hostname_resolves_ipv4": {
			connection: models.Connection{
				Hostname: hostname,
				Port:     51820,
			},
			lookup: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
			},
			expected: models.Connection{
				Hostname: hostname,
				IP:       netip.MustParseAddr("1.2.3.4"),
				Port:     51820,
			},
		},
		"hostname_prefers_ipv6_when_supported": {
			connection: models.Connection{
				Hostname: hostname,
				Port:     51820,
			},
			ipv6Supported: true,
			lookup: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return []netip.Addr{
					netip.MustParseAddr("1.2.3.4"),
					netip.MustParseAddr("2001:db8::1"),
				}, nil
			},
			expected: models.Connection{
				Hostname: hostname,
				IP:       netip.MustParseAddr("2001:db8::1"),
				Port:     51820,
			},
		},
		"hostname_keeps_connection_fields": {
			connection: models.Connection{
				Type:        "wireguard",
				Hostname:    hostname,
				Port:        51820,
				PubKey:      "pubkey",
				ServerName:  "server",
				PortForward: true,
			},
			lookup: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, nil
			},
			expected: models.Connection{
				Type:        "wireguard",
				Hostname:    hostname,
				IP:          netip.MustParseAddr("1.2.3.4"),
				Port:        51820,
				PubKey:      "pubkey",
				ServerName:  "server",
				PortForward: true,
			},
		},
		"hostname_resolution_without_ips_is_fail_closed": {
			connection: models.Connection{
				Hostname: hostname,
				Port:     51820,
			},
			lookup: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return nil, nil
			},
			errMessage: `resolving hostname "vpn.example.com": no IPv4 address found (fail-closed)`,
		},
		"hostname_resolution_failure_is_fail_closed": {
			connection: models.Connection{
				Hostname: hostname,
				Port:     51820,
			},
			lookup: func(_ context.Context, _ string) ([]netip.Addr, error) {
				return nil, errors.New("lookup failed")
			},
			errMessage: `resolving hostname "vpn.example.com": lookup failed (fail-closed)`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			connection, err := resolveWireguardEndpointWithLookup(context.Background(),
				testCase.connection, testCase.ipv6Supported, noopWireguardLogger{}, testCase.lookup)

			assert.Equal(t, testCase.expected, connection)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_pickWireguardEndpointIP(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		ips           []netip.Addr
		ipv6Supported bool
		expectedIP    netip.Addr
		errMessage    string
	}{
		"prefer_ipv6_when_supported": {
			ips: []netip.Addr{
				netip.MustParseAddr("1.2.3.4"),
				netip.MustParseAddr("2001:db8::1"),
			},
			ipv6Supported: true,
			expectedIP:    netip.MustParseAddr("2001:db8::1"),
		},
		"fallback_to_ipv4_when_ipv6_not_supported": {
			ips: []netip.Addr{
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("1.2.3.4"),
			},
			expectedIP: netip.MustParseAddr("1.2.3.4"),
		},
		"error_without_ipv4_when_ipv6_not_supported": {
			ips: []netip.Addr{
				netip.MustParseAddr("2001:db8::1"),
			},
			errMessage: "no IPv4 address found",
		},
		"error_without_any_ip_when_ipv6_supported": {
			ipv6Supported: true,
			errMessage:    "no suitable IP address found",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ip, err := pickWireguardEndpointIP(testCase.ips, testCase.ipv6Supported)

			assert.Equal(t, testCase.expectedIP, ip)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_lookupIPAddrs(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := lookupIPAddrs(ctx, "localhost")
	require.NoError(t, err)
	require.NotEmpty(t, ips)

	foundLoopback := false
	for _, ip := range ips {
		if ip.IsLoopback() {
			foundLoopback = true
			break
		}
	}
	assert.True(t, foundLoopback)
}

type fakeIPAddrResolver struct {
	ips []net.IPAddr
	err error
}

func (r fakeIPAddrResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.ips, nil
}

func Test_lookupIPAddrsWithResolvers(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		resolvers  []namedIPAddrResolver
		expected   []netip.Addr
		errMessage string
	}{
		"first_resolver_success": {
			resolvers: []namedIPAddrResolver{
				{
					name: "system DNS",
					resolver: fakeIPAddrResolver{
						ips: []net.IPAddr{{IP: net.ParseIP("1.2.3.4")}},
					},
				},
				{
					name: "public DoH fallback",
					resolver: fakeIPAddrResolver{
						err: errors.New("should not be called"),
					},
				},
			},
			expected: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		"fallback_resolver_success": {
			resolvers: []namedIPAddrResolver{
				{
					name: "system DNS",
					resolver: fakeIPAddrResolver{
						err: errors.New("lookup failed"),
					},
				},
				{
					name: "public DoH fallback",
					resolver: fakeIPAddrResolver{
						ips: []net.IPAddr{
							{IP: net.ParseIP("1.2.3.4")},
							{IP: net.ParseIP("2001:db8::1")},
						},
					},
				},
			},
			expected: []netip.Addr{
				netip.MustParseAddr("1.2.3.4"),
				netip.MustParseAddr("2001:db8::1"),
			},
		},
		"all_resolvers_fail": {
			resolvers: []namedIPAddrResolver{
				{
					name: "system DNS",
					resolver: fakeIPAddrResolver{
						err: errors.New("lookup failed"),
					},
				},
				{
					name:     "public DoH fallback",
					resolver: fakeIPAddrResolver{},
				},
				{
					name: "public DoT fallback",
					resolver: fakeIPAddrResolver{
						err: errors.New("timeout"),
					},
				},
			},
			errMessage: "system DNS: lookup failed\npublic DoH fallback: no IP addresses found\npublic DoT fallback: timeout",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ips, err := lookupIPAddrsWithResolvers(context.Background(), "vpn.example.com", testCase.resolvers...)

			assert.Equal(t, testCase.expected, ips)
			if testCase.errMessage != "" {
				require.Error(t, err)
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
