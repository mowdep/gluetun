package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
)

type noopLogger struct{}

func (noopLogger) Debug(string)                  {}
func (noopLogger) Debugf(string, ...interface{}) {}
func (noopLogger) Info(string)                   {}
func (noopLogger) Error(string)                  {}
func (noopLogger) Errorf(string, ...any)         {}

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
				testCase.connection, testCase.ipv6Supported, noopLogger{}, testCase.lookup)

			assert.Equal(t, testCase.expected, connection)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
