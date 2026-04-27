package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gosettings/reader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func generateTestPublicKey(t *testing.T) string {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	return key.PublicKey().String()
}

func Test_WireguardSelection_validate(t *testing.T) {
	t.Parallel()

	publicKey := generateTestPublicKey(t)

	testCases := map[string]struct {
		selection  WireguardSelection
		errWrapped error
		errMessage string
	}{
		"valid_custom_ipv4": {
			selection: WireguardSelection{
				EndpointIP:   netip.MustParseAddr("1.2.3.4"),
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    publicKey,
			},
		},
		"valid_custom_hostname": {
			selection: WireguardSelection{
				EndpointHost: "vpn.example.com",
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    publicKey,
			},
		},
		"valid_custom_fqdn_with_trailing_dot": {
			selection: WireguardSelection{
				EndpointHost: "vpn.example.com.",
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    publicKey,
			},
		},
		"valid_custom_ipv6": {
			selection: WireguardSelection{
				EndpointIP:   netip.MustParseAddr("2001:db8::1"),
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    publicKey,
			},
		},
		"invalid_missing_port": {
			selection: WireguardSelection{
				EndpointHost: "vpn.example.com",
				EndpointPort: ptrTo(uint16(0)),
				PublicKey:    publicKey,
			},
			errWrapped: ErrWireguardEndpointPortNotSet,
			errMessage: ErrWireguardEndpointPortNotSet.Error(),
		},
		"invalid_hostname": {
			selection: WireguardSelection{
				EndpointHost: "bad host",
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    publicKey,
			},
			errWrapped: ErrWireguardEndpointHostNotValid,
			errMessage: `endpoint host is not valid: "bad host" must be a valid hostname or FQDN`,
		},
		"invalid_ipv4_given_as_host": {
			selection: WireguardSelection{
				EndpointHost: "1.2.3.4",
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    publicKey,
			},
			errWrapped: ErrWireguardEndpointHostNotValid,
			errMessage: `endpoint host is not valid: "1.2.3.4" must be a hostname or FQDN and not an IP address`,
		},
		"invalid_ipv6_given_as_host": {
			selection: WireguardSelection{
				EndpointHost: "2001:db8::1",
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    publicKey,
			},
			errWrapped: ErrWireguardEndpointHostNotValid,
			errMessage: `endpoint host is not valid: "2001:db8::1" must be a hostname or FQDN and not an IP address`,
		},
		"host_priority_is_fail_closed": {
			selection: WireguardSelection{
				EndpointHost: "bad host",
				EndpointIP:   netip.MustParseAddr("1.2.3.4"),
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    publicKey,
			},
			errWrapped: ErrWireguardEndpointHostNotValid,
			errMessage: `endpoint host is not valid: "bad host" must be a valid hostname or FQDN`,
		},
		"missing_host_and_ip": {
			selection: WireguardSelection{
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    publicKey,
			},
			errWrapped: ErrWireguardEndpointHostOrIPNotSet,
			errMessage: ErrWireguardEndpointHostOrIPNotSet.Error(),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.selection.validate(providers.Custom)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_WireguardSelection_read(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		keyValues  []sourceKeyValue
		selection  WireguardSelection
		errMessage string
	}{
		"reads_endpoint_host": {
			keyValues: []sourceKeyValue{
				{key: "VPN_ENDPOINT_IP"},
				{key: "WIREGUARD_ENDPOINT_IP"},
				{key: "VPN_ENDPOINT_HOST"},
				{key: "WIREGUARD_ENDPOINT_HOST", value: "vpn.example.com"},
				{key: "VPN_ENDPOINT_PORT"},
				{key: "WIREGUARD_ENDPOINT_PORT", value: "51820"},
				{key: "WIREGUARD_PUBLIC_KEY"},
			},
			selection: WireguardSelection{
				EndpointHost: "vpn.example.com",
				EndpointPort: ptrTo(uint16(51820)),
			},
		},
		"reads_retro_endpoint_host": {
			keyValues: []sourceKeyValue{
				{key: "VPN_ENDPOINT_IP"},
				{key: "WIREGUARD_ENDPOINT_IP"},
				{key: "VPN_ENDPOINT_HOST", value: "retro.example.com"},
				{key: "VPN_ENDPOINT_PORT"},
				{key: "WIREGUARD_ENDPOINT_PORT", value: "51820"},
				{key: "WIREGUARD_PUBLIC_KEY"},
			},
			selection: WireguardSelection{
				EndpointHost: "retro.example.com",
				EndpointPort: ptrTo(uint16(51820)),
			},
		},
		"reads_amneziawg_endpoint_host": {
			keyValues: []sourceKeyValue{
				{key: "VPN_ENDPOINT_IP"},
				{key: "AMNEZIAWG_ENDPOINT_IP"},
				{key: "VPN_ENDPOINT_HOST"},
				{key: "AMNEZIAWG_ENDPOINT_HOST", value: "amnezia.example.com"},
				{key: "VPN_ENDPOINT_PORT"},
				{key: "AMNEZIAWG_ENDPOINT_PORT", value: "51821"},
				{key: "AMNEZIAWG_PUBLIC_KEY"},
			},
			selection: WireguardSelection{
				EndpointHost: "amnezia.example.com",
				EndpointPort: ptrTo(uint16(51821)),
			},
		},
		"invalid_endpoint_port": {
			keyValues: []sourceKeyValue{
				{key: "VPN_ENDPOINT_IP"},
				{key: "WIREGUARD_ENDPOINT_IP"},
				{key: "VPN_ENDPOINT_HOST"},
				{key: "WIREGUARD_ENDPOINT_HOST"},
				{key: "VPN_ENDPOINT_PORT"},
				{key: "WIREGUARD_ENDPOINT_PORT", value: "70000"},
			},
			errMessage: "map source WIREGUARD_ENDPOINT_PORT: value is not in range: 70000 is not between 0 and 65535",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			source := newMapSource(testCase.keyValues)
			r := reader.New(reader.Settings{
				Sources: []reader.Source{source},
			})

			var selection WireguardSelection
			err := selection.read(r, name == "reads_amneziawg_endpoint_host")

			assert.Equal(t, testCase.selection, selection)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_WireguardSelection_toLinesNode(t *testing.T) {
	t.Parallel()

	selection := WireguardSelection{
		EndpointHost: "vpn.example.com",
		EndpointIP:   netip.MustParseAddr("1.2.3.4"),
		EndpointPort: ptrTo(uint16(51820)),
		PublicKey:    "public",
	}

	assert.Equal(t, `Wireguard selection settings:
├── Endpoint host: vpn.example.com
├── Endpoint IP address: 1.2.3.4
├── Endpoint port: 51820
└── Server public key: public`, selection.String())
}

type testMapSource struct {
	values map[string]string
}

func newMapSource(keyValues []sourceKeyValue) *testMapSource {
	values := make(map[string]string, len(keyValues))
	for _, keyValue := range keyValues {
		values[keyValue.key] = keyValue.value
	}
	return &testMapSource{values: values}
}

func (s *testMapSource) Get(key string) (value string, isSet bool) {
	value, isSet = s.values[key]
	return value, isSet
}

// KeyTransform preserves the key unchanged so tests can define exact reader keys.
func (s *testMapSource) KeyTransform(key string) string { return key }

func (s *testMapSource) String() string { return "map source" }
