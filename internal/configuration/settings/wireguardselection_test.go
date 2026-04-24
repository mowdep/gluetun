package settings

import (
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gosettings/reader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_WireguardSelection_validate(t *testing.T) {
	t.Parallel()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	testCases := map[string]struct {
		selection  WireguardSelection
		errWrapped error
		errMessage string
	}{
		"valid_custom_ipv4": {
			selection: WireguardSelection{
				EndpointIP:   netip.MustParseAddr("1.2.3.4"),
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    key.PublicKey().String(),
			},
		},
		"valid_custom_hostname": {
			selection: WireguardSelection{
				EndpointHost: "vpn.example.com",
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    key.PublicKey().String(),
			},
		},
		"valid_custom_ipv6": {
			selection: WireguardSelection{
				EndpointIP:   netip.MustParseAddr("2001:db8::1"),
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    key.PublicKey().String(),
			},
		},
		"invalid_missing_port": {
			selection: WireguardSelection{
				EndpointHost: "vpn.example.com",
				EndpointPort: ptrTo(uint16(0)),
				PublicKey:    key.PublicKey().String(),
			},
			errWrapped: ErrWireguardEndpointPortNotSet,
			errMessage: ErrWireguardEndpointPortNotSet.Error(),
		},
		"invalid_hostname": {
			selection: WireguardSelection{
				EndpointHost: "bad host",
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    key.PublicKey().String(),
			},
			errWrapped: ErrWireguardEndpointHostNotValid,
			errMessage: `endpoint host is not valid: "bad host" must be a valid hostname or FQDN`,
		},
		"host_priority_is_fail_closed": {
			selection: WireguardSelection{
				EndpointHost: "bad host",
				EndpointIP:   netip.MustParseAddr("1.2.3.4"),
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    key.PublicKey().String(),
			},
			errWrapped: ErrWireguardEndpointHostNotValid,
			errMessage: `endpoint host is not valid: "bad host" must be a valid hostname or FQDN`,
		},
		"missing_host_and_ip": {
			selection: WireguardSelection{
				EndpointPort: ptrTo(uint16(51820)),
				PublicKey:    key.PublicKey().String(),
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
		"invalid_endpoint_port": {
			keyValues: []sourceKeyValue{
				{key: "VPN_ENDPOINT_IP"},
				{key: "WIREGUARD_ENDPOINT_IP"},
				{key: "VPN_ENDPOINT_HOST"},
				{key: "WIREGUARD_ENDPOINT_HOST"},
				{key: "VPN_ENDPOINT_PORT"},
				{key: "WIREGUARD_ENDPOINT_PORT", value: "70000"},
			},
			errMessage: "mock source WIREGUARD_ENDPOINT_PORT: value is not in range: 70000 is not between 0 and 65535",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			source := newMockSource(ctrl, testCase.keyValues)
			r := reader.New(reader.Settings{
				Sources: []reader.Source{source},
			})

			var selection WireguardSelection
			err := selection.read(r, false)

			assert.Equal(t, testCase.selection, selection)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
