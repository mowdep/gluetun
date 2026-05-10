package custom

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func ptrTo[T any](value T) *T { return &value }

func Test_getWireguardConnection(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		selection  settings.ServerSelection
		connection models.Connection
	}{
		"ip_only_regression": {
			selection: settings.ServerSelection{
				Wireguard: settings.WireguardSelection{
					EndpointIP:   netip.MustParseAddr("1.2.3.4"),
					EndpointPort: ptrTo(uint16(51820)),
					PublicKey:    "public",
				},
			},
			connection: models.Connection{
				Type:        vpn.Wireguard,
				IP:          netip.MustParseAddr("1.2.3.4"),
				Port:        51820,
				Protocol:    constants.UDP,
				PubKey:      "public",
				PortForward: true,
			},
		},
		"hostname_endpoint": {
			selection: settings.ServerSelection{
				Wireguard: settings.WireguardSelection{
					EndpointHost: "vpn.example.com",
					EndpointIP:   netip.IPv4Unspecified(),
					EndpointPort: ptrTo(uint16(51820)),
					PublicKey:    "public",
				},
				Names: []string{"server-name"},
			},
			connection: models.Connection{
				Type:        vpn.Wireguard,
				Hostname:    "vpn.example.com",
				IP:          netip.IPv4Unspecified(),
				Port:        51820,
				Protocol:    constants.UDP,
				PubKey:      "public",
				ServerName:  "server-name",
				PortForward: true,
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			connection := getWireguardConnection(testCase.selection)

			assert.Equal(t, testCase.connection, connection)
		})
	}
}
