package files

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

func ptrTo[T any](value T) *T { return &value }

func Test_Source_ParseWireguardConf(t *testing.T) {
	t.Parallel()

	t.Run("fail reading from file", func(t *testing.T) {
		t.Parallel()

		dirPath := t.TempDir()
		wireguard, err := ParseWireguardConf(dirPath)
		assert.Equal(t, WireguardConfig{}, wireguard)
		assert.Error(t, err)
		assert.Regexp(t, `loading ini from reader: BOM: read .+: is a directory`, err.Error())
	})

	t.Run("no file", func(t *testing.T) {
		t.Parallel()

		noFile := filepath.Join(t.TempDir(), "doesnotexist")
		wireguard, err := ParseWireguardConf(noFile)
		assert.Equal(t, WireguardConfig{}, wireguard)
		assert.NoError(t, err)
	})

	testCases := map[string]struct {
		fileContent string
		wireguard   WireguardConfig
		errMessage  string
	}{
		"ini load error": {
			fileContent: "invalid",
			errMessage:  "loading ini from reader: key-value delimiter not found: invalid",
		},
		"empty file": {},
		"interface_section_missing": {
			fileContent: `
[Peer]
PresharedKey = YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g=
`,
			wireguard: WireguardConfig{
				PreSharedKey: ptrTo("YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g="),
			},
		},
		"success": {
			fileContent: `
[Interface]
PrivateKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=
Address = 10.38.22.35/32
DNS = 193.138.218.74

[Peer]
PresharedKey = YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g=
`,
			wireguard: WireguardConfig{
				PrivateKey:   ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
				PreSharedKey: ptrTo("YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g="),
				Addresses:    ptrTo("10.38.22.35/32"),
			},
		},
		"success_with_hostname_endpoint": {
			fileContent: `
[Interface]
PrivateKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=
Address = 10.38.22.35/32

[Peer]
PublicKey = YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g=
Endpoint = vpn.example.com:51820
`,
			wireguard: WireguardConfig{
				PrivateKey:   ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
				Addresses:    ptrTo("10.38.22.35/32"),
				PublicKey:    ptrTo("YJ680VN+dGrdsWNjSFqZ6vvwuiNhbq502ZL3G7Q3o3g="),
				EndpointHost: ptrTo("vpn.example.com"),
				EndpointPort: ptrTo("51820"),
			},
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			configFile := filepath.Join(t.TempDir(), "wg.conf")
			const permission = fs.FileMode(0o600)
			err := os.WriteFile(configFile, []byte(testCase.fileContent), permission)
			require.NoError(t, err)

			wireguard, err := ParseWireguardConf(configFile)

			assert.Equal(t, testCase.wireguard, wireguard)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_parseWireguardInterfaceSection(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		iniData    string
		privateKey *string
		addresses  *string
	}{
		"no_fields": {
			iniData: `[Interface]`,
		},
		"only_private_key": {
			iniData: `[Interface]
PrivateKey = x
`,
			privateKey: ptrTo("x"),
		},
		"all_fields": {
			iniData: `
[Interface]
PrivateKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=
Address = 10.38.22.35/32
`,
			privateKey: ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
			addresses:  ptrTo("10.38.22.35/32"),
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			iniFile, err := ini.Load([]byte(testCase.iniData))
			require.NoError(t, err)
			iniSection, err := iniFile.GetSection("Interface")
			require.NoError(t, err)

			privateKey, addresses := parseWireguardInterfaceSection(iniSection)

			assert.Equal(t, testCase.privateKey, privateKey)
			assert.Equal(t, testCase.addresses, addresses)
		})
	}
}

func Test_parseWireguardPeerSection(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		iniData      string
		preSharedKey *string
		publicKey    *string
		endpointHost *string
		endpointIP   *string
		endpointPort *string
		errMessage   string
	}{
		"public key set": {
			iniData: `[Peer]
PublicKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=`,
			publicKey: ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
		},
		"endpoint_only_host": {
			iniData: `[Peer]
Endpoint = x`,
			endpointHost: ptrTo("x"),
		},
		"endpoint_no_port": {
			iniData: `[Peer]
Endpoint = x:`,
			endpointHost: ptrTo("x"),
			endpointPort: ptrTo(""),
		},
		"valid_endpoint": {
			iniData: `[Peer]
Endpoint = 1.2.3.4:51820`,
			endpointIP:   ptrTo("1.2.3.4"),
			endpointPort: ptrTo("51820"),
		},
		"hostname_endpoint": {
			iniData: `[Peer]
Endpoint = vpn.example.com:51820`,
			endpointHost: ptrTo("vpn.example.com"),
			endpointPort: ptrTo("51820"),
		},
		"all_set": {
			iniData: `[Peer]
PublicKey = QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8=
Endpoint = 1.2.3.4:51820`,
			publicKey:    ptrTo("QOlCgyA/Sn/c/+YNTIEohrjm8IZV+OZ2AUFIoX20sk8="),
			endpointIP:   ptrTo("1.2.3.4"),
			endpointPort: ptrTo("51820"),
		},
		"ipv6_endpoint": {
			iniData: `[Peer]
Endpoint = [2a02:bbbb:aaaa:8075::10]:51820`,
			endpointIP:   ptrTo("2a02:bbbb:aaaa:8075::10"),
			endpointPort: ptrTo("51820"),
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			iniFile, err := ini.Load([]byte(testCase.iniData))
			require.NoError(t, err)
			iniSection, err := iniFile.GetSection("Peer")
			require.NoError(t, err)

			preSharedKey, publicKey, endpointHost, endpointIP,
				endpointPort := parseWireguardPeerSection(iniSection)

			assert.Equal(t, testCase.preSharedKey, preSharedKey)
			assert.Equal(t, testCase.publicKey, publicKey)
			assert.Equal(t, testCase.endpointHost, endpointHost)
			assert.Equal(t, testCase.endpointIP, endpointIP)
			assert.Equal(t, testCase.endpointPort, endpointPort)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_splitWireguardEndpoint(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		endpoint string
		host     string
		port     string
		portSet  bool
	}{
		"hostname_and_port": {
			endpoint: "vpn.example.com:51820",
			host:     "vpn.example.com",
			port:     "51820",
			portSet:  true,
		},
		"hostname_without_port": {
			endpoint: "vpn.example.com",
			host:     "vpn.example.com",
		},
		"hostname_with_empty_port": {
			endpoint: "vpn.example.com:",
			host:     "vpn.example.com",
			portSet:  true,
		},
		"ipv4_and_port": {
			endpoint: "1.2.3.4:51820",
			host:     "1.2.3.4",
			port:     "51820",
			portSet:  true,
		},
		"ipv6_bracketed_and_port": {
			endpoint: "[2001:db8::1]:51820",
			host:     "2001:db8::1",
			port:     "51820",
			portSet:  true,
		},
		"ipv6_bracketed_without_port": {
			endpoint: "[2001:db8::1]",
			host:     "2001:db8::1",
		},
		"ipv6_without_port": {
			endpoint: "2001:db8::1",
			host:     "2001:db8::1",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			host, port, portSet := splitWireguardEndpoint(testCase.endpoint)

			assert.Equal(t, testCase.host, host)
			assert.Equal(t, testCase.port, port)
			assert.Equal(t, testCase.portSet, portSet)
		})
	}
}
