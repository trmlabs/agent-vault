package brokercore

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var errProxyHeader = errors.New("invalid PROXY header")

// ReadProxyV1 reads one PROXY protocol v1 header from a connection made by a
// trusted loopback TLS terminator (stunnel's protocol = proxy) and returns the
// original client address. The caller must require a loopback remote address
// before trusting it. It reads byte by byte so no client protocol bytes are
// consumed past the header.
func ReadProxyV1(r io.Reader, remote net.Addr) (netip.Addr, error) {
	tcp, ok := remote.(*net.TCPAddr)
	if !ok || !tcp.IP.IsLoopback() {
		return netip.Addr{}, errProxyHeader
	}
	var line []byte
	one := make([]byte, 1)
	for len(line) < 107 {
		if _, err := io.ReadFull(r, one); err != nil {
			return netip.Addr{}, errProxyHeader
		}
		line = append(line, one[0])
		// Fail fast on anything that is not a PROXY header, such as a client
		// protocol message sent straight to the listener.
		if n := len(line); n <= 6 && line[n-1] != "PROXY "[n-1] {
			return netip.Addr{}, errProxyHeader
		}
		if len(line) >= 2 && line[len(line)-2] == '\r' && line[len(line)-1] == '\n' {
			return parseProxyV1(string(line[:len(line)-2]))
		}
	}
	return netip.Addr{}, errProxyHeader
}

func parseProxyV1(line string) (netip.Addr, error) {
	fields := strings.Split(line, " ")
	if len(fields) != 6 || fields[0] != "PROXY" || (fields[1] != "TCP4" && fields[1] != "TCP6") {
		return netip.Addr{}, errProxyHeader
	}
	source, err := netip.ParseAddr(fields[2])
	if err != nil || source.Zone() != "" || (fields[1] == "TCP4") != source.Is4() {
		return netip.Addr{}, errProxyHeader
	}
	if _, err := netip.ParseAddr(fields[3]); err != nil {
		return netip.Addr{}, errProxyHeader
	}
	for _, port := range fields[4:] {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return netip.Addr{}, errProxyHeader
		}
	}
	return source, nil
}
