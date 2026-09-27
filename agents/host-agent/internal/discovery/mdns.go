package discovery

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

const ServiceName = "_lanmodelmanager._tcp.local"
const MaxTTLSeconds uint32 = 3600

var ErrInvalidAdvertisement = errors.New("invalid discovery advertisement")
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type ProtocolVersion struct {
	Major uint16
	Minor uint16
}
type Advertisement struct {
	ID              string
	DisplayName     string
	ProtocolVersion ProtocolVersion
	AgentPort       uint16
	Platform        string
	Addresses       []string
	TTLSeconds      uint32
}
type Sender interface {
	Send([]byte) error
	Close() error
}

func validName(value string) bool {
	if value == "" || len([]byte(value)) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func canonicalIP(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil || strings.Contains(value, "%") {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return value == v4.String()
	}
	return value == ip.String()
}
func validate(a Advertisement) error {
	if !idPattern.MatchString(a.ID) || !validName(a.DisplayName) || a.ProtocolVersion.Major != 1 || a.AgentPort == 0 || (a.Platform != "linux" && a.Platform != "darwin" && a.Platform != "windows") || a.TTLSeconds < 1 || a.TTLSeconds > MaxTTLSeconds || len(a.Addresses) > 16 {
		return ErrInvalidAdvertisement
	}
	seen := map[string]bool{}
	for _, address := range a.Addresses {
		if !canonicalIP(address) || seen[address] {
			return ErrInvalidAdvertisement
		}
		seen[address] = true
	}
	return nil
}
func name(out *bytes.Buffer, value string) error {
	labels := strings.Split(value, ".")
	if len(value) > 253 {
		return ErrInvalidAdvertisement
	}
	for _, label := range labels {
		raw := []byte(label)
		if len(raw) < 1 || len(raw) > 63 {
			return ErrInvalidAdvertisement
		}
		out.WriteByte(byte(len(raw)))
		out.Write(raw)
	}
	out.WriteByte(0)
	return nil
}
func u16(out *bytes.Buffer, value uint16) { _ = binary.Write(out, binary.BigEndian, value) }
func u32(out *bytes.Buffer, value uint32) { _ = binary.Write(out, binary.BigEndian, value) }
func rr(out *bytes.Buffer, owner string, kind uint16, ttl uint32, data []byte) error {
	if err := name(out, owner); err != nil {
		return err
	}
	u16(out, kind)
	u16(out, 1)
	u32(out, ttl)
	u16(out, uint16(len(data)))
	out.Write(data)
	return nil
}
func nameData(value string) ([]byte, error) {
	var out bytes.Buffer
	if err := name(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func txtData(values [][2]string) ([]byte, error) {
	var out bytes.Buffer
	for _, pair := range values {
		raw := []byte(pair[0] + "=" + pair[1])
		if len(raw) < 3 || len(raw) > 255 {
			return nil, ErrInvalidAdvertisement
		}
		out.WriteByte(byte(len(raw)))
		out.Write(raw)
	}
	return out.Bytes(), nil
}
func BuildAdvertisement(a Advertisement) ([]byte, error) {
	if err := validate(a); err != nil {
		return nil, err
	}
	instance := a.ID + "." + ServiceName
	host := a.ID + ".local"
	var records []struct {
		name string
		kind uint16
		data []byte
	}
	ptr, _ := nameData(instance)
	records = append(records, struct {
		name string
		kind uint16
		data []byte
	}{ServiceName, 12, ptr})
	target, _ := nameData(host)
	srv := append([]byte{0, 0, 0, 0, byte(a.AgentPort >> 8), byte(a.AgentPort)}, target...)
	records = append(records, struct {
		name string
		kind uint16
		data []byte
	}{instance, 33, srv})
	proto := strings.Join([]string{uintString(a.ProtocolVersion.Major), uintString(a.ProtocolVersion.Minor)}, ".")
	txt, _ := txtData([][2]string{{"id", a.ID}, {"name", a.DisplayName}, {"platform", a.Platform}, {"proto", proto}})
	records = append(records, struct {
		name string
		kind uint16
		data []byte
	}{instance, 16, txt})
	for _, address := range a.Addresses {
		ip := net.ParseIP(address)
		if v4 := ip.To4(); v4 != nil {
			records = append(records, struct {
				name string
				kind uint16
				data []byte
			}{host, 1, []byte(v4)})
		} else {
			records = append(records, struct {
				name string
				kind uint16
				data []byte
			}{host, 28, []byte(ip.To16())})
		}
	}
	var out bytes.Buffer
	u16(&out, 0)
	u16(&out, 0x8400)
	u16(&out, 0)
	u16(&out, uint16(len(records)))
	u16(&out, 0)
	u16(&out, 0)
	for _, record := range records {
		if err := rr(&out, record.name, record.kind, a.TTLSeconds, record.data); err != nil {
			return nil, err
		}
	}
	if out.Len() > 65535 {
		return nil, ErrInvalidAdvertisement
	}
	return out.Bytes(), nil
}
func uintString(value uint16) string {
	if value == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for value > 0 {
		i--
		b[i] = byte('0' + value%10)
		value /= 10
	}
	return string(b[i:])
}

type Advertiser struct {
	mu            sync.Mutex
	sender        Sender
	advertisement Advertisement
	started       bool
}

func NewAdvertiser(sender Sender, advertisement Advertisement) (*Advertiser, error) {
	if sender == nil || validate(advertisement) != nil {
		return nil, ErrInvalidAdvertisement
	}
	return &Advertiser{sender: sender, advertisement: advertisement}, nil
}
func (a *Advertiser) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.started {
		return nil
	}
	packet, err := BuildAdvertisement(a.advertisement)
	if err != nil {
		return err
	}
	if err = a.sender.Send(packet); err != nil {
		return errors.New("discovery send failed")
	}
	a.started = true
	return nil
}
func (a *Advertiser) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.started {
		return nil
	}
	a.started = false
	if err := a.sender.Close(); err != nil {
		return errors.New("discovery close failed")
	}
	return nil
}
