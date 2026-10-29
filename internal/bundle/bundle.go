// Package bundle turns what one host hands another into a block of text
// that survives copy and paste: a BEGIN/END armour around base64 of
// gzipped JSON.
//
// A Bundle goes from the CA host to a new host: the CA cert, the host's
// cert, its key when the CA host made it, and the lighthouses. A Request
// goes the other way when the new host keeps its own key: its name and
// public key, for the CA host to sign.
package bundle

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/davewat/nebctl/internal/netconf"
)

const (
	KindBundle  = "NEBCTL BUNDLE"
	KindRequest = "NEBCTL REQUEST"
	version     = 1
)

func Begin(kind string) string { return "-----BEGIN " + kind + "-----" }
func End(kind string) string   { return "-----END " + kind + "-----" }

type Bundle struct {
	V           int                  `json:"v"`
	Name        string               `json:"name"`
	CACrt       string               `json:"ca_crt"`
	HostCrt     string               `json:"host_crt"`
	HostKey     string               `json:"host_key,omitempty"`
	Lighthouses []netconf.Lighthouse `json:"lighthouses,omitempty"`
	Domain      string               `json:"domain,omitempty"` // the network's Nebula-only DNS domain
}

type Request struct {
	V         int    `json:"v"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"` // PEM from nebula-cert keygen
	NebulaIP  string `json:"nebula_ip,omitempty"`
}

func EncodeBundle(b Bundle) (string, error) {
	b.V = version
	return encode(KindBundle, b)
}

func DecodeBundle(text string) (Bundle, error) {
	var b Bundle
	if err := decode(text, KindBundle, &b); err != nil {
		return b, err
	}
	if b.CACrt == "" || b.HostCrt == "" {
		return b, errors.New("bundle is missing its certificates")
	}
	return b, nil
}

func EncodeRequest(r Request) (string, error) {
	r.V = version
	return encode(KindRequest, r)
}

func DecodeRequest(text string) (Request, error) {
	var r Request
	if err := decode(text, KindRequest, &r); err != nil {
		return r, err
	}
	if r.Name == "" || r.PublicKey == "" {
		return r, errors.New("request is missing its name or public key")
	}
	return r, nil
}

func encode(kind string, v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	zw.Write(data)
	if err := zw.Close(); err != nil {
		return "", err
	}
	s := base64.StdEncoding.EncodeToString(gz.Bytes())
	var b strings.Builder
	b.WriteString(Begin(kind) + "\n")
	for len(s) > 64 {
		b.WriteString(s[:64] + "\n")
		s = s[64:]
	}
	b.WriteString(s + "\n")
	b.WriteString(End(kind) + "\n")
	return b.String(), nil
}

func decode(text, kind string, v any) error {
	begin, end := Begin(kind), End(kind)
	i := strings.Index(text, begin)
	j := strings.Index(text, end)
	if i < 0 || j < i {
		return fmt.Errorf("no %s found: paste everything from %s to %s", strings.ToLower(kind), begin, end)
	}
	body := strings.Join(strings.Fields(text[i+len(begin):j]), "")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return fmt.Errorf("%s is damaged (some of it was not copied?): %w", strings.ToLower(kind), err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%s is damaged: %w", strings.ToLower(kind), err)
	}
	data, err := io.ReadAll(io.LimitReader(zr, 1<<20))
	if err != nil {
		return fmt.Errorf("%s is damaged: %w", strings.ToLower(kind), err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s is damaged: %w", strings.ToLower(kind), err)
	}
	return nil
}
