package admin

import (
	"encoding/json"
	"reflect"
	"testing"
)

// From `list-hostmap -json` on nebula 1.11.2: one direct tunnel and one
// relayed through the lighthouse (whose remote prints as the zero address).
const hostmap = `[
 {"vpnAddrs":["10.42.0.2"],"localIndex":11,"remoteIndex":22,"remoteAddrs":["198.51.100.7:4242"],
  "cert":{"details":{"name":"fe01.nebula.example.com","networks":["10.42.0.2/22"],"groups":["web"],
  "notAfter":"2027-10-29T00:10:53-04:00","isCa":false},"fingerprint":"abc","version":2},
  "messageCounter":42,"currentRemote":"198.51.100.7:4242","currentRelaysToMe":[],"currentRelaysThroughMe":["10.42.0.3"]},
 {"vpnAddrs":["10.42.0.9"],"localIndex":1,"remoteIndex":2,"remoteAddrs":null,
  "cert":{"details":{"name":"laptop","groups":null,"notAfter":"2027-01-01T00:00:00Z"},"fingerprint":"def"},
  "messageCounter":3,"currentRemote":"invalid AddrPort","currentRelaysToMe":["10.42.0.1"],"currentRelaysThroughMe":null}
]`

func TestPeers(t *testing.T) {
	var hs []hostInfo
	if err := json.Unmarshal([]byte(hostmap), &hs); err != nil {
		t.Fatal(err)
	}
	direct, relayed := hs[0].peer(false), hs[1].peer(true)
	if direct.VpnAddr != "10.42.0.2" || direct.Name != "fe01.nebula.example.com" || direct.CurrentRemote != "198.51.100.7:4242" ||
		direct.MessageCounter != 42 || !reflect.DeepEqual(direct.Groups, []string{"web"}) ||
		!reflect.DeepEqual(direct.RelaysFor, []string{"10.42.0.3"}) || direct.Fingerprint != "abc" || direct.NotAfter.Year() != 2027 {
		t.Errorf("direct: %+v", direct)
	}
	if relayed.CurrentRemote != "" || !reflect.DeepEqual(relayed.RelayedThrough, []string{"10.42.0.1"}) ||
		relayed.RemoteAddrs == nil || relayed.Groups == nil || relayed.RelaysFor == nil || !relayed.Pending {
		t.Errorf("relayed: %+v", relayed)
	}
}

func TestFlatten(t *testing.T) {
	var raw []struct {
		VpnAddr string            `json:"vpnAddr"`
		Addrs   map[string]*cache `json:"addrs"`
	}
	json.Unmarshal([]byte(`[{"vpnAddr":"10.42.0.2","addrs":{"10.42.0.2":{"learned":["127.0.0.1:1"],"reported":["10.0.0.5:1"],"relay":["10.42.0.1"]}}}]`), &raw)
	e := flatten(raw[0].VpnAddr, raw[0].Addrs)
	if !reflect.DeepEqual(e, AddrEntry{"10.42.0.2", []string{"127.0.0.1:1"}, []string{"10.0.0.5:1"}, []string{"10.42.0.1"}}) {
		t.Errorf("%+v", e)
	}
}
