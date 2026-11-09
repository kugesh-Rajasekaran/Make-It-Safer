package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
)

// Nothing to list must be [] in JSON, never null.
func TestEmptyListsAreJSONArrays(t *testing.T) {
	paths := newConfigHome(t)
	withServers(t, paths, false)

	t.Run("status", func(t *testing.T) {
		code, out, _ := runCLI(t, "status", "--json")
		var view struct {
			Servers json.RawMessage `json:"servers"`
		}
		if e := decode(t, out); code != 0 || json.Unmarshal(e.Data, &view) != nil || string(view.Servers) != "[]" {
			t.Fatalf("exit %d, servers %s: %s", code, view.Servers, out)
		}
	})

	t.Run("findings", func(t *testing.T) {
		code, out, _ := runCLI(t, "findings", "--json")
		if e := decode(t, out); code != 0 || string(e.Data) != "[]" {
			t.Fatalf("exit %d, data %s: %s", code, e.Data, out)
		}
	})

	t.Run("init servers", func(t *testing.T) {
		var out bytes.Buffer
		a := newApp(nil, nil, &out, &out)
		a.in = bufio.NewReader(strings.NewReader("n\nn\n")) // not this computer, no server
		cfg := config.Default()
		w := &wizard{a: a, paths: paths, cfg: &cfg}
		added, err := w.servers()
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(initResult{Servers: added})
		if err != nil || !strings.Contains(string(data), `"servers":[]`) {
			t.Fatalf("err %v, json %s", err, data)
		}
	})
}
