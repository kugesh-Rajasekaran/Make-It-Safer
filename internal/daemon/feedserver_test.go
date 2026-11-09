package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kugesh-rajasekaran/make-it-safer/internal/config"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/engine"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/feeds"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/inventory"
	"github.com/kugesh-rajasekaran/make-it-safer/internal/notify"
)

// feedServer stands in for the data sources: OSV knows the given openssh
// vulnerabilities, the ETag of the data files is fixed, and everything else
// (CISA's catalog, EPSS, end-of-life dates, the CVE List) is "not found".
type feedServer struct {
	*httptest.Server
	mu   sync.Mutex
	cves []string // CVE ids that affect openssh 1:9.6p1-3ubuntu13.5
}

// set changes which CVEs affect openssh.
func (f *feedServer) set(cves ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cves = cves
}

func newFeedServer(t *testing.T, cves ...string) *feedServer {
	t.Helper()
	f := &feedServer{cves: cves}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct{ Package struct{ Name string } }
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		results := make([]map[string]any, len(req.Queries))
		for i, q := range req.Queries {
			results[i] = map[string]any{}
			if q.Package.Name != "openssh" {
				continue
			}
			var vulns []map[string]string
			f.mu.Lock()
			for _, cve := range f.cves {
				vulns = append(vulns, map[string]string{"id": "UBUNTU-" + cve, "modified": "2026-11-01T00:00:00Z"})
			}
			f.mu.Unlock()
			results[i]["vulns"] = vulns
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		_, _ = fmt.Fprintf(w, `{"id":%q,"modified":"2026-11-01T00:00:00Z","upstream":[%q],"summary":"a bug in openssh",
			"severity":[{"type":"Ubuntu","score":"high"}],
			"affected":[{"package":{"name":"openssh","ecosystem":"Ubuntu:24.04:LTS"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:9.6p1-3ubuntu13.8"}]}],
			"ecosystem_specific":{"availability":"No subscription required"}}]}`, id, id[len("UBUNTU-"):])
	})
	mux.HandleFunc("HEAD /{dist}/modified_id.csv", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"v1"`)
	})
	f.Server = httptest.NewServer(mux) // other paths: 404
	t.Cleanup(f.Close)
	return f
}

// engine returns the engine builder for a daemon whose every data source is f.
func (f *feedServer) engine(paths config.Paths, log *slog.Logger) func(*config.Config) *engine.Engine {
	fc := feeds.NewForTest(f.URL)
	return func(cfg *config.Config) *engine.Engine {
		e := engine.New(paths, cfg, "test", log)
		e.OSV.Feeds, e.OSV.API = fc, f.URL
		e.KEV.Feeds, e.KEV.URLs = fc, []string{f.URL + "/kev.json"}
		e.EPSS.Feeds, e.EPSS.API = fc, f.URL+"/epss"
		e.EOL.Feeds, e.EOL.API = fc, f.URL
		e.CVE.Feeds, e.CVE.Base = fc, f.URL
		e.Apple.Feeds = fc
		return e
	}
}

// testDaemon returns a daemon (not started) with a scheduler, a fixed clock
// and, when f isn't nil, f as its data sources. Its log goes to logs.
func testDaemon(t *testing.T, n notify.Notifier, f *feedServer, logs io.Writer) (*Daemon, config.Paths) {
	t.Helper()
	paths := newInstall(t)
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := New(paths, "test", log, n)
	d.now = func() time.Time { return time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC) }
	d.sched = newScheduler(nil, filepath.Join(paths.State, "schedule.json"), d.now, d.unlocked, log)
	if f != nil {
		d.feeds = feeds.NewForTest(f.URL)
		d.newEngine = f.engine(paths, log)
		d.feedURLs = []string{f.URL + "/Debian/modified_id.csv", f.URL + "/Ubuntu/modified_id.csv"}
	}
	return d, paths
}

// addServer registers a server in config.yaml and saves a package list for
// it that was read at collected, with openssh installed.
func addServer(t *testing.T, paths config.Paths, name string, collected time.Time) {
	t.Helper()
	cfg, err := config.Load(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Servers = append(cfg.Servers, config.Server{Name: name, Host: "127.0.0.1", Port: 1, AdminSSH: "u@127.0.0.1"})
	if err := cfg.Save(paths.Config); err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{CollectedAt: collected, OSID: "ubuntu", OSVersion: "24.04", Kernel: "6.8.0-49-generic", Arch: "amd64",
		Packages: []inventory.Package{{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.5", Source: "openssh", SourceVersion: "1:9.6p1-3ubuntu13.5"}}}
	if err := inventory.Save(paths, name, inv); err != nil {
		t.Fatal(err)
	}
}
