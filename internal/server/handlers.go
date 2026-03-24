package server

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/hudsoncoutinho/honeybr/internal/config"
	"github.com/hudsoncoutinho/honeybr/internal/ebpf"
)

func New(cfg *config.Rules, stream <-chan ebpf.RuntimeEvent) *fiber.App {
	_ = cfg
	hub := NewHub()
	state := NewState()
	startLoaderStream(hub, state, stream)
	app := fiber.New()

	app.Get("/", func(c *fiber.Ctx) error {
		c.Type("html")
		return c.SendString(indexHTML)
	})

	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	app.Get("/ws", websocket.New(func(conn *websocket.Conn) {
		hub.Add(conn)
		defer hub.Remove(conn)

		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}))

	app.Get("/api/summary", func(c *fiber.Ctx) error {
		sum, _ := state.Snapshot()
		return c.JSON(sum)
	})

	app.Get("/api/events", func(c *fiber.Ctx) error {
		_, events := state.Snapshot()
		ns := c.Query("namespace")
		pod := c.Query("pod")
		if ns == "" && pod == "" {
			return c.JSON(events)
		}
		filtered := make([]SecurityEvent, 0, len(events))
		for _, ev := range events {
			if ns != "" && ev.Namespace != ns {
				continue
			}
			if pod != "" && ev.Pod != pod {
				continue
			}
			filtered = append(filtered, ev)
		}
		return c.JSON(filtered)
	})

	app.Get("/api/filters", func(c *fiber.Ctx) error {
		_, events := state.Snapshot()
		nsSet := map[string]struct{}{}
		podSet := map[string]struct{}{}
		for _, ev := range events {
			if ev.Namespace != "" {
				nsSet[ev.Namespace] = struct{}{}
			}
			if ev.Pod != "" {
				podSet[ev.Pod] = struct{}{}
			}
		}
		namespaces := make([]string, 0, len(nsSet))
		for v := range nsSet {
			namespaces = append(namespaces, v)
		}
		pods := make([]string, 0, len(podSet))
		for v := range podSet {
			pods = append(pods, v)
		}
		sort.Strings(namespaces)
		sort.Strings(pods)
		return c.JSON(fiber.Map{
			"namespaces": namespaces,
			"pods":       pods,
		})
	})

	app.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	return app
}

func startLoaderStream(hub *Hub, state *State, stream <-chan ebpf.RuntimeEvent) {
	go func() {
		for ev := range stream {
			out := SecurityEvent{
				Timestamp:      ev.Timestamp.Format(time.RFC3339),
				Type:           ev.Type,
				Severity:       ev.Severity,
				Priority:       ev.Priority,
				CredentialType: ev.CredentialType,
				Source:         ev.Source,
				Target:         ev.Target,
				Node:           ev.Node,
				Namespace:      ev.Namespace,
				Pod:            ev.Pod,
				Container:      ev.Container,
			}
			sum := state.AddEvent(out)
			raw, _ := json.Marshal(WSMessage{
				Event:   out,
				Summary: sum,
			})
			hub.Broadcast(string(raw))
		}
	}()
}

const indexHTML = `<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>honeyBR // SOC</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700&family=Share+Tech+Mono&display=swap" rel="stylesheet" />
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
      :root {
        --bg0: #030806;
        --bg1: #0a120e;
        --panel: rgba(6, 18, 12, 0.92);
        --border: rgba(0, 255, 136, 0.35);
        --glow: rgba(0, 255, 170, 0.45);
        --txt: #b8ffd4;
        --txt-dim: #4a9d6e;
        --accent: #00ff88;
        --accent2: #00d4ff;
        --warn: #ffcc00;
        --danger: #ff3366;
      }
      * { box-sizing: border-box; }
      body.hb-body {
        font-family: "Share Tech Mono", ui-monospace, monospace;
        background: var(--bg0);
        color: var(--txt);
        min-height: 100vh;
        margin: 0;
        position: relative;
        overflow-x: hidden;
      }
      body.hb-body::before {
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        background:
          repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0, 0, 0, 0.18) 2px, rgba(0, 0, 0, 0.18) 4px),
          radial-gradient(ellipse 120% 80% at 50% -20%, rgba(0, 255, 120, 0.12), transparent 50%),
          linear-gradient(180deg, var(--bg0) 0%, var(--bg1) 40%, #050a08 100%);
        z-index: 0;
      }
      body.hb-body::after {
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        background: radial-gradient(circle at 80% 20%, rgba(0, 212, 255, 0.06), transparent 40%);
        z-index: 0;
      }
      .hb-main { position: relative; z-index: 1; max-width: 72rem; margin: 0 auto; padding: 1.5rem 1.25rem 3rem; }
      .hb-header {
        border: 1px solid var(--border);
        background: var(--panel);
        box-shadow: 0 0 24px rgba(0, 255, 136, 0.08), inset 0 1px 0 rgba(0, 255, 170, 0.12);
        padding: 1rem 1.25rem;
        margin-bottom: 1.25rem;
        clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 12px 100%, 0 calc(100% - 12px));
      }
      .hb-title {
        font-family: "Rajdhani", sans-serif;
        font-weight: 700;
        font-size: clamp(1.75rem, 4vw, 2.35rem);
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--accent);
        text-shadow: 0 0 20px var(--glow), 0 0 40px rgba(0, 255, 136, 0.2);
        margin: 0 0 0.35rem;
      }
      .hb-sub { color: var(--txt-dim); font-size: 0.8rem; margin: 0; line-height: 1.5; }
      .hb-prompt { color: var(--accent2); font-size: 0.75rem; margin-top: 0.65rem; }
      .hb-prompt .cursor { animation: hb-blink 1.1s step-end infinite; color: var(--accent); }
      @keyframes hb-blink { 50% { opacity: 0; } }
      .hb-panel {
        border: 1px solid var(--border);
        background: var(--panel);
        padding: 1rem 1.1rem;
        margin-bottom: 0.75rem;
        box-shadow: inset 0 0 0 1px rgba(0, 0, 0, 0.35);
      }
      .hb-panel h2 {
        font-family: "Rajdhani", sans-serif;
        font-weight: 600;
        font-size: 1rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--accent2);
        margin: 0 0 0.75rem;
        border-bottom: 1px dashed rgba(0, 255, 136, 0.25);
        padding-bottom: 0.4rem;
      }
      .hb-metric label { font-size: 0.65rem; color: var(--txt-dim); text-transform: uppercase; letter-spacing: 0.15em; }
      .hb-metric .val { font-size: 1.65rem; font-weight: 700; margin-top: 0.2rem; }
      .hb-metric.crit .val { color: var(--danger); text-shadow: 0 0 12px rgba(255, 51, 102, 0.5); }
      .hb-metric.cmd .val { color: var(--warn); }
      .hb-metric.sec .val { color: var(--accent2); }
      .hb-metric.tot .val { color: var(--accent); }
      select.hb-input, button.hb-btn {
        font-family: inherit;
        font-size: 0.8rem;
        background: #050d0a;
        color: var(--accent);
        border: 1px solid var(--border);
        padding: 0.45rem 0.6rem;
        width: 100%;
      }
      button.hb-btn {
        width: auto;
        cursor: pointer;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        transition: background 0.15s, box-shadow 0.15s;
      }
      button.hb-btn:hover {
        background: rgba(0, 255, 136, 0.12);
        box-shadow: 0 0 12px rgba(0, 255, 136, 0.2);
      }
      .hb-table-wrap { overflow: auto; max-height: 420px; }
      table.hb-table { width: 100%; font-size: 0.72rem; border-collapse: collapse; }
      table.hb-table th {
        text-align: left;
        color: var(--accent2);
        padding: 0.5rem 0.35rem;
        border-bottom: 1px solid var(--border);
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }
      table.hb-table td { padding: 0.45rem 0.35rem; border-bottom: 1px solid rgba(0, 255, 136, 0.12); color: var(--txt); }
      table.hb-table tbody tr:hover { background: rgba(0, 255, 136, 0.06); }
      .sev-crit { color: var(--danger); }
      .sev-high { color: #ff8c42; }
      .sev-med { color: var(--warn); }
      .sev-low { color: var(--txt-dim); }
      #map { height: 260px; border: 1px solid var(--border); background: #020805; }
      .leaflet-container { background: #020805; font-family: "Share Tech Mono", monospace; }
      .leaflet-popup-content-wrapper {
        background: #0a120e;
        color: var(--accent);
        border: 1px solid var(--border);
        border-radius: 0;
      }
      .leaflet-popup-tip { background: #0a120e; }
    </style>
  </head>
  <body class="hb-body">
    <main class="hb-main space-y-4">
      <header class="hb-header">
        <h1 class="hb-title">HoneyBR</h1>
        <p class="hb-sub">[ KERNEL / eBPF ] deteccao de ameacas e vazamento de credenciais no runtime (CI/CD, pods, agentes)</p>
        <p class="hb-prompt">root@honeybr:~# ./watch-runtime --live<span class="cursor">_</span></p>
      </header>

      <section class="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div class="hb-panel hb-metric tot"><label>Total</label><p id="m-total" class="val">0</p></div>
        <div class="hb-panel hb-metric crit"><label>Criticos</label><p id="m-critical" class="val">0</p></div>
        <div class="hb-panel hb-metric cmd"><label>Cmd suspeitos</label><p id="m-cmd" class="val">0</p></div>
        <div class="hb-panel hb-metric sec"><label>Segredos</label><p id="m-secret" class="val">0</p></div>
      </section>

      <section class="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div class="hb-panel">
          <label class="text-xs uppercase tracking-widest" style="color:var(--txt-dim)">Namespace</label>
          <select id="f-namespace" class="hb-input mt-2"></select>
        </div>
        <div class="hb-panel">
          <label class="text-xs uppercase tracking-widest" style="color:var(--txt-dim)">Pod</label>
          <select id="f-pod" class="hb-input mt-2"></select>
        </div>
        <div class="hb-panel md:col-span-2 flex flex-wrap items-end gap-2">
          <button type="button" id="preset-ci" class="hb-btn flex-1 min-w-[140px]">Preset: gitlab-agent-hml</button>
          <button type="button" id="preset-clear" class="hb-btn flex-1 min-w-[120px]">Limpar filtros</button>
        </div>
      </section>

      <section class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="hb-panel">
          <h2>Severidade // histogram</h2>
          <canvas id="severityChart" height="140"></canvas>
        </div>
        <div class="hb-panel">
          <h2>Geoloc // feed</h2>
          <div id="map" class="z-0"></div>
        </div>
      </section>

      <section class="hb-panel">
        <h2>Stream // ameacas &amp; vazamentos</h2>
        <div class="hb-table-wrap">
          <table class="hb-table">
            <thead>
              <tr>
                <th>Hora</th><th>Tipo</th><th>Credencial</th><th>Sev</th><th>Prio</th><th>NS</th><th>Pod</th><th>Origem</th><th>Alvo</th>
              </tr>
            </thead>
            <tbody id="events"></tbody>
          </table>
        </div>
      </section>
    </main>

    <script>
      const tableBody = document.getElementById("events");
      const nsSelect = document.getElementById("f-namespace");
      const podSelect = document.getElementById("f-pod");
      const presetCI = document.getElementById("preset-ci");
      const presetClear = document.getElementById("preset-clear");
      const counters = {
        total: document.getElementById("m-total"),
        critical: document.getElementById("m-critical"),
        cmd: document.getElementById("m-cmd"),
        secret: document.getElementById("m-secret"),
      };

      const chartColors = { low: "#00d4aa", medium: "#ffcc00", high: "#ff6b35", critical: "#ff0044" };
      const gridTheme = {
        color: "rgba(0, 255, 136, 0.12)",
        lineWidth: 1,
      };
      const tickTheme = { color: "#4a9d6e", font: { family: "Share Tech Mono", size: 10 } };

      const severityCount = { low: 0, medium: 0, high: 0, critical: 0 };
      let filteredNamespace = "";
      let filteredPod = "";
      let currentRows = [];
      const severityChart = new Chart(document.getElementById("severityChart"), {
        type: "bar",
        data: {
          labels: ["low", "medium", "high", "critical"],
          datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: [chartColors.low, chartColors.medium, chartColors.high, chartColors.critical],
            borderColor: "rgba(0, 255, 136, 0.4)",
            borderWidth: 1,
          }],
        },
        options: {
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: tickTheme, grid: gridTheme },
            y: { ticks: tickTheme, grid: gridTheme, beginAtZero: true },
          },
        },
      });

      const map = L.map("map", { attributionControl: true }).setView([-15.79, -47.88], 3);
      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        attribution: '&copy; OSM &copy; CARTO',
        subdomains: "abcd",
        maxZoom: 19,
      }).addTo(map);

      function sevClass(s) {
        if (s === "critical") return "sev-crit";
        if (s === "high") return "sev-high";
        if (s === "medium") return "sev-med";
        return "sev-low";
      }

      function setSummary(s) {
        counters.total.textContent = s.totalEvents;
        counters.critical.textContent = s.criticalEvents;
        counters.cmd.textContent = s.suspiciousCommands;
        counters.secret.textContent = s.secretAccess;
      }

      function addEventRow(ev) {
        if (filteredNamespace && ev.namespace !== filteredNamespace) return;
        if (filteredPod && ev.pod !== filteredPod) return;
        const tr = document.createElement("tr");
        const sc = sevClass(ev.severity);
        tr.innerHTML =
          "<td>" + new Date(ev.timestamp).toLocaleTimeString() + "</td><td>" + ev.type + "</td><td>" + (ev.credentialType || "-") +
          "</td><td class='" + sc + "'>" + ev.severity + "</td><td>" + (ev.priority || 0) + "</td><td>" + (ev.namespace || "-") +
          "</td><td>" + (ev.pod || "-") + "</td><td>" + ev.source + "</td><td>" + ev.target + "</td>";
        tableBody.prepend(tr);
        while (tableBody.children.length > 20) tableBody.removeChild(tableBody.lastChild);

        severityCount[ev.severity] = (severityCount[ev.severity] || 0) + 1;
        severityChart.data.datasets[0].data = ["low", "medium", "high", "critical"].map((k) => severityCount[k] || 0);
        severityChart.update();

        const marker = L.circleMarker([-14 + Math.random() * 20, -52 + Math.random() * 18], {
          radius: 6,
          color: "#00ff88",
          fillColor: "#00ff88",
          fillOpacity: 0.35,
          weight: 1,
        });
        marker.addTo(map).bindPopup("<span style='color:#00ff88'>" + (ev.namespace || "?") + "/" + (ev.pod || "?") + "</span><br/>" + ev.type);
      }

      function resetTableAndChart() {
        tableBody.innerHTML = "";
        severityCount.low = 0;
        severityCount.medium = 0;
        severityCount.high = 0;
        severityCount.critical = 0;
        severityChart.data.datasets[0].data = [0, 0, 0, 0];
        severityChart.update();
      }

      async function refreshFilters() {
        const f = await fetch("/api/filters").then((r) => r.json());
        const ns = ["", ...f.namespaces];
        const pods = ["", ...f.pods];
        nsSelect.innerHTML = ns.map((v) => "<option value='" + v + "'>" + (v || "Todos") + "</option>").join("");
        podSelect.innerHTML = pods.map((v) => "<option value='" + v + "'>" + (v || "Todos") + "</option>").join("");
        nsSelect.value = filteredNamespace;
        podSelect.value = filteredPod;
      }

      async function bootstrap() {
        await refreshFilters();
        const summary = await fetch("/api/summary").then((r) => r.json());
        const qs = new URLSearchParams();
        if (filteredNamespace) qs.set("namespace", filteredNamespace);
        if (filteredPod) qs.set("pod", filteredPod);
        const events = await fetch("/api/events?" + qs.toString()).then((r) => r.json());
        currentRows = events;
        resetTableAndChart();
        setSummary(summary);
        events.slice(0, 20).forEach(addEventRow);
      }

      bootstrap();

      nsSelect.onchange = () => {
        filteredNamespace = nsSelect.value;
        filteredPod = "";
        bootstrap();
      };

      podSelect.onchange = () => {
        filteredPod = podSelect.value;
        bootstrap();
      };

      presetCI.onclick = () => {
        filteredNamespace = "gitlab-agent-hml";
        filteredPod = "";
        bootstrap();
      };

      presetClear.onclick = () => {
        filteredNamespace = "";
        filteredPod = "";
        bootstrap();
      };

      const ws = new WebSocket(` + "`ws://${location.host}/ws`" + `);
      ws.onmessage = (raw) => {
        const data = JSON.parse(raw.data);
        setSummary(data.summary);
        addEventRow(data.event);
      };
    </script>
  </body>
</html>`
