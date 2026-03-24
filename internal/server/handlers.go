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
				Timestamp: ev.Timestamp.Format(time.RFC3339),
				Type:      ev.Type,
				Severity:  ev.Severity,
				Source:    ev.Source,
				Target:    ev.Target,
				Node:      ev.Node,
				Namespace: ev.Namespace,
				Pod:       ev.Pod,
				Container: ev.Container,
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
    <title>HoneyBR Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  </head>
  <body class="bg-zinc-950 text-zinc-100 min-h-screen p-6">
    <main class="max-w-6xl mx-auto space-y-6">
      <h1 class="text-3xl font-bold mb-2">HoneyBR</h1>
      <p class="text-zinc-400 mb-6">Deteccao de ameacas e vazamento de segredos no runtime de CI/CD</p>

      <section class="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><p class="text-xs text-zinc-400">Total</p><p id="m-total" class="text-2xl font-bold">0</p></div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><p class="text-xs text-zinc-400">Criticos</p><p id="m-critical" class="text-2xl font-bold text-red-400">0</p></div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><p class="text-xs text-zinc-400">Comandos suspeitos</p><p id="m-cmd" class="text-2xl font-bold text-amber-300">0</p></div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><p class="text-xs text-zinc-400">Acesso a segredos</p><p id="m-secret" class="text-2xl font-bold text-cyan-300">0</p></div>
      </section>

      <section class="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
          <label class="text-xs text-zinc-400">Namespace</label>
          <select id="f-namespace" class="mt-1 w-full bg-zinc-800 rounded p-2 text-sm"></select>
        </div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-3">
          <label class="text-xs text-zinc-400">Pod</label>
          <select id="f-pod" class="mt-1 w-full bg-zinc-800 rounded p-2 text-sm"></select>
        </div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-3 md:col-span-2 flex items-end gap-2">
          <button id="preset-ci" class="bg-zinc-800 hover:bg-zinc-700 px-3 py-2 rounded text-sm">Preset CI/CD (gitlab-agent-hml)</button>
          <button id="preset-clear" class="bg-zinc-800 hover:bg-zinc-700 px-3 py-2 rounded text-sm">Limpar filtros</button>
        </div>
      </section>

      <section class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <h2 class="text-lg font-semibold mb-3">Eventos por severidade</h2>
          <canvas id="severityChart" height="140"></canvas>
        </div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <h2 class="text-lg font-semibold mb-3">Mapa de eventos</h2>
          <div id="map" class="h-[260px] rounded z-0"></div>
        </div>
      </section>

      <section class="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
        <h2 class="text-lg font-semibold mb-3">Ameacas e possiveis vazamentos (runtime)</h2>
        <div class="overflow-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-zinc-400 border-b border-zinc-800">
                <th class="text-left py-2">Horario</th><th class="text-left py-2">Tipo</th><th class="text-left py-2">Severidade</th><th class="text-left py-2">Namespace</th><th class="text-left py-2">Pod</th><th class="text-left py-2">Origem</th><th class="text-left py-2">Alvo</th>
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

      const severityCount = { low: 0, medium: 0, high: 0, critical: 0 };
      let filteredNamespace = "gitlab-agent-hml";
      let filteredPod = "";
      let currentRows = [];
      const severityChart = new Chart(document.getElementById("severityChart"), {
        type: "bar",
        data: {
          labels: ["low", "medium", "high", "critical"],
          datasets: [{ data: [0, 0, 0, 0], backgroundColor: ["#38bdf8", "#fbbf24", "#f97316", "#ef4444"] }],
        },
        options: { plugins: { legend: { display: false } } },
      });

      const map = L.map("map").setView([-15.79, -47.88], 3);
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(map);

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
        tr.className = "border-b border-zinc-800";
        tr.innerHTML = "<td class='py-2'>" + new Date(ev.timestamp).toLocaleTimeString() + "</td><td>" + ev.type + "</td><td>" + ev.severity + "</td><td>" + (ev.namespace || "-") + "</td><td>" + (ev.pod || "-") + "</td><td>" + ev.source + "</td><td>" + ev.target + "</td>";
        tableBody.prepend(tr);
        while (tableBody.children.length > 20) tableBody.removeChild(tableBody.lastChild);

        severityCount[ev.severity] = (severityCount[ev.severity] || 0) + 1;
        severityChart.data.datasets[0].data = ["low", "medium", "high", "critical"].map((k) => severityCount[k] || 0);
        severityChart.update();

        const marker = L.circleMarker([-14 + Math.random() * 20, -52 + Math.random() * 18], { radius: 5, color: "#f97316" });
        marker.addTo(map).bindPopup((ev.namespace || "unknown") + "/" + (ev.pod || "unknown") + " - " + ev.type);
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
