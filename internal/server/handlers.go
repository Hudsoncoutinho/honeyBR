package server

import (
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/hudsoncoutinho/honeybr/internal/config"
)

func New(cfg *config.Rules) *fiber.App {
	_ = cfg
	hub := NewHub()
	state := NewState()
	StartDemoStream(hub, state)
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
		return c.JSON(events)
	})

	app.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	return app
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
      <p class="text-zinc-400 mb-6">Monitor de seguranca runtime via eBPF</p>

      <section class="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><p class="text-xs text-zinc-400">Total</p><p id="m-total" class="text-2xl font-bold">0</p></div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><p class="text-xs text-zinc-400">Criticos</p><p id="m-critical" class="text-2xl font-bold text-red-400">0</p></div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><p class="text-xs text-zinc-400">Comandos suspeitos</p><p id="m-cmd" class="text-2xl font-bold text-amber-300">0</p></div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><p class="text-xs text-zinc-400">Acesso a segredos</p><p id="m-secret" class="text-2xl font-bold text-cyan-300">0</p></div>
      </section>

      <section class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <h2 class="text-lg font-semibold mb-3">Eventos por severidade</h2>
          <canvas id="severityChart" height="140"></canvas>
        </div>
        <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <h2 class="text-lg font-semibold mb-3">Mapa de eventos</h2>
          <div id="map" class="h-[260px] rounded"></div>
        </div>
      </section>

      <section class="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
        <h2 class="text-lg font-semibold mb-3">Eventos em tempo real</h2>
        <div class="overflow-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-zinc-400 border-b border-zinc-800">
                <th class="text-left py-2">Horario</th><th class="text-left py-2">Tipo</th><th class="text-left py-2">Severidade</th><th class="text-left py-2">Origem</th><th class="text-left py-2">Alvo</th>
              </tr>
            </thead>
            <tbody id="events"></tbody>
          </table>
        </div>
      </section>
    </main>

    <script>
      const tableBody = document.getElementById("events");
      const counters = {
        total: document.getElementById("m-total"),
        critical: document.getElementById("m-critical"),
        cmd: document.getElementById("m-cmd"),
        secret: document.getElementById("m-secret"),
      };

      const severityCount = { low: 0, medium: 0, high: 0, critical: 0 };
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
        const tr = document.createElement("tr");
        tr.className = "border-b border-zinc-800";
        tr.innerHTML = "<td class='py-2'>" + new Date(ev.timestamp).toLocaleTimeString() + "</td><td>" + ev.type + "</td><td>" + ev.severity + "</td><td>" + ev.source + "</td><td>" + ev.target + "</td>";
        tableBody.prepend(tr);
        while (tableBody.children.length > 20) tableBody.removeChild(tableBody.lastChild);

        severityCount[ev.severity] = (severityCount[ev.severity] || 0) + 1;
        severityChart.data.datasets[0].data = ["low", "medium", "high", "critical"].map((k) => severityCount[k] || 0);
        severityChart.update();

        L.circleMarker([ev.lat, ev.lng], { radius: 5, color: "#f97316" }).addTo(map).bindPopup(ev.type + " - " + ev.severity);
      }

      async function bootstrap() {
        const summary = await fetch("/api/summary").then((r) => r.json());
        const events = await fetch("/api/events").then((r) => r.json());
        setSummary(summary);
        events.slice(0, 20).forEach(addEventRow);
      }

      bootstrap();

      const ws = new WebSocket(` + "`ws://${location.host}/ws`" + `);
      ws.onmessage = (raw) => {
        const data = JSON.parse(raw.data);
        setSummary(data.summary);
        addEventRow(data.event);
      };
    </script>
  </body>
</html>`
