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
  </head>
  <body class="bg-zinc-950 text-zinc-100 min-h-screen p-6">
    <main class="max-w-5xl mx-auto">
      <h1 class="text-3xl font-bold mb-2">HoneyBR</h1>
      <p class="text-zinc-400 mb-6">Monitor de seguranca runtime via eBPF</p>

      <section class="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
        <h2 class="text-lg font-semibold mb-3">Eventos em tempo real</h2>
        <ul id="events" class="space-y-2 text-sm text-zinc-200"></ul>
      </section>
    </main>

    <script>
      const list = document.getElementById("events");
      const ws = new WebSocket(` + "`ws://${location.host}/ws`" + `);
      ws.onmessage = (event) => {
        const li = document.createElement("li");
        li.className = "bg-zinc-800 p-2 rounded";
        li.textContent = event.data;
        list.prepend(li);
      };
    </script>
  </body>
</html>`
