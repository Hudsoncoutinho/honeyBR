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
		return c.SendFile("templates/index.html")
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
