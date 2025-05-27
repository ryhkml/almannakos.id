package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
)

type (
	AlmnContact struct {
		Main      string
		Secondary string
	}
	AlmnData struct {
		Price       string
		Contact     AlmnContact
		FullyBooked bool
	}
)

var CSPHeaders = [][]string{
	{
		"default-src 'none'",
		"connect-src 'self' data: https://www.google-analytics.com https://analytics.google.com https://*.googleapis.com https://www.google.com https://*.gstatic.com",
		"script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://maps.googleapis.com https://*.gstatic.com https://www.google.com https://*.ggpht.com https://*.googleusercontent.com",
		"child-src 'self'",
		"frame-src https://www.google.com",
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
		"form-action 'none'",
		"img-src 'self' data: https://maps.googleapis.com https://*.gstatic.com https://www.google.com https://*.googleusercontent.com",
		"manifest-src 'self'",
		"worker-src 'self'",
		"base-uri 'self'",
		"object-src 'none'",
		"font-src https://fonts.gstatic.com",
		"frame-ancestors 'self'",
		"block-all-mixed-content;",
	},
	{
		"default-src 'none'",
		"connect-src 'self' data: https://www.google-analytics.com https://analytics.google.com",
		"script-src 'self' 'unsafe-inline' https://www.googletagmanager.com",
		"child-src 'self'",
		"frame-src 'none'",
		"style-src 'self' 'unsafe-inline'",
		"form-action 'none'",
		"img-src 'self' data:",
		"manifest-src 'self'",
		"worker-src 'self' blob:",
		"base-uri 'self'",
		"object-src 'none'",
		"font-src 'none'",
		"frame-ancestors 'self'",
		"block-all-mixed-content;",
	},
}

const (
	CacheControlPublicLong = "public, max-age=604800, stale-while-revalidate=86400, immutable"
	CacheControlNoStore    = "no-cache, no-store, must-revalidate"
	CacheControl404        = "private, max-age=0"
)

func truncate(v string) string {
	const MAX_LEN = 24
	if utf8.RuneCountInString(v) <= MAX_LEN {
		return v
	}
	runes := []rune(v)
	if MAX_LEN > 3 {
		return string(runes[:MAX_LEN-3]) + "..."
	}
	return string(runes[:MAX_LEN])
}

func containsAssets(path string) bool {
	return strings.HasSuffix(path, ".ico") ||
		strings.HasSuffix(path, ".jpeg") ||
		strings.HasSuffix(path, ".jpg") ||
		strings.HasSuffix(path, ".png") ||
		strings.HasSuffix(path, ".svg")
}

func containsGEO(path string) bool {
	return path == "/llms.txt"
}

func containsSEO(path string) bool {
	return path == "/robots.txt" || path == "/sitemap.xml"
}

func containsCSS(path string) bool {
	return strings.HasSuffix(path, ".css")
}

func containsJS(path string) bool {
	return strings.HasSuffix(path, ".js")
}

func serveStaticFile(path string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.SendFile(path)
	}
}

func headersProtection() fiber.Handler {
	return func(c *fiber.Ctx) error {
		path := c.Path()
		if containsAssets(path) {
			c.Set(fiber.HeaderCacheControl, CacheControlPublicLong)
			return c.Next()
		}
		if containsGEO(path) || containsSEO(path) {
			c.Set(fiber.HeaderCacheControl, CacheControl404)
			return c.Next()
		}
		c.Set(fiber.HeaderCacheControl, CacheControlPublicLong)
		if containsCSS(path) {
			c.Set(fiber.HeaderContentSecurityPolicy, "default-src 'none'; style-src 'self' 'unsafe-inline';")
			return c.Next()
		}
		if containsJS(path) {
			c.Set(fiber.HeaderContentSecurityPolicy, "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';")
			return c.Next()
		}
		if path == "/" {
			c.Set(fiber.HeaderContentSecurityPolicy, strings.Join(CSPHeaders[0], "; "))
			c.Set(fiber.HeaderXFrameOptions, "SAMEORIGIN")
			return c.Next()
		}
		c.Set(fiber.HeaderContentSecurityPolicy, strings.Join(CSPHeaders[1], "; "))
		c.Set(fiber.HeaderXFrameOptions, "DENY")
		return c.Next()
	}
}

func main() {
	// Data
	almn := AlmnData{
		Price: "1.200.000",
		Contact: AlmnContact{
			Main:      "+6281330566254",
			Secondary: "+6282229335820",
		},
		FullyBooked: false,
	}

	// Template engine
	engine := html.New("./public", ".html")
	app := fiber.New(fiber.Config{
		Views:     engine,
		BodyLimit: 16 * 1024,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			var e *fiber.Error
			if errors.As(err, &e) {
				code = e.Code
			}
			c.Status(code)
			if code == fiber.StatusNotFound {
				c.Set(fiber.HeaderCacheControl, CacheControl404)
				return c.Render("404", fiber.Map{
					"Path": truncate(c.Path()),
				})
			}
			c.Set(fiber.HeaderCacheControl, CacheControlNoStore)
			return nil
		},
		JSONEncoder: json.Marshal,
		JSONDecoder: json.Unmarshal,
	})

	if err := godotenv.Load(); err != nil {
		fmt.Println("Cannot load .env file")
	}

	app.Use(headersProtection())

	cookieSecure := os.Getenv("COOKIE_SECURE") == "1"
	cookieName := "csrf_"
	if cookieSecure {
		cookieName = "__Secure-csrf_.X-Csrf-Token"
	}
	csrfProtection := csrf.New(csrf.Config{
		CookieSessionOnly: true,
		CookieSecure:      cookieSecure,
		CookieName:        cookieName,
		CookieHTTPOnly:    true,
		CookiePath:        "/",
		ContextKey:        "Token",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			c.Status(fiber.StatusForbidden)
			c.Set(fiber.HeaderCacheControl, CacheControlNoStore)
			return nil
		},
		Next: func(c *fiber.Ctx) bool {
			path := c.Path()
			return containsAssets(path) || containsGEO(path) || containsSEO(path) ||
				containsCSS(path) || containsJS(path)
		},
	})
	app.Use(csrfProtection)

	// Static files
	staticConfig := fiber.Static{
		Compress:  true,
		ByteRange: true,
	}
	app.Static("/assets", "./public/assets", staticConfig)
	app.Static("/css", "./public/css", staticConfig)
	app.Static("/js", "./public/js", staticConfig)

	// Favicon
	app.Get("/favicon.png", serveStaticFile("./public/favicon.png"))

	// SEO
	app.Get("/llms.txt", serveStaticFile("./public/llms.txt"))
	app.Get("/robots.txt", serveStaticFile("./public/robots.txt"))
	app.Get("/sitemap.xml", serveStaticFile("./public/sitemap.xml"))

	// Views
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{
			"ContactMain":      almn.Contact.Main,
			"ContactSecondary": almn.Contact.Secondary,
			"FullyBooked":      almn.FullyBooked,
			"Price":            almn.Price,
		})
	})
	app.Get("/rules", func(c *fiber.Ctx) error {
		return c.Render("rules", fiber.Map{})
	})
	app.Get("/gallery", func(c *fiber.Ctx) error {
		return c.Render("gallery", fiber.Map{
			"Price": almn.Price,
		})
	})
	app.Get("/privacy-policy", func(c *fiber.Ctx) error {
		return c.Render("privacy-policy", fiber.Map{})
	})

	port := os.Getenv("PORT")
	if port == "" || port == "0" {
		port = "9100"
	}
	log.Fatal(app.Listen(fmt.Sprintf("127.0.0.1:%s", port)))
}
