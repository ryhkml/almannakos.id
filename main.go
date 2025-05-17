package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode/utf8"

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

var Almn = AlmnData{
	Price: "1.400.000",
	Contact: AlmnContact{
		Main:      "+6281330566254",
		Secondary: "+6282229335820",
	},
	FullyBooked: false,
}

var CSPHeaders = [][]string{
	{
		"default-src 'none'",
		"connect-src 'self' https://www.google-analytics.com https://analytics.google.com https://*.googleapis.com https://www.google.com https://*.gstatic.com data: blob:",
		"script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://maps.googleapis.com https://*.gstatic.com https://www.google.com https://*.ggpht.com https://*.googleusercontent.com blob:",
		"child-src 'self' blob:",
		"frame-src https://www.google.com",
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
		"form-action 'none'",
		"img-src 'self' https://maps.googleapis.com https://*.gstatic.com https://www.google.com https://*.googleusercontent.com data:",
		"manifest-src 'self'",
		"worker-src 'self' blob:",
		"base-uri 'self'",
		"object-src 'none'",
		"font-src https://fonts.gstatic.com",
		"frame-ancestors 'self'",
	},
	{
		"default-src 'none'",
		"connect-src 'self' https://www.google-analytics.com https://analytics.google.com data: blob:",
		"script-src 'self' 'unsafe-inline' https://www.googletagmanager.com blob:",
		"child-src 'self' blob:",
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
	},
}

var (
	CSPIndex   = strings.Join(CSPHeaders[0], "; ")
	CSPDefault = strings.Join(CSPHeaders[1], "; ")
)

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

func serveStaticFile(path string, cacheControlValue ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if len(cacheControlValue) > 0 && cacheControlValue[0] != "" {
			c.Set(fiber.HeaderCacheControl, cacheControlValue[0])
		}
		return c.SendFile(path)
	}
}

func setViewHeaders(csp, xFrameOptions string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderCacheControl, CacheControlPublicLong)
		c.Set(fiber.HeaderContentSecurityPolicy, csp)
		c.Set(fiber.HeaderXFrameOptions, xFrameOptions)
		return c.Next()
	}
}

func main() {
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
	})

	if err := godotenv.Load(); err != nil {
		fmt.Println("Cannot load .env file")
	}

	cookieSecure := os.Getenv("COOKIE_SECURE") == "1"
	cookieName := "csrf_"
	if cookieSecure {
		cookieName = "__Secure-csrf_.X-Csrf-Token"
	}
	csrfConfig := csrf.New(csrf.Config{
		KeyLookup:      "header:X-Csrf-Token",
		SingleUseToken: true,
		CookieSecure:   cookieSecure,
		CookieName:     cookieName,
		CookieHTTPOnly: true,
		CookiePath:     "/",
		CookieSameSite: "Strict",
		ContextKey:     "Token",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			c.Status(fiber.StatusForbidden)
			c.Set(fiber.HeaderCacheControl, CacheControlNoStore)
			return nil
		},
	})
	app.Use(csrfConfig)

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
	app.Get("/llms.txt", serveStaticFile("./public/llms.txt", CacheControl404))
	app.Get("/robots.txt", serveStaticFile("./public/robots.txt", CacheControl404))
	app.Get("/sitemap.xml", serveStaticFile("./public/sitemap.xml", CacheControl404))

	// Views
	app.Get("/", setViewHeaders(CSPIndex, "SAMEORIGIN"), func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{
			"ContactMain":      Almn.Contact.Main,
			"ContactSecondary": Almn.Contact.Secondary,
			"FullyBooked":      Almn.FullyBooked,
			"Price":            Almn.Price,
		})
	})
	app.Get("/rules", setViewHeaders(CSPDefault, "DENY"), func(c *fiber.Ctx) error {
		return c.Render("rules", fiber.Map{})
	})
	app.Get("/gallery", setViewHeaders(CSPDefault, "DENY"), func(c *fiber.Ctx) error {
		return c.Render("gallery", fiber.Map{
			"Price": Almn.Price,
		})
	})
	app.Get("/privacy-policy", setViewHeaders(CSPDefault, "DENY"), func(c *fiber.Ctx) error {
		return c.Render("privacy-policy", fiber.Map{})
	})

	port := os.Getenv("PORT")
	if port == "" || port == "0" {
		port = "9100"
	}
	addr := fmt.Sprintf("127.0.0.1:%s", port)
	log.Fatal(app.Listen(addr))
}
