package middleware

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// LoggingMiddleware logs each incoming HTTP request in JSON format.
func LoggingMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(logrus.Fields{
			// ECS field names
			"http.request.method": r.Method,
			"url.original":        r.RequestURI,
			"source.ip":           r.RemoteAddr,
			"event.dataset":       "http.request",
			"event.kind":          "event",
		}).Info("incoming HTTP request")

		next.ServeHTTP(w, r)
	})
}
