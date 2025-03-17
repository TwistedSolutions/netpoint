package middleware

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// LoggingMiddleware logs each incoming HTTP request in JSON format.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the request details.
		logrus.WithFields(logrus.Fields{
			"method":      r.Method,
			"url":         r.RequestURI,
			"remote_addr": r.RemoteAddr,
		}).Info("Incoming request")
		next.ServeHTTP(w, r)
	})
}
