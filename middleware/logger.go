package middleware

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware logs each incoming HTTP request in JSON format.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		logrus.WithFields(logrus.Fields{
			// ECS field names
			"http.request.method": r.Method,
			"url.original":        r.RequestURI,
			"url.path":            r.URL.Path,
			"source.ip":           r.RemoteAddr,
			"event.dataset":       "http.request",
			"event.kind":          "event",
		}).Info("incoming HTTP request")

		start := time.Now()
		next.ServeHTTP(lrw, r)
		elapsed := time.Since(start).Milliseconds()

		logrus.WithFields(logrus.Fields{
			"http.response.status_code": lrw.statusCode,
			"event.dataset":             "http.response",
			"event.kind":                "event",
			"event.duration":            elapsed,
		}).Info("HTTP response sent")
	})
}
