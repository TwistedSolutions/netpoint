package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"twistedsolutions.se/netpoint/api"
	"twistedsolutions.se/netpoint/middleware"
)

type ecsVersionHook struct{}

func (h *ecsVersionHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *ecsVersionHook) Fire(entry *logrus.Entry) error {
	entry.Data["ecs.version"] = "9.0.0"
	return nil
}

func main() {

	// Configure logrus to output JSON logs.
	logrus.SetFormatter(&logrus.JSONFormatter{
		DisableHTMLEscape: true,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyMsg:   "message",
			logrus.FieldKeyLevel: "log.level",
			logrus.FieldKeyTime:  "@timestamp",
		},
	})
	logrus.AddHook(&ecsVersionHook{})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	r := mux.NewRouter()
	r.HandleFunc("/networkpolicies", func(w http.ResponseWriter, r *http.Request) {
		// Read the "view" query parameter.
		view := r.URL.Query().Get("view")
		filterNamespace := r.URL.Query().Get("namespace")
		filterName := r.URL.Query().Get("name")
		providedCIDRs := r.URL.Query().Get("cidrs")
		data, err := api.GetNetworkPolicyEgressCIDRs(view, filterNamespace, filterName, providedCIDRs)
		if err != nil {
			logrus.Errorf("Failed to get network policies: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(data))
	}).Methods("GET")

	r.Use(middleware.LoggingMiddleware)

	// Create an HTTP server.
	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	// Channel to listen for interrupt or terminate signals.
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the server in a separate goroutine.
	go func() {
		logrus.Info("Starting server on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("Server failed: %v", err)
		}
	}()

	// Block until we receive a signal.
	<-stopChan
	logrus.Info("Shutdown signal received, shutting down gracefully...")

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Attempt a graceful shutdown.
	if err := server.Shutdown(ctx); err != nil {
		logrus.Fatalf("Server forced to shutdown: %v", err)
	}

	logrus.Info("Server exiting")

}
