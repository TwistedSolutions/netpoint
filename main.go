package main

import (
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"twistedsolutions.se/netpoint/api"
	"twistedsolutions.se/netpoint/middleware"
)

func main() {

	// Configure logrus to output JSON logs.
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	r := mux.NewRouter()
	r.HandleFunc("/networkpolicies", func(w http.ResponseWriter, r *http.Request) {
		// Read the "view" query parameter.
		view := r.URL.Query().Get("view")
		filterNamespace := r.URL.Query().Get("namespace")
		filterName := r.URL.Query().Get("name")
		data, err := api.GetNetworkPolicyEgressCIDRs(view, filterNamespace, filterName)
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

	logrus.Info("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		logrus.Fatalf("Server failed to start: %v", err)
	}

}
