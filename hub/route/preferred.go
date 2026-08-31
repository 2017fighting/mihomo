package route

import (
	"encoding/json"

	"github.com/metacubex/mihomo/component/preferred"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func preferredIPRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getPreferredIP)
	r.Post("/speedtest", triggerPreferredIPSpeedTest)
	return r
}

// getPreferredIP returns every entry with its current pools.
func getPreferredIP(w http.ResponseWriter, r *http.Request) {
	status := preferred.Default.Status()
	if status == nil {
		status = []preferred.EntryStatus{}
	}
	render.JSON(w, r, status)
}

type preferredIPTestRequest struct {
	Name string `json:"name"`
}

// triggerPreferredIPSpeedTest nudges one entry (or all when name is empty)
// into an immediate retest round; the round itself runs asynchronously.
func triggerPreferredIPSpeedTest(w http.ResponseWriter, r *http.Request) {
	req := preferredIPTestRequest{}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("invalid request body"))
			return
		}
	}
	if !preferred.Default.TriggerSpeedTest(req.Name) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("entry not found or a test round is already queued"))
		return
	}
	render.NoContent(w, r)
}
