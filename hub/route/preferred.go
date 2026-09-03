package route

import (
	"context"
	"encoding/json"
	"net/netip"

	"github.com/metacubex/mihomo/component/preferred"
	"github.com/metacubex/mihomo/component/resolver"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	D "github.com/miekg/dns"
)

func preferredIPRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getPreferredIP)
	r.Get("/verify", getPreferredIPVerify)
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
	found, triggered := preferred.Default.TriggerSpeedTest(req.Name)
	if !found {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("entry not found"))
		return
	}
	if !triggered {
		render.Status(r, http.StatusConflict)
		render.JSON(w, r, newError("a test round is already queued or running"))
		return
	}
	render.NoContent(w, r)
}

// getPreferredIPVerify resolves name (A + AAAA) through the default resolver
// and reports, for each family, the verdict the production rewrite decision
// would produce — the same Match/AnswerPool logic both DNS hooks share
// (docs/adr/0004). The raw exchange result is only the upstream input;
// GET /dns/query's answer bypasses both rewrite hooks and must not be
// presented as the rewrite outcome.
func getPreferredIPVerify(w http.ResponseWriter, r *http.Request) {
	if resolver.DefaultResolver == nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("DNS section is disabled"))
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("missing name"))
		return
	}

	resolve := func(qtype uint16, isV6 bool) preferred.FamilyVerdict {
		query := &D.Msg{}
		query.SetQuestion(D.Fqdn(name), qtype)
		ctx, cancel := context.WithTimeout(r.Context(), resolver.DefaultDNSTimeout)
		defer cancel()
		resp, err := resolver.DefaultResolver.ExchangeContext(ctx, query)
		if err != nil || resp == nil || resp.Rcode != D.RcodeSuccess {
			return preferred.FamilyVerdict{Verdict: preferred.VerdictResolveError}
		}
		return preferred.Default.VerifyFamily(answerIPs(resp, isV6), isV6)
	}

	render.JSON(w, r, render.M{
		"name": name,
		"v4":   resolve(D.TypeA, false),
		"v6":   resolve(D.TypeAAAA, true),
	})
}

// answerIPs extracts the A or AAAA records of one family from a DNS response,
// normalized for range matching.
func answerIPs(msg *D.Msg, isV6 bool) []netip.Addr {
	var ips []netip.Addr
	for _, ans := range msg.Answer {
		var raw netip.Addr
		switch rr := ans.(type) {
		case *D.A:
			if isV6 {
				continue
			}
			raw, _ = netip.AddrFromSlice(rr.A)
		case *D.AAAA:
			if !isV6 {
				continue
			}
			raw, _ = netip.AddrFromSlice(rr.AAAA)
		default:
			continue
		}
		if raw.IsValid() {
			ips = append(ips, raw.Unmap())
		}
	}
	return ips
}
