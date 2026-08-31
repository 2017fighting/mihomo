package dns

import (
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/preferred"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

type (
	handler    func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error)
	middleware func(next handler) handler
)

func withHosts(mapping *lru.LruCache[netip.Addr, string]) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			if !isIPRequest(q) {
				return next(ctx, r)
			}

			host := strings.TrimRight(q.Name, ".")
			handleCName := func(resp *D.Msg, domain string) {
				rr := &D.CNAME{}
				rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 10}
				rr.Target = domain + "."
				resp.Answer = append([]D.RR{rr}, resp.Answer...)
			}
			record, ok := resolver.DefaultHosts.Search(host, q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA)
			if !ok {
				if record != nil && record.IsDomain {
					// replace request domain
					newR := r.Copy()
					newR.Question[0].Name = record.Domain + "."
					resp, err := next(ctx, newR)
					if err == nil {
						resp.Id = r.Id
						resp.Question = r.Question
						handleCName(resp, record.Domain)
					}
					return resp, err
				}
				return next(ctx, r)
			}

			msg := r.Copy()
			handleIPs := func() {
				for _, ipAddr := range record.IPs {
					if ipAddr.Is4() && q.Qtype == D.TypeA {
						rr := &D.A{}
						rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 10}
						rr.A = ipAddr.AsSlice()
						msg.Answer = append(msg.Answer, rr)
						if mapping != nil {
							mapping.SetWithExpire(ipAddr, host, time.Now().Add(time.Second*10))
						}
					} else if ipAddr.Is6() && q.Qtype == D.TypeAAAA {
						rr := &D.AAAA{}
						rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 10}
						rr.AAAA = ipAddr.AsSlice()
						msg.Answer = append(msg.Answer, rr)
						if mapping != nil {
							mapping.SetWithExpire(ipAddr, host, time.Now().Add(time.Second*10))
						}
					}
				}
			}

			switch q.Qtype {
			case D.TypeA:
				handleIPs()
			case D.TypeAAAA:
				handleIPs()
			case D.TypeCNAME:
				handleCName(msg, record.Domain)
			default:
				return next(ctx, r)
			}

			ctx.SetType(icontext.DNSTypeHost)
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true
			return msg, nil
		}
	}
}

func withMapping(mapping *lru.LruCache[netip.Addr, string]) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			if !isIPRequest(q) {
				return next(ctx, r)
			}

			msg, err := next(ctx, r)
			if err != nil {
				return nil, err
			}

			host := strings.TrimRight(q.Name, ".")

			for _, ans := range msg.Answer {
				var ip netip.Addr
				var ttl uint32

				switch a := ans.(type) {
				case *D.A:
					ip, _ = netip.AddrFromSlice(a.A)
					ttl = a.Hdr.Ttl
				case *D.AAAA:
					ip, _ = netip.AddrFromSlice(a.AAAA)
					ttl = a.Hdr.Ttl
				default:
					continue
				}
				if !ip.IsValid() {
					continue
				}
				if !ip.IsGlobalUnicast() {
					continue
				}
				ip = ip.Unmap()

				if ttl < 1 {
					ttl = 1
				}

				mapping.SetWithExpire(ip, host, time.Now().Add(time.Second*time.Duration(ttl)))
			}

			return msg, nil
		}
	}
}

func withFakeIP(skipper *fakeip.Skipper, fakePool *fakeip.Pool, fakePool6 *fakeip.Pool, fakeIPTTL int) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			host := strings.TrimRight(q.Name, ".")
			if skipper.ShouldSkipped(host) {
				return next(ctx, r)
			}

			var rr D.RR
			switch q.Qtype {
			case D.TypeA:
				if fakePool == nil {
					return handleMsgWithEmptyAnswer(r), nil
				}
				ip := fakePool.Lookup(host)
				rr = &D.A{
					Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: dnsDefaultTTL},
					A:   ip.AsSlice(),
				}
			case D.TypeAAAA:
				if fakePool6 == nil {
					return handleMsgWithEmptyAnswer(r), nil
				}
				ip := fakePool6.Lookup(host)
				rr = &D.AAAA{
					Hdr:  D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: dnsDefaultTTL},
					AAAA: ip.AsSlice(),
				}
			case D.TypeSVCB, D.TypeHTTPS:
				return handleMsgWithEmptyAnswer(r), nil
			default:
				return next(ctx, r)
			}

			msg := r.Copy()
			msg.Answer = []D.RR{rr}

			ctx.SetType(icontext.DNSTypeFakeIP)
			setMsgTTL(msg, uint32(fakeIPTTL))
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true

			return msg, nil
		}
	}
}

// withPreferredIP rewrites upstream answers whose records fall inside a
// configured preferred-ip range set. Runs INSIDE withMapping (compose folds
// right-to-left, and withMapping was appended first): the mapping table must
// record the REWRITTEN IP -> host so redir-host/TUN DIRECT connections keep
// hitting DOMAIN rules (see docs/adr/0001). Pool not ready -> passthrough.
func withPreferredIP(next handler) handler {
	return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
		q := r.Question[0]
		if q.Qclass != D.ClassINET || (q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA) {
			return next(ctx, r)
		}

		msg, err := next(ctx, r)
		if err != nil || msg == nil {
			return msg, err
		}

		mgr := preferred.Default
		isV6 := q.Qtype == D.TypeAAAA
		entry := mgr.Match(msgToIP(msg), isV6)
		if entry == nil {
			return msg, nil
		}
		if isV6 && entry.BlockIPv6() {
			log.Debugln("[DNS Server] preferred-ip[%s] blocked AAAA for %s", entry.Name(), q.Name)
			return handleMsgWithEmptyAnswer(r), nil
		}
		pool := entry.AnswerPool(isV6)
		if len(pool) == 0 { // pool not ready: passthrough
			log.Debugln("[DNS Server] preferred-ip[%s] pool not ready, passthrough %s", entry.Name(), q.Name)
			return msg, nil
		}

		msg = msg.Copy() // cache holds the original; rewrite only the copy we serve
		ttl := entry.TTLCap()
		answers := make([]D.RR, 0, len(msg.Answer)+len(pool))
		for _, ans := range msg.Answer {
			switch ans.(type) {
			case *D.A, *D.AAAA:
				continue // drop records of the rewritten family, keep CNAME et al.
			}
			answers = append(answers, ans)
		}
		for _, ip := range pool {
			if isV6 {
				answers = append(answers, &D.AAAA{
					Hdr:  D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: ttl},
					AAAA: ip.AsSlice(),
				})
			} else {
				answers = append(answers, &D.A{
					Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: ttl},
					A:   ip.AsSlice(),
				})
			}
		}
		msg.Answer = answers
		msg.Authoritative = true
		return msg, nil
	}
}

func withResolver(resolver resolver.Resolver, ipv6 bool) handler {
	return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
		ctx.SetType(icontext.DNSTypeRaw)

		q := r.Question[0]

		// return a empty AAAA msg when ipv6 disabled
		if !ipv6 && q.Qtype == D.TypeAAAA {
			return handleMsgWithEmptyAnswer(r), nil
		}

		msg, err := resolver.ExchangeContext(ctx, r)
		if err != nil {
			log.Debugln("[DNS Server] Exchange %s failed: %v", q.String(), err)
			return msg, err
		}
		msg.SetRcode(r, msg.Rcode)
		msg.Authoritative = true

		return msg, nil
	}
}

func compose(middlewares []middleware, endpoint handler) handler {
	length := len(middlewares)
	h := endpoint
	for i := length - 1; i >= 0; i-- {
		middleware := middlewares[i]
		h = middleware(h)
	}

	return h
}

func newHandler(resolver resolver.Resolver, mapper *ResolverEnhancer) handler {
	var middlewares []middleware

	if mapper.useHosts {
		middlewares = append(middlewares, withHosts(mapper.mapping))
	}

	if mapper.mode == C.DNSFakeIP {
		middlewares = append(middlewares, withFakeIP(mapper.fakeIPSkipper, mapper.fakeIPPool, mapper.fakeIPPool6, mapper.fakeIPTTL))
	}

	if mapper.mode != C.DNSNormal {
		middlewares = append(middlewares, withMapping(mapper.mapping))
	}

	// preferred-ip rewrite runs innermost (closest to the resolver) so that
	// withMapping — when present — records rewritten IPs; in normal mode it is
	// still the last step before the resolver. See docs/adr/0001.
	middlewares = append(middlewares, withPreferredIP)

	return compose(middlewares, withResolver(resolver, mapper.ipv6))
}
