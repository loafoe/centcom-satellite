package server

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/loafoe/centcom-satellite/internal/config"
)

// ipLimiterEntry pairs a token-bucket limiter with the last time it was
// used, so idle entries can be evicted instead of accumulating forever.
type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// ipRateLimiter tracks one token-bucket limiter per client IP.
type ipRateLimiter struct {
	cfg config.RateLimitConfig

	mu       sync.Mutex
	limiters map[string]*ipLimiterEntry
}

func newIPRateLimiter(cfg config.RateLimitConfig) *ipRateLimiter {
	l := &ipRateLimiter{cfg: cfg, limiters: make(map[string]*ipLimiterEntry)}
	go l.evictLoop()
	return l
}

// evictLoop periodically drops limiters for IPs that haven't been seen
// recently. The set of real callers here is small and mostly fixed (centcom,
// maybe a handful of others), so this is housekeeping against a long-lived
// pod slowly accumulating map entries, not a defense against a large attack
// surface.
func (l *ipRateLimiter) evictLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-10 * time.Minute)
		l.mu.Lock()
		for ip, entry := range l.limiters {
			if entry.lastSeen.Before(cutoff) {
				delete(l.limiters, ip)
			}
		}
		l.mu.Unlock()
	}
}

func (l *ipRateLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.limiters[ip]
	if !ok {
		entry = &ipLimiterEntry{
			limiter: rate.NewLimiter(rate.Limit(l.cfg.RequestsPerSecond), l.cfg.Burst),
		}
		l.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

// clientIP extracts the caller's IP from RemoteAddr — the direct TCP peer —
// rather than X-Forwarded-For, which is attacker-controllable unless a
// trusted proxy strips and overwrites it. This satellite has no such
// guarantee in front of it, so trusting XFF would let a single caller
// spoof unlimited distinct rate-limit buckets and defeat the whole point.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RateLimitMiddleware enforces a per-client-IP token bucket. /healthz and
// /readyz are always exempt, regardless of config, since a throttled
// liveness probe would get the pod killed by kubelet — the opposite of what
// this middleware is for.
//
// On rejection it responds 429 with Retry-After (RFC 9110 §10.2.3) plus the
// RateLimit-Limit/Remaining/Reset headers from the IETF
// draft-ietf-httpapi-ratelimit-headers convention, so callers can implement
// standard backoff instead of guessing or hammering immediately.
func RateLimitMiddleware(cfg config.RateLimitConfig) func(http.Handler) http.Handler {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}

	limiter := newIPRateLimiter(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/healthz", "/readyz":
				next.ServeHTTP(w, r)
				return
			}

			rl := limiter.get(clientIP(r))
			now := time.Now()
			reservation := rl.ReserveN(now, 1)
			if !reservation.OK() {
				// Only possible if Burst < 1, which Validate() rejects at
				// startup — fail open rather than block all traffic on a
				// config bug that shouldn't reach here.
				next.ServeHTTP(w, r)
				return
			}

			if delay := reservation.DelayFrom(now); delay > 0 {
				reservation.Cancel()
				retrySeconds := int(delay.Seconds()) + 1

				w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
				w.Header().Set("RateLimit-Limit", strconv.Itoa(cfg.Burst))
				w.Header().Set("RateLimit-Remaining", "0")
				w.Header().Set("RateLimit-Reset", strconv.Itoa(retrySeconds))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprintf(w, `{"error":"rate limit exceeded","retry_after_seconds":%d}`, retrySeconds)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
