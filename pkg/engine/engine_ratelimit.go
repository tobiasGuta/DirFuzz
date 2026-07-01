package engine

import (
	"golang.org/x/time/rate"
)

// SetRPS updates the rate limiter settings dynamically.
func (e *Engine) SetRPS(rps int) {
	var limit rate.Limit
	var burst int
	if rps <= 0 {
		limit = rate.Inf
		burst = e.currentBurst
		if burst < MinRateLimitBurst {
			burst = MinRateLimitBurst
		}
	} else {
		limit = rate.Limit(rps)
		burst = rps
		if burst < MinRateLimitBurst {
			burst = MinRateLimitBurst
		}
	}
	e.limitersLock.Lock()
	e.currentLimit = limit
	e.currentBurst = burst
	for _, l := range e.limiters {
		l.SetLimit(limit)
		l.SetBurst(burst)
	}
	e.limitersLock.Unlock()
}

// UpdateRateLimiterFromDelay updates the rate limiter based on the delay setting.
func (e *Engine) UpdateRateLimiterFromDelay() {
	e.Config.RLock()
	d := e.Config.Delay
	workers := e.Config.MaxWorkers
	e.Config.RUnlock()

	var limit rate.Limit
	var b int
	if d <= 0 {
		limit = rate.Inf
		b = workers
		if b < 10 {
			b = 10
		}
	} else {
		rps := float64(workers) / d.Seconds()
		if rps < 1 {
			rps = 1
		}
		limit = rate.Limit(rps)
		b = workers
	}

	e.limitersLock.Lock()
	e.currentLimit = limit
	e.currentBurst = b
	for _, l := range e.limiters {
		l.SetLimit(limit)
		l.SetBurst(b)
	}
	e.limitersLock.Unlock()
}

func (e *Engine) getLimiter(host string) *rate.Limiter {
	e.limitersLock.RLock()
	l, exists := e.limiters[host]
	e.limitersLock.RUnlock()
	if exists {
		return l
	}

	e.limitersLock.Lock()
	defer e.limitersLock.Unlock()
	if l, exists := e.limiters[host]; exists {
		return l
	}
	newLimiter := rate.NewLimiter(e.currentLimit, e.currentBurst)
	e.limiters[host] = newLimiter
	return newLimiter
}
