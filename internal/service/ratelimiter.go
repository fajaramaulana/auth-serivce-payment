package service

type RateLimiterAuth interface {
	// Allow checks if the request is allowed to proceed
	IsAllowed(identifier string) (bool, error)
}
