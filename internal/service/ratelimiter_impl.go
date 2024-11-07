package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

type RateLimiter struct {
	client *redis.Client
}

func NewRateLimiter(client *redis.Client) *RateLimiter {
	return &RateLimiter{
		client: client,
	}
}

// IsAllowed checks if the user has exceeded the rate limit based on their unique identifier
func (rl *RateLimiter) IsAllowed(ctx context.Context, identifier string, limit int, period time.Duration) (bool, error) {
	// Create a unique Redis key based on the identifier (e.g., username or IP)
	key := fmt.Sprintf("login_attempts:%s", identifier)

	// Increment the login attempt counter in Redis
	count, err := rl.client.Incr(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("error incrementing Redis counter: %v", err)
	}

	// Set expiration if this is the first attempt
	if count == 1 {
		// Set the expiration time to the limit period (e.g., 1 minute)
		err := rl.client.Expire(ctx, key, period).Err()
		if err != nil {
			return false, fmt.Errorf("error setting expiration on Redis key: %v", err)
		}
	}

	// Check if the attempts exceed the limit
	if count > int64(limit) {
		return false, nil // Block the attempt
	}

	return true, nil // Allow the attempt
}
