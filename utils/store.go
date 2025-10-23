package utils

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

func GenerateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic("failed to generate secure random string: " + err.Error())
	}
	return hex.EncodeToString(bytes)
}

var tempStore = struct {
	sync.RWMutex
	data map[string]storedValue
}{data: make(map[string]storedValue)}

type storedValue struct {
	value     string
	expiresAt time.Time
}

// Save value with TTL
func TempStoreSet(key, value string, ttl time.Duration) {
	tempStore.Lock()
	defer tempStore.Unlock()
	tempStore.data[key] = storedValue{value, time.Now().Add(ttl)}
}

// Get value and delete if expired
func TempStoreGet(key string) string {
	tempStore.Lock()
	defer tempStore.Unlock()
	val, ok := tempStore.data[key]
	if !ok || time.Now().After(val.expiresAt) {
		delete(tempStore.data, key)
		return ""
	}
	return val.value
}

// Optional cleanup goroutine
func init() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			tempStore.Lock()
			for k, v := range tempStore.data {
				if time.Now().After(v.expiresAt) {
					delete(tempStore.data, k)
				}
			}
			tempStore.Unlock()
		}
	}()
}
