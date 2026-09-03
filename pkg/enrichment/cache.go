package enrichment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// DiskCache provides simple file-based JSON caching with a TTL check.
type DiskCache struct {
	dir string
}

func NewDiskCache(dir string) (*DiskCache, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &DiskCache{dir: dir}, nil
}

// Read checks if the cached key exists and is still within TTL.
func (c *DiskCache) Read(key string, ttl time.Duration, target any) bool {
	filePath := filepath.Join(c.dir, key+".json")
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	// Drop cache if file is older than TTL
	if time.Since(info.ModTime()) > ttl {
		return false
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	return json.Unmarshal(data, target) == nil
}

// Write dumps the value as JSON to disk.
func (c *DiskCache) Write(key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	filePath := filepath.Join(c.dir, key+".json")
	return os.WriteFile(filePath, data, 0644)
}
