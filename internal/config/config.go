package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

type Config interface {
	Get(key string) string
}

type configImpl struct {
}

func (config *configImpl) Get(key string) string {
	return os.Getenv(key)
}

func New(filenames string) Config {
	fmt.Println("Loading .env file from:", filenames)
	if err := godotenv.Load(filenames); err != nil {
		log.Fatalf("Error loading .env file, %v", err)
	}
	// Initialize your configuration fields from os.Getenv()
	return &configImpl{}
}

func LoadConfiguration() Config {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Error getting working directory: %v", err)
	}

	// Construct the path to the .env file
	envPath := filepath.Join(wd, "../../", ".env")
	configuration := New(envPath)

	return configuration
}
