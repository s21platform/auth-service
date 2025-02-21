package config

import (
	"log"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Service   Service
	School    School
	Community Community
	User      User
	Platform  Platform
	Metrics   Metrics
	Logger    Logger
}

type Service struct {
	Port   string `env:"AUTH_SERVICE_PORT"`
	Secret string `env:"SECRET_KEY"`
	Name   string `env:"AUTH_SERVICE_NAME"`
}

type Community struct {
	Host string `env:"COMMUNITY_SERVICE_HOST"`
	Port string `env:"COMMUNITY_SERVICE_PORT"`
}

type School struct {
	Host string `env:"SCHOOL_SERVICE_HOST"`
	Port string `env:"SCHOOL_SERVICE_PORT"`
}

type User struct {
	Host string `env:"USER_SERVICE_HOST"`
	Port string `env:"USER_SERVICE_PORT"`
}

type Metrics struct {
	Host string `env:"GRAFANA_HOST"`
	Port int    `env:"GRAFANA_PORT"`
}

type Logger struct {
	Host string `env:"LOGGER_SERVICE_HOST"`
	Port string `env:"LOGGER_SERVICE_PORT"`
}

type Platform struct {
	Env string `env:"ENV"`
}

type Cache struct {
}

func MustLoad() *Config {
	cfg := &Config{}

	err := cleanenv.ReadEnv(cfg)
	if err != nil {
		log.Fatalf("Can not read env variables: %s", err)
	}
	return cfg
}
