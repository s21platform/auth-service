package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
)

type Config struct {
	Service   Service
	School    School
	Community Community
	User      User
}

type Service struct {
	Port   string `env:"AUTH_SERVICE_PORT"`
	Secret string `env:"SECRET_KEY"`
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
