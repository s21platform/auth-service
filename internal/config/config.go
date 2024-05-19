package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
)

type Config struct {
	Service Service
	School  School
}

type Service struct {
	Port   string `env:"AUTH_SERVICE_PORT"`
	Secret string `env:"SECRET_KEY"`
}

type School struct {
	Host string `env:"SCHOOL_SERVICE_HOST"`
	Port string `env:"SCHOOL_SERVICE_PORT"`
}

func MustLoad() *Config {
	cfg := &Config{}

	err := cleanenv.ReadEnv(cfg)
	if err != nil {
		log.Fatalf("Can not read env variables: %s", err)
	}
	return cfg
}
