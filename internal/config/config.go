package config

import (
	"log"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Service      Service
	School       School
	Community    Community
	User         User
	Notification Notification
	Postgres     Postgres
	Kafka        Kafka
	Platform     Platform
	Metrics      Metrics
	Logger       Logger
}

type Service struct {
	Port          string `env:"AUTH_SERVICE_PORT"`
	Secret        string `env:"SECRET_KEY"`
	AccessSecret  string `env:"ACCESS_SECRET"`
	RefreshSecret string `env:"REFRESH_SECRET"`
	Name          string `env:"AUTH_SERVICE_NAME"`
}

type Postgres struct {
	User     string `env:"AUTH_SERVICE_POSTGRES_USER"`
	Password string `env:"AUTH_SERVICE_POSTGRES_PASSWORD"`
	Database string `env:"AUTH_SERVICE_POSTGRES_DB"`
	Host     string `env:"AUTH_SERVICE_POSTGRES_HOST"`
	Port     string `env:"AUTH_SERVICE_POSTGRES_PORT"`
}

type Kafka struct {
	Host  string `env:"KAFKA_HOST"`
	Port  string `env:"KAFKA_PORT"`
	Topic string `env:"USER_REGISTER"`
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

type Notification struct {
	Host string `env:"NOTIFICATION_SERVICE_HOST"`
	Port string `env:"NOTIFICATION_SERVICE_PORT"`
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

func MustLoad() *Config {
	cfg := &Config{}
	err := cleanenv.ReadEnv(cfg)

	if err != nil {
		log.Fatalf("failed to read env variables: %s", err)
	}

	return cfg
}
