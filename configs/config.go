package configs

import (
	"github.com/spf13/viper"
)

type Config struct {
	HttpServerPort    string `mapstructure:"HTTP_SERVER_PORT"`
	KeycloakPublicKey string `mapstructure:"KEYCLOAK_PUBLIC_KEY"`
}

func LoadConfig(path string) (*Config, error) {
	var cfg *Config

	viper.AddConfigPath(path)
	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	err = viper.Unmarshal(&cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
