package bundle

import (
	"github.com/jailtonjunior94/keycloak-sso-backend/configs"
	"github.com/jailtonjunior94/keycloak-sso-backend/internal/infra/web/handlers"
	"github.com/jailtonjunior94/keycloak-sso-backend/internal/infra/web/middlewares"
)

type container struct {
	Config         *configs.Config
	Authorization  middlewares.Authorization
	ProductHandler *handlers.ProductHandler
}

func NewContainer() *container {
	config, err := configs.LoadConfig(".")
	if err != nil {
		panic(err)
	}

	authorization := middlewares.NewAuthorization(config)
	productHandler := handlers.NewProductHandler()

	return &container{
		Config:         config,
		Authorization:  authorization,
		ProductHandler: productHandler,
	}
}
