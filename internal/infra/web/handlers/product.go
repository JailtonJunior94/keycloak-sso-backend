package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jailtonjunior94/keycloak-sso-backend/internal/infra/web/middlewares"
)

type ProductHandler struct {
}

func NewProductHandler() *ProductHandler {
	return &ProductHandler{}
}

func (h *ProductHandler) Products(w http.ResponseWriter, r *http.Request) {
	u := r.Context().Value(middlewares.UserCtxKey).(*middlewares.User)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(u)
}
