package handler

type LoginRequest struct {
	PhoneNumber string `json:"phoneNumber" validate:"required,numeric"`
	Password    string `json:"password" validate:"required"`
}

type UpdateRequest struct {
	PhoneNumber string `json:"phoneNumber" validate:"required,numeric"`
	FullName    string `json:"fullName" validate:"required,gte=3,lte=60"`
}

type RegisterRequest struct {
	FullName    string `json:"fullName" validate:"required,gte=3,lte=60"`
	PhoneNumber string `json:"phoneNumber" validate:"required,gte=10,lte=13,numeric"`
	Password    string `json:"password" validate:"required,gte=6,lte=64"`
}
