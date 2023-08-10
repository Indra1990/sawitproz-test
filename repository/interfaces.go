// This file contains the interfaces for the repository layer.
// The repository layer is responsible for interacting with the database.
// For testing purpose we will generate mock implementations of these
// interfaces using mockgen. See the Makefile for more information.
package repository

import "context"

type RepositoryInterface interface {
	GetTestById(ctx context.Context, input GetTestByIdInput) (output GetTestByIdOutput, err error)
	CreateUser(ctx context.Context, data map[string]string) (id int, err error)
	FindUserByPhoneNumber(ctx context.Context, phoneNumber string) (user map[string]interface{}, err error)
	FindUserByUserId(ctx context.Context, userId string) (user map[string]interface{}, err error)
	UpdateUser(data map[string]string) (id int, err error)
}
