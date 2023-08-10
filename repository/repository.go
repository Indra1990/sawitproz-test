// This file contains the repository implementation layer.
package repository

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Repository struct {
	Db *sql.DB
}

type NewRepositoryOptions struct {
	Dsn string
}

func NewRepository(opts NewRepositoryOptions) *Repository {
	db, err := sql.Open("postgres", opts.Dsn)
	if err != nil {
		panic(err)
	}
	return &Repository{
		Db: db,
	}
}

func (r *Repository) CreateUser(ctx context.Context, data map[string]string) (id int, err error) {
	sqlStatement := `INSERT INTO users (phone_number,full_name,password) VALUES ($1, $2, $3) RETURNING id`
	err = r.Db.QueryRow(sqlStatement, data["phoneNumber"], data["fullName"], data["password"]).Scan(&id)
	if err != nil {
		return
	}

	return
}

func (r *Repository) UpdateUser(data map[string]string) (id int, err error) {
	sqlStatement := `UPDATE users SET full_name = $2, phone_number = $3 WHERE id = $1 RETURNING id;`
	err = r.Db.QueryRow(sqlStatement, data["userId"], data["fullName"], data["phoneNumber"]).Scan(&id)
	if err != nil {
		return
	}
	return
}

func (r *Repository) FindUserByUserId(ctx context.Context, userId string) (user map[string]interface{}, err error) {
	var iduser string
	var phoneNum string
	var fullName string

	findUser := fmt.Sprintf(`SELECT id, full_name, phone_number FROM users WHERE id = '%s';`, userId)
	queryErr := r.Db.QueryRowContext(ctx, findUser).
		Scan(&iduser, &fullName, &phoneNum)
	if queryErr != nil {
		err = queryErr
		return
	}

	if queryErr == sql.ErrNoRows {
		err = sql.ErrNoRows
		return
	}

	user = map[string]interface{}{
		"userId":      iduser,
		"fullName":    fullName,
		"phoneNumber": phoneNum,
	}

	return
}

func (r *Repository) FindUserByPhoneNumber(ctx context.Context, phoneNumber string) (user map[string]interface{}, err error) {
	var iduser string
	var phoneNum string
	var password string
	var fullName string

	findUser := fmt.Sprintf(`SELECT id, full_name, phone_number, password FROM users WHERE phone_number = '%s';`, phoneNumber)
	queryErr := r.Db.QueryRowContext(ctx, findUser).
		Scan(&iduser, &fullName, &phoneNum, &password)
	if queryErr != nil {
		err = queryErr
		return
	}

	if queryErr == sql.ErrNoRows {
		err = sql.ErrNoRows
		return
	}

	user = map[string]interface{}{
		"userId":      iduser,
		"fullName":    fullName,
		"phoneNumber": phoneNum,
		"password":    password,
	}

	return
}
