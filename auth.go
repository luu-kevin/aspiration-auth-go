package auth

import (
	"context"
	"database/sql"
	"errors"

	_auth "github.com/AspirationPartners/kit/auth"
	"github.com/jmoiron/sqlx"
)

type Queryer interface {
	Get(dest interface{}, query string, args ...interface{}) error
	QueryRowx(query string, args ...interface{}) *sqlx.Row
	QueryRow(query string, args ...interface{}) *sql.Row
	Select(dest interface{}, query string, args ...interface{}) error
	PrepareNamed(query string) (*sqlx.NamedStmt, error)
	NamedQuery(query string, arg interface{}) (*sqlx.Rows, error)
	NamedExec(query string, arg interface{}) (sql.Result, error)
	Exec(query string, args ...interface{}) (sql.Result, error)
}

// TODO : REMOVE THIS INTO ITS OWN INDIVIDUAL PKG
//light wrapper around auth kit package
type AuthService struct {
	DB      Datastore
	enabled bool
}
type Datastore interface {
	Queryer
	UserAccountValidation(q Queryer, userID, accountID int64) error
	UserDepositoryValidation(q Queryer, userID, depositoryID int64) error
}

// ErrNotAuthenticated is when user is not authenticated
var ErrNotAuthenticated = errors.New("Request Not Authenticated")

// ErrForbidden is for when user tries to perform an atcion they don't have permission to
var ErrForbidden = errors.New("Action Forbidden")

// IsAuthenticated is quick auth check. Returns true if user is logged in, else false
func (as *AuthService) IsAuthenticated(ctx context.Context) bool {
	if !as.enabled {
		return true
	}
	return (_auth.ExtractUserFromContext(ctx) != nil)
}

// DepositoryAuthorization does a userId/Depository check to enforce user ownership.
// if user is not logged in, it will return ErrNotAuthenticated
// if depository does not belong to user, it will return ErrForbidden
func (as *AuthService) DepositoryAuthorization(ctx context.Context, depositoryID int64) error {
	if !as.enabled {
		return nil
	}
	if u := as.GetUser(ctx); u != nil {
		if err := as.DB.UserDepositoryValidation(as.DB, u.UserId, depositoryID); err != nil {
			return ErrForbidden
		}
		return nil
	}
	return ErrNotAuthenticated
}

// AccountAuthorization does a userId/Account check to enforce user ownership.
// if user is not logged in, it will return ErrNotAuthenticated
// if account does not belong to user, it will return ErrForbidden
func (as *AuthService) AccountAuthorization(ctx context.Context, accountID int64) error {
	if !as.enabled {
		return nil
	}
	if u := as.GetUser(ctx); u != nil {
		if err := as.DB.UserAccountValidation(as.DB, u.UserId, accountID); err != nil {
			return ErrForbidden
		}
		return nil
	}
	return ErrNotAuthenticated
}

// GetUser retrieves user from context if user is logged in; else nil
func (as *AuthService) GetUser(ctx context.Context) *_auth.AspirationUser {
	return _auth.ExtractUserFromContext(ctx)
}

func (as *AuthService) SetEnable(b bool) {
	as.enabled = b
}

func NewAuthService(DB Datastore) *AuthService {
	return &AuthService{
		DB:      DB,
		enabled: true,
	}
}
