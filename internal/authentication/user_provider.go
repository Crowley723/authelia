package authentication

import (
	"github.com/authelia/authelia/v4/internal/model"
)

// UserProvider is the interface for interacting with the authentication backends.
// UserProvider is the interface for interacting with the authentication backends.
type UserProvider interface {
	model.StartupCheck

	// CheckUserPassword is used to check if a password matches for a specific user.
	CheckUserPassword(username string, password string) (valid bool, err error)

	// GetDetails is used to get a user's information.
	GetDetails(username string) (details *UserDetails, err error)

	GetDetailsExtended(username string) (details *UserDetailsExtended, err error)

	// UpdatePassword is used to change a user's password without verifying their old password.
	UpdatePassword(username string, newPassword string) (err error)

	// ChangePassword is used to change a user's password but requires their old password to be successfully verified.
	ChangePassword(username string, oldPassword string, newPassword string) (err error)

	GetUser(username string) (details *UserDetails, err error)

	ListUsers() (userList []UserDetails, err error)

	UpdateUser(username string, opts ...func(options *ModifyUserDetailsOpts)) (err error)

	AddUser(userData *NewUserData) (err error)

	DeleteUser(username string) (err error)

	GetRequiredFields() []string
	GetSupportedFields() []string
	ValidateUserData(userData *NewUserData) error

	Close() (err error)
}
