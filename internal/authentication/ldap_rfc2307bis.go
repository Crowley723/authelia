package authentication

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

const (
	rfc2307bisLDAPAttributeSurname = "sn"
)

func (p *LDAPUserProvider) getRFC2307bisRequiredFields() []string {
	return []string{
		"Username",
		"Password",
		"CommonName",
		"FamilyName",
	}
}

func (p *LDAPUserProvider) getRFC2307bisSupportedFields() []string {
	return []string{
		"Username",
		"Password",
		"CommonName",
		"GivenName",
		"FamilyName",
		"Email",
		"Emails",
		"Groups",
		"DN",
		"ObjectClass",
		"Extended",
	}
}

func (p *LDAPUserProvider) getRFC2307bisDefaultObjectClasses() []string {
	return []string{
		"top",
		"person",
		"organizationalPerson",
		"inetOrgPerson",
	}
}

// validateRFC2307bisUserData checks that the fields required to create a user are present and follow the proper patterns.
func (p *LDAPUserProvider) validateRFC2307bisUserData(userData *NewUserData) error {
	//TODO: implement input validation using regex.
	if userData.Username == "" {
		return fmt.Errorf("username required")
	}
	if userData.Password == "" {
		return fmt.Errorf("password required")
	}
	if userData.CommonName == "" {
		// Try to build it from other fields
		if userData.DisplayName != "" {
			userData.CommonName = userData.DisplayName
		} else if userData.GivenName != "" && userData.FamilyName != "" {
			userData.CommonName = userData.GivenName + " " + userData.FamilyName
		} else {
			return fmt.Errorf("commonName (cn) required for RFC2307bis")
		}
	}
	if userData.FamilyName == "" {
		return fmt.Errorf("familyName (sn) required for RFC2307bis")
	}
	return nil
}

func (p *LDAPUserProvider) createRFC2307bisAddRequest(userData *NewUserData) (*ldap.AddRequest, error) {
	userDN := fmt.Sprintf("%s=%s,%s", p.config.Attributes.Username, ldap.EscapeFilter(userData.Username), p.usersBaseDN)
	addRequest := ldap.NewAddRequest(userDN, nil)

	addRequest.Attribute("objectClass", p.getRFC2307bisDefaultObjectClasses())
	//TODO: allow custom object classes to be define in ldap config (as list).
	//addRequest.Attribute("objectClass", p.config.Attributes.RequiredObjectClasses)

	addRequest.Attribute(p.config.Attributes.Username, []string{userData.Username})
	addRequest.Attribute(p.config.Attributes.DisplayName, []string{userData.CommonName})
	addRequest.Attribute(p.config.Attributes.FamilyName, []string{userData.FamilyName})
	addRequest.Attribute(ldapAttributeUserPassword, []string{userData.Password})

	// Optional attributes
	if userData.GivenName != "" {
		givenNameAttr := p.config.Attributes.GivenName
		if p.config.Attributes.GivenName == "" {
			givenNameAttr = "givenName"
		}
		addRequest.Attribute(givenNameAttr, []string{userData.GivenName})
	}

	if userData.GivenName != "" {
		mailAttr := p.config.Attributes.Mail
		if p.config.Attributes.Mail == "" {
			mailAttr = "mail"
		}
		addRequest.Attribute(mailAttr, []string{userData.Email})
	}

	return addRequest, nil
}
