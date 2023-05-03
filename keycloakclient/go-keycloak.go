package keycloakclient

import (
	// Error Handling
	"errors"
	"fmt"

	// REST
	"gopkg.in/resty.v1"

	// Encoding
	b64 "encoding/base64"
	"encoding/json"
)

type KeycloakPermission struct {
	Scopes []string `json:"scopes"`
	RSID   string   `json:"rsid"`
	RSName string   `json:"rsname"`
}
type KeycloakPolicy struct {
	ID               string      `json:"id"`
	Config           interface{} `json:"config"`
	DecisionStrategy string      `json:"decisionStrategy"`
	Description      string      `json:"description"`
	Logic            string      `json:"logic"`
	Name             string      `json:"name"`
	Owner            string      `json:"owner"`
	Policies         []string    `json:"policies"`
	Resources        []string    `json:"resources"`
	Scopes           []string    `json:"scopes"`
	Type             []string    `json:"type"`
}

type KeycloakScope struct {
	ID          string             `json:"id"`
	DisplayName string             `json:"displayName"`
	IconURI     string             `json:"iconUri"`
	Name        string             `json:"name"`
	Policies    []KeycloakPolicy   `json:"policies"`
	Resources   []KeycloakResource `json:"resources"`
}
type UserSessionRepresentation struct {
	ID         string            `json:"id"`
	Username   string            `json:"username"`
	UserID     string            `json:"userId"`
	IPAddress  string            `json:"ipAddress"`
	Start      int64             `json:"start"`
	LastAccess int64             `json:"lastAccess"`
	Clients    map[string]string `json:"clients"`
}
type KeycloakResource struct {
	ID                 string          `json:"id,omitempty"`
	Attributes         interface{}     `json:"attributes,omitempty"`
	DisplayName        string          `json:"displayName,omitempty"`
	IconURI            string          `json:"icon_uri,omitempty"`
	Name               string          `json:"name,omitempty"`
	OwnerManagedAccess bool            `json:"ownerManagedAccess,omitempty"`
	Scopes             []KeycloakScope `json:"scopes,omitempty"`
	Type               string          `json:"type,omitempty"`
	Uris               []string        `json:"uris,omitempty"`
}

type KeycloakBruteForce struct {
	NumFailures   int64  `json:"numFailures"`
	Disabled      bool   `json:"disabled"`
	LastIPFailure string `json:"lastIPFailure"`
	LastFailure   int64  `json:"lastFailure"`
}

func NewKeycloakResource() KeycloakResource {
	var resource KeycloakResource

	resource.Attributes = map[string]string{}
	resource.Scopes = make([]KeycloakScope, 0)
	return resource

}

type ExchangeToken struct {
	State        string `json:"state"`
	SessionState string `json:"session_state"`
	Code         string `json:"code"`
}

/**
 * The OIDCToken holds all info about the token
 */
type OIDCToken struct {
	AccessToken      string
	ExpiresIn        float64
	RefreshExpiresIn float64
	RefreshToken     string
	TokenType        string
	Raw              interface{}
}

/**
 * The keycloak client kind-of class
 */
type KeycloakClient struct {
	Server string
}

/**
 * The Keycloak User Structure
 */
type KeycloakUser struct {
	Id                         string        `json:"id"`
	CreatedTimestamp           int64         `json:"createdTimestamp"`
	Username                   string        `json:"username"`
	Enabled                    bool          `json:"enabled"`
	Totp                       bool          `json:"totp"`
	EmailVerified              bool          `json:"emailVerified"`
	FirstName                  string        `json:"firstName"`
	LastName                   string        `json:"lastName"`
	Email                      string        `json:"email"`
	FederationLink             string        `json:"federationLink"`
	Attributes                 interface{}   `json:"attributes"`
	DisableableCredentialTypes []interface{} `json:"disableableCredentialTypes"`
	RequiredActions            []interface{} `json:"requiredActions"`
	NotBefore                  int64         `json:"notBefore"`
	Access                     struct {
		ManageGroupMembership bool `json:"manageGroupMembership"`
		View                  bool `json:"view"`
		MapRoles              bool `json:"mapRoles"`
		Impersonate           bool `json:"impersonate"`
		Manage                bool `json:"manage"`
	} `json:"access"`
}

/**
 * Keycloak User Groups
 */
type KeycloakUserGroup struct {
	Id   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

/**
 * The Keycloak Group Structure
 */
type KeycloakGroup struct {
	Id        string        `json:"id"`
	Name      string        `json:"name"`
	Path      string        `json:"path"`
	SubGroups []interface{} `json:"subGroups"`
}

/**
 * The Keycloak Role Structure
 */
type KeycloakRole struct {
	Id                 string      `json:"id"`
	Attributes         interface{} `json:"attributes"`
	Name               string      `json:"name"`
	ScopeParamRequired bool        `json:"scopeParamRequired"`
	Composite          bool        `json:"composite"`
	ClientRole         bool        `json:"clientRole"`
	ContainerID        string      `json:"containerId"`
	Description        string      `json:"description,omitempty"`
}

/**
 * Role Mapping for Clients
 */
type ClientRoleMapping struct {
	ID       string                  `json:"id"`
	Client   string                  `json:"client"`
	Mappings []ClientRoleMappingRole `json:"mappings"`
}
type ClientRoleMappingRole struct {
	Id                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description,omitempty"`
	ScopeParamRequired bool   `json:"scopeParamRequired"`
	Composite          bool   `json:"composite"`
	ClientRole         bool   `json:"clientRole"`
	ContainerID        string `json:"containerId"`
}

/**
 * Keycloak Client
 */
type KeycloakRealmClient struct {
	Id       string `json:"id"`
	ClientID string `json:"clientId"`
}

/**
 * Direct Grant Authentication
 * -
 * This method directly gets you the OIDC Token from keycloak to use in your next requests
 */
func (keycloakClient KeycloakClient) DirectGrantAuthentication(clientId string, clientSecret string, realm string, username string, password string) (*OIDCToken, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", getBasicAuthForClient(clientId, clientSecret)).
		SetFormData(map[string]string{
			"grant_type": "password",
			"username":   username,
			"password":   password,
		}).Post(keycloakClient.Server + "/auth/realms/" + realm + "/protocol/openid-connect/token")
	if err != nil {
		return nil, err
	}

	// Here’s the actual decoding, and a check for associated errors.
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	// Check for Result
	if val, ok := result["access_token"]; ok {
		_ = val
		return &OIDCToken{
			AccessToken:      result["access_token"].(string),
			ExpiresIn:        result["expires_in"].(float64),
			RefreshExpiresIn: result["refresh_expires_in"].(float64),
			RefreshToken:     result["refresh_token"].(string),
			TokenType:        result["token_type"].(string),
			Raw:              result,
		}, nil
	}

	return nil, errors.New("Authentication failed")
}

func (keycloakClient KeycloakClient) DirectGrantAuthenticationWithOtp(clientId string, clientSecret string, realm string, username string, password string, otp string, scope string) (*OIDCToken, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", getBasicAuthForClient(clientId, clientSecret)).
		SetFormData(map[string]string{
			"grant_type": "password",
			"username":   username,
			"password":   password,
			"totp":       otp,
			"scope":      scope,
		}).Post(keycloakClient.Server + "/auth/realms/" + realm + "/protocol/openid-connect/token")
	if err != nil {
		return nil, err
	}

	// Here’s the actual decoding, and a check for associated errors.
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	// Check for Result
	if val, ok := result["access_token"]; ok {
		_ = val
		return &OIDCToken{
			AccessToken:      result["access_token"].(string),
			ExpiresIn:        result["expires_in"].(float64),
			RefreshExpiresIn: result["refresh_expires_in"].(float64),
			RefreshToken:     result["refresh_token"].(string),
			TokenType:        result["token_type"].(string),
			Raw:              result,
		}, nil
	}

	return nil, errors.New("Authentication failed")
}

func (keycloakClient KeycloakClient) SignOut(accessToken string, realm string, redirectURI string) bool {
	_, err := resty.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/protocol/openid-connect/logout?redirect_uri=" + redirectURI)
	if err != nil {
		return false
	}
	return true
}

/**
 * Remove Session
 */
func (keycloakClient KeycloakClient) RemoveSession(accessToken string, realm string, sessionID string) (bool, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Delete(keycloakClient.Server + "/auth/admin/realms/" + realm + "/sessions/" + sessionID)
	if err != nil {
		return false, err
	}

	return resp.IsSuccess(), nil
}

/**
 * Get Session By user
 */
func (keycloakClient KeycloakClient) GetSessionsByUser(accessToken string, realm string, userID string) ([]UserSessionRepresentation, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/users/" + userID + "/sessions")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []UserSessionRepresentation
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return result, nil
}

/**
 * User List
 */
func (keycloakClient KeycloakClient) GetUserListInRealm(accessToken string, realm string) (*[]KeycloakUser, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/users?max=10000")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakUser
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Groups of UserId
 */
func (keycloakClient KeycloakClient) GetUserGroupsInRealm(accessToken string, realm string, userId string) (*[]KeycloakUserGroup, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/users/" + userId + "/groups")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakUserGroup
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Group Role Mapping
 */
func (keycloakClient KeycloakClient) GetRoleMappingByGroupId(accessToken string, realm string, groupId string) (*[]ClientRoleMapping, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/groups/" + groupId + "/role-mappings")
	if err != nil {
		return nil, err
	}

	var result []ClientRoleMapping

	// Decode into struct
	var f map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &f); err != nil {
		return nil, err
	}

	// JSON object parses into a map with string keys
	itemsMap := f["clientMappings"].(map[string]interface{})

	// Loop through the Items; we're not interested in the key, just the values
	for _, v := range itemsMap {
		// Use type assertions to ensure that the value's a JSON object
		switch jsonObj := v.(type) {
		// The value is an Item, represented as a generic interface
		case interface{}:
			jsonClientMapping, _ := json.Marshal(jsonObj)
			var client ClientRoleMapping
			if err := json.Unmarshal(jsonClientMapping, &client); err != nil {
				return nil, err
			}
			result = append(result, client)
		default:
			return nil, errors.New("Expecting a JSON object; got something else")
		}
	}

	return &result, nil
}

/**
 * Group List
 */
func (keycloakClient KeycloakClient) GetGroupListByRealm(accessToken string, realm string) (*[]KeycloakGroup, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/groups")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakGroup
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Roles by Realm
 */
func (keycloakClient KeycloakClient) GetClientRolesForUser(accessToken string, realm string, userId string, clientId string) (*[]KeycloakRole, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/users/" + userId + "/role-mappings/clients/" + clientId + "/composite")
	if err != nil {
		return nil, err
	}
	// Decode into struct
	var result []KeycloakRole
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Roles by Realm
 */
func (keycloakClient KeycloakClient) GetRolesByRealm(accessToken string, realm string) (*[]KeycloakRole, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/roles")
	if err != nil {
		return nil, err
	}

	var result []KeycloakRole
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Roles by Client and Realm
 */
func (keycloakClient KeycloakClient) GetRolesByName(accessToken string, realm string, clientId string, roleName string) (*KeycloakRole, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/roles/" + roleName)
	if err != nil {
		return nil, err
	}

	var result KeycloakRole
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Roles by Client and Realm
 */
func (keycloakClient KeycloakClient) GetRolesByClientId(accessToken string, realm string, clientId string) (*[]KeycloakRole, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/roles")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	// Decode into struct
	var result []KeycloakRole
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Clients by Realm
 */
func (keycloakClient KeycloakClient) GetClientsInRealm(accessToken string, realm string) (*[]KeycloakRealmClient, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/clients")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakRealmClient
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Function to build the HttpBasicAuth Base64 String
 */
func getBasicAuthForClient(clientId string, clientSecret string) string {
	var httpBasicAuth string
	if len(clientId) > 0 && len(clientSecret) > 0 {
		httpBasicAuth = b64.URLEncoding.EncodeToString([]byte(clientId + ":" + clientSecret))
	}

	return "Basic " + httpBasicAuth
}

func (keycloakClient KeycloakClient) RefreshAceessToken(refreshToken string, realm string, clientId string, clientSecret string) (*OIDCToken, bool) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetFormData(map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
			"client_id":     clientId,
			"client_secret": clientSecret,
		}).
		Post(keycloakClient.Server + "/auth/realms/" + realm + "/protocol/openid-connect/token")
	if err != nil {
		fmt.Println("Error sending request")
		return nil, false
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, false
	}

	if result["access_token"] == nil {
		return nil, false
	}

	return &OIDCToken{
		AccessToken:      result["access_token"].(string),
		ExpiresIn:        result["expires_in"].(float64),
		RefreshExpiresIn: result["refresh_expires_in"].(float64),
		RefreshToken:     result["refresh_token"].(string),
		TokenType:        result["token_type"].(string),
	}, true
}

func (keycloakClient KeycloakClient) GetPermissions(accessToken string, realm string, clientId string, userId string, resources []KeycloakResource) (interface{}, error) {
	body := map[string]interface{}{
		"resources":    resources,
		"context":      map[string]interface{}{"attributes": map[string]string{}},
		"roleIds":      []int{},
		"userId":       userId,
		"entitlements": false}

	bodyJson, _ := json.Marshal(body)
	resp, err := resty.R().
		SetHeader("Accept", "application/json, text/plain, */*").
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		SetBody(string(bodyJson)).
		Post(keycloakClient.Server + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/authz/resource-server/policy/evaluate")
	if err != nil {
		fmt.Println("Error sending request")
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}
	if _, ok := result["rpt"]; ok {
		rpt := result["rpt"].(map[string]interface{})
		if _, ok = rpt["authorization"]; ok {
			authorization := rpt["authorization"]
			return authorization, nil
		}
	}

	return nil, nil
}

func (keycloakClient KeycloakClient) GetUserDetail(accessToken string, realm string, userID string) (*KeycloakUser, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/users/" + userID)
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result KeycloakUser
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (keycloakClient KeycloakClient) GetUserDetailByUsername(accessToken string, realm string, username string) (*[]KeycloakUser, error) {
	resp, err := resty.R().
		SetQueryParam("username", username).
		SetQueryParam("exact", "true").
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/users")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakUser
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (keycloakClient KeycloakClient) GetUserListByRoleName(accessToken string, realm string, clientUUID string, roleName string) (*[]KeycloakUser, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/clients/" + clientUUID + "/roles/" + roleName + "/users?max=10000")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakUser
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get status of a username in brute force detection
 */
func (keycloakClient KeycloakClient) GetBruteForceInfoByUserID(accessToken string, realm string, userID string) (*KeycloakBruteForce, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/attack-detection/brute-force/users/" + userID)
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result KeycloakBruteForce
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Clear any user login failures for the user This can release temporary disabled user
 */
func (keycloakClient KeycloakClient) ClearUserLoginFailureByUserID(accessToken string, realm string, userID string) (bool, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		Delete(keycloakClient.Server + "/auth/admin/realms/" + realm + "/attack-detection/brute-force/users/" + userID)
	if err != nil {
		return false, err
	}

	return resp.IsSuccess(), nil
}

/**
 * Logout user by refresh token
 */
func (keycloakClient KeycloakClient) LogoutByRefreshToken(refreshToken string, realm string, clientId string, clientSecret string) (bool, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetFormData(map[string]string{
			"refresh_token": refreshToken,
			"client_id":     clientId,
			"client_secret": clientSecret,
		}).
		Post(keycloakClient.Server + "/auth/realms/" + realm + "/protocol/openid-connect/logout")
	if err != nil {
		return false, err
	}

	return resp.IsSuccess(), nil
}

func (keycloakClient KeycloakClient) UpdateUserDetail(accessToken string, realm string, user KeycloakUser) (bool, error) {
	body := map[string]interface{}{
		"firstName":  user.FirstName,
		"lastName":   user.LastName,
		"email":      user.Email,
		"attributes": user.Attributes,
	}
	bodyJson, _ := json.Marshal(body)

	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+accessToken).
		SetBody(string(bodyJson)).
		Put(keycloakClient.Server + "/auth/admin/realms/" + realm + "/users/" + user.Id)
	if err != nil {
		return false, err
	}

	return resp.IsSuccess(), nil
}
