package main

import (
	"encoding/json"
	"fmt"


	kc "./keycloakclient"
)

func main() {
	clientName := "pending"
	clientID := "3784e292-512c-4c89-af8c-695358af1ce8"
	clientSecret := "4be83804-0e98-40c9-88ae-64889c7ec589"
	userID := "36e2a9ff-15b4-4bf6-b138-ebef93fe6dcf"
	realm := "production"
	userName := "bank"
	password := "gfkgvkgft"
	keycloak := kc.KeycloakClient{Server: "http://10.45.128.204"}
	var err error
	token, err := keycloak.DirectGrantAuthentication(clientName, clientSecret, realm, userName, password)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(token.AccessToken)
	fmt.Println()

	lists, err := keycloak.GetUserListInRealm(token.AccessToken, realm)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(lists)
	fmt.Println()

	roles, err := keycloak.GetRolesByClientId(token.AccessToken, realm, clientID)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(roles)
	fmt.Println()

	userRoles, err := keycloak.GetClientRolesForUser(token.AccessToken, realm, userID, clientID)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(userRoles)
	fmt.Println()

	resources := make([]kc.KeycloakResource, 0)
	resource := kc.NewKeycloakResource()
	resource.Type = "urn:pending:resources:default"
	resources = append(resources, resource)
	result, _ := keycloak.GetPermissions(token.AccessToken, realm, clientID, userID, resources)
	jsonResult, _ := json.Marshal(result)
	fmt.Println(string(jsonResult))
	sessions, err := keycloak.GetSessionsByUser(token.AccessToken, realm, userID)
	fmt.Println(sessions)
	res, err := keycloak.RemoveSession(token.AccessToken, realm, sessions[0].ID)
	fmt.Println(res)
}
