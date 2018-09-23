package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/buger/jsonparser"
	"github.com/fatih/color"
	"gopkg.in/AlecAivazis/survey.v1"
)

func main() {
	args := os.Args[1:]

	if len(args) < 2 {
		color.White(
			`USAGE: bulk-platform-dump <ORG_ID> <TOKEN>
	ORG_ID: CoreService ID for the organization
	TOKEN: Authorization admin token`)
		return
	}

	orgID := args[0]
	token := args[1]
	color.HiYellow("\nDumping organization " + orgID)
	if isValidToken(token) {
		info := []string{}
		prompt := &survey.MultiSelect{
			Message: "Information to download:",
			Options: []string{"Organization", "Apps and Environments", "Users and Roles", "VPC/VPN", "Runtime Fabric", "Audit Log", "MQ"},
			Default: []string{"Organization", "Apps and Environments", "Users and Roles", "VPC/VPN", "Runtime Fabric", "Audit Log", "MQ"},
		}
		err := survey.AskOne(prompt, &info, nil)

		if err != nil {
			fmt.Println(err.Error())
			return
		}

		now := time.Now()
		secsTimestamp := strconv.FormatInt(now.Unix(), 10)
		workingFolder := "dump_" + string(secsTimestamp) + "_" + orgID
		os.MkdirAll(workingFolder, os.ModePerm)

		for _, opt := range info {
			switch opt {
			case "Organization":
				extractCoreServicesOrganizationInformation(orgID, token, workingFolder)
				extractCloudhubOrganizationInformation(orgID, token, workingFolder)
			case "Apps and Environments":
				extractApplications(orgID, token, workingFolder)
			case "Users and Roles":
				extractUsersMembers(orgID, token, workingFolder)
				extractUsersRolegroups(orgID, token, workingFolder)
			case "VPC/VPN":
				extractVPCs(orgID, token, workingFolder)
			case "Runtime Fabric":
				extractRuntimeFabrics(orgID, token, workingFolder)
			case "Audit Log":
				extractAudit(orgID, token, workingFolder, now)
			case "MQ":
				extractMQ(orgID, token, workingFolder)
			}
		}
	} else {
		color.Red("Token invalid.")
	}
}

// Environments
// https://anypoint.mulesoft.com/accounts/api/organizations/24d08578-431e-4b0e-a4d1-40219f5f2d27/environments
func extractMQ(orgID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/accounts/api/organizations/" + orgID + "/environments"
	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "mq_environments", bodyBytes)
		jsonparser.ArrayEach(bodyBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			envID, _ := jsonparser.GetString(value, "id")
			extractMQRegions(orgID, envID, token, workingFolder)
		}, "data")
	}
}

// MQ
// curl -H "Authorization: Bearer b49e6b68-997b-45d5-9ab3-67c5069d56b0" https://anypoint.mulesoft.com/mq/admin/api/v1/organizations/606cdb62-c787-47de-9d6c-baf243de7015/environments/8423a10f-0484-4805-9275-9fa2f7fb27ac/regions/us-east-1/destinations
func extractMQRegions(orgID, envID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/mq/admin/api/v1/organizations/" + orgID + "/environments/" + envID + "/regions"
	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "mq_"+envID+"_regions", bodyBytes)
		jsonparser.ArrayEach(bodyBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			regionID, _ := jsonparser.GetString(value, "regionId")
			extractMQDestinations(orgID, envID, regionID, token, workingFolder)
		})
	}
}

// MQ Destinations
func extractMQDestinations(orgID, envID, regionID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/mq/admin/api/v1/organizations/" + orgID + "/environments/" + envID + "/regions/" + regionID + "/destinations"
	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "mq_"+envID+"_region_"+regionID+"_destinations", bodyBytes)
		jsonparser.ArrayEach(bodyBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			queueType, _ := jsonparser.GetString(value, "type")
			if queueType == "queue" {
				queueID, _ := jsonparser.GetString(value, "queueId")
				extractMQQueue(orgID, envID, regionID, queueID, token, workingFolder)
			} else {
				exchangeID, _ := jsonparser.GetString(value, "exchangeId")
				extractMQExchange(orgID, envID, regionID, exchangeID, token, workingFolder)
			}
		})
	}
}

// MQ Queue Usage
// https://anypoint.mulesoft.com/mq/stats/api/:version/organizations/:organizationId/environments/:environmentId/regions/:region/queues/:queueId
func extractMQQueue(orgID, envID, regionID, queueID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/mq/stats/api/v1/organizations/" + orgID + "/environments/" + envID + "/regions/" + regionID + "/queues/" + queueID
	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "mq_"+envID+"_region_"+regionID+"_destination_"+queueID, bodyBytes)
	}
}

// MQ Exchange
// https://anypoint.mulesoft.com/mq/stats/api/:version/organizations/:organizationId/environments/:environmentId/regions/:region/exchanges/:queueId
func extractMQExchange(orgID, envID, regionID, exchangeID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/mq/stats/api/v1/organizations/" + orgID + "/environments/" + envID + "/regions/" + regionID + "/exchanges/" + exchangeID
	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "mq_"+envID+"_region_"+regionID+"_destination_"+exchangeID, bodyBytes)
	}
}

// Runtime Fabrics
// https://anypoint.mulesoft.com/runtimefabric/api/agents?organizationId=24d08578-431e-4b0e-a4d1-40219f5f2d27&page=0&query=%7B%22method%22:%22GET%22,%22isArray%22:false%7D&size=25
func extractRuntimeFabrics(orgID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/runtimefabric/api/agents?organizationId=" + orgID + "&page=0&query=%7B%22method%22:%22GET%22,%22isArray%22:false%7D&size=1000"

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "runtime_fabrics", bodyBytes)
	}
}

// Rolegroups
//https://anypoint.mulesoft.com/accounts/api/organizations/24d08578-431e-4b0e-a4d1-40219f5f2d27/members?limit=25&offset=0
func extractUsersRolegroups(orgID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/accounts/api/organizations/" + orgID + "/rolegroups?limit=10000&offset=0"

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "rolegroups", bodyBytes)
		jsonparser.ArrayEach(bodyBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			roleGroupID, _ := jsonparser.GetString(value, "role_group_id")
			extractUsersRolegroupsUsers(orgID, roleGroupID, token, workingFolder)
			extractUsersRolegroupsRoles(orgID, roleGroupID, token, workingFolder)
		}, "data")
	}
}

// Rolegroups Roles
//https://anypoint.mulesoft.com/accounts/api/organizations/24d08578-431e-4b0e-a4d1-40219f5f2d27/members?limit=25&offset=0
func extractUsersRolegroupsRoles(orgID, roleGroupID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/accounts/api/organizations/" + orgID + "/rolegroups/" + roleGroupID + "/roles?limit=10000&offset=0"

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "rolegroup_"+roleGroupID+"_roles", bodyBytes)
	}
}

// Rolegroups Users
//https://anypoint.mulesoft.com/accounts/api/organizations/24d08578-431e-4b0e-a4d1-40219f5f2d27/members?limit=25&offset=0
func extractUsersRolegroupsUsers(orgID, roleGroupID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/accounts/api/organizations/" + orgID + "/rolegroups/" + roleGroupID + "/users?limit=10000&offset=0"

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "rolegroup_"+roleGroupID+"_users", bodyBytes)
	}
}

// Roles
// https://anypoint.mulesoft.com/accounts/api/users/fe483eda-b147-49d9-ab0d-43b53da0abb6/roles?limit=100&offset=0
func extractUserRoles(orgID, userID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/accounts/api/users/" + userID + "/roles?limit=10000&offset=0"

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "user_"+userID+"_roles", bodyBytes)
	}
}

// User Members
//https://anypoint.mulesoft.com/accounts/api/organizations/24d08578-431e-4b0e-a4d1-40219f5f2d27/members?limit=25&offset=0
func extractUsersMembers(orgID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/accounts/api/organizations/" + orgID + "/members?limit=10000&offset=0"

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "users", bodyBytes)
		jsonparser.ArrayEach(bodyBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			userID, _ := jsonparser.GetString(value, "id")
			extractUserRoles(orgID, userID, token, workingFolder)
		}, "data")
	}
}

// Organization CS
// https://anypoint.mulesoft.com/accounts/api/organizations/24d08578-431e-4b0e-a4d1-40219f5f2d27
func extractCoreServicesOrganizationInformation(orgID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/accounts/api/organizations/" + orgID

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "cs_organization_information", bodyBytes)
	}
}

// Organization
// https://anypoint.mulesoft.com/cloudhub/api/admin/organizations/cs/0dd3c5b9-3967-421d-bf80-4b9b08fdd2ca?_=1537470631350
func extractCloudhubOrganizationInformation(orgID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/cloudhub/api/admin/organizations/cs/" + orgID

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "ch_organization_information", bodyBytes)
	}
}

// Applications
//// https://anypoint.mulesoft.com/cloudhub/api/admin/applications?organizationId=9210f7fa-a53e-48cf-af4b-1b40f30df4cc
// https://anypoint.mulesoft.com/cloudhub/api/admin/applications?organizationId=c608fbd6-87b3-41ff-838a-c46bb7077f1b
func extractApplications(orgID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/cloudhub/api/admin/applications?organizationId=" + orgID + "&limit=10000"
	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "applications", bodyBytes)
	}
}

// VPCs
// https://anypoint.mulesoft.com/cloudhub/api/organizations/0dd3c5b9-3967-421d-bf80-4b9b08fdd2ca/vpcs
// {"data":[{"id":"vpc-25417241","name":"CLOUDHUB-PPE-VPC","region":"ap-southeast-2","cidrBlock":"10.238.8.0/21","internalDns":{"dnsServers":["13.237.146.79","13.236.25.138"],"specialDomains":["cloudhub.ppe.chorus.co.nz","cloudhub.sandbox.ppe.chorus.co.nz"]},"isDefault":false,"associatedEnvironments":["08665f74-e14c-416f-b77d-f7deab9051b8","2bca9363-2af9-44af-8c14-15ce69a5aba8"],"ownerId":"0dd3c5b9-3967-421d-bf80-4b9b08fdd2ca","sharedWith":[],"firewallRules":[{"cidrBlock":"10.238.8.0/21","protocol":"tcp","fromPort":8092,"toPort":8092},{"cidrBlock":"10.231.1.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"146.171.64.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"10.233.0.0/16","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"10.234.0.0/16","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"146.171.112.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"0.0.0.0/0","protocol":"tcp","fromPort":8082,"toPort":8082},{"cidrBlock":"10.238.8.0/21","protocol":"tcp","fromPort":8091,"toPort":8091},{"cidrBlock":"0.0.0.0/0","protocol":"tcp","fromPort":8081,"toPort":8081}]},{"id":"vpc-5842713c","name":"CLOUDHUB-PRD-VPC","region":"ap-southeast-2","cidrBlock":"10.238.0.0/21","internalDns":{"dnsServers":["13.236.25.138","13.237.146.79"],"specialDomains":["cloudhub.sandbox.chorus.co.nz","cloudhub.chorus.co.nz"]},"isDefault":false,"associatedEnvironments":["cdd99fc9-fd89-4b2c-aa13-ed514e9d477a","a04f2dfd-d99c-40b3-9b13-daa33fdc6fac"],"ownerId":"0dd3c5b9-3967-421d-bf80-4b9b08fdd2ca","sharedWith":[],"firewallRules":[{"cidrBlock":"10.238.0.0/21","protocol":"tcp","fromPort":8092,"toPort":8092},{"cidrBlock":"10.231.1.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"146.171.38.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"10.233.0.0/16","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"10.234.0.0/16","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"146.171.112.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"146.171.112.104/32","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"0.0.0.0/0","protocol":"tcp","fromPort":8082,"toPort":8082},{"cidrBlock":"10.238.0.0/21","protocol":"tcp","fromPort":8091,"toPort":8091},{"cidrBlock":"0.0.0.0/0","protocol":"tcp","fromPort":8081,"toPort":8081}]},{"id":"vpc-a5d4fcc1","name":"CLOUDHUB-SIT-VPC","region":"ap-southeast-2","cidrBlock":"10.238.16.0/21","internalDns":{"dnsServers":["13.236.25.138","13.237.146.79"],"specialDomains":["cloudhub.sit.chorus.co.nz","cloudhub.sandbox.sit.chorus.co.nz"]},"isDefault":false,"associatedEnvironments":["9be23e98-4852-4469-907f-4c6e616e975f","55ca151a-42d3-43c4-9177-0397898e75e0"],"ownerId":"0dd3c5b9-3967-421d-bf80-4b9b08fdd2ca","sharedWith":[],"firewallRules":[{"cidrBlock":"10.238.16.0/21","protocol":"tcp","fromPort":8092,"toPort":8092},{"cidrBlock":"10.231.1.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"10.238.84.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"146.171.64.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"10.233.0.0/16","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"10.234.0.0/16","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"146.171.112.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"0.0.0.0/0","protocol":"tcp","fromPort":8082,"toPort":8082},{"cidrBlock":"10.238.16.0/21","protocol":"tcp","fromPort":8091,"toPort":8091},{"cidrBlock":"0.0.0.0/0","protocol":"tcp","fromPort":8081,"toPort":8081}]},{"id":"vpc-cbe9b2af","name":"CLOUDHUB-DEV-VPC","region":"ap-southeast-2","cidrBlock":"10.238.24.0/21","internalDns":{"dnsServers":["10.238.104.120","10.238.104.154"],"specialDomains":["cloudhub.dev.chorus.co.nz","cloudhub.sandbox.dev.chorus.co.nz"]},"isDefault":true,"associatedEnvironments":["0aa8152b-13c4-4ea1-b1fb-e58be783d8cf","616bc341-4fe2-482e-97be-03af1cb93b8a"],"ownerId":"0dd3c5b9-3967-421d-bf80-4b9b08fdd2ca","sharedWith":[],"firewallRules":[{"cidrBlock":"10.238.24.0/21","protocol":"tcp","fromPort":8092,"toPort":8092},{"cidrBlock":"10.231.1.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"146.171.64.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"10.233.0.0/16","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"10.234.0.0/16","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"146.171.112.0/24","protocol":"tcp","fromPort":8091,"toPort":8092},{"cidrBlock":"0.0.0.0/0","protocol":"tcp","fromPort":8082,"toPort":8082},{"cidrBlock":"10.238.24.0/21","protocol":"tcp","fromPort":8091,"toPort":8091},{"cidrBlock":"0.0.0.0/0","protocol":"tcp","fromPort":8081,"toPort":8081}]}],"total":4}
func extractVPCs(orgID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/cloudhub/api/organizations/" + orgID + "/vpcs"
	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "VPCs", bodyBytes)
		jsonparser.ArrayEach(bodyBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			vpcID, _ := jsonparser.GetString(value, "id")
			extractLoadBalancer(orgID, vpcID, token, workingFolder)
			extractLoadVPN(orgID, vpcID, token, workingFolder)
		}, "data")
	}
}

// VPN
// https://anypoint.mulesoft.com/cloudhub/api/organizations/24d08578-431e-4b0e-a4d1-40219f5f2d27/vpcs/vpc-0e74e26a/ipsec?_=1537567441325
func extractLoadVPN(orgID, vpcID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/cloudhub/api/organizations/" + orgID + "/vpcs/" + vpcID + "/ipsec"

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "VPC_"+vpcID+"_ipsec", bodyBytes)
	}
}

// DLB: https://anypoint.mulesoft.com/cloudhub/api/organizations/0dd3c5b9-3967-421d-bf80-4b9b08fdd2ca/vpcs/vpc-25417241/loadbalancers
func extractLoadBalancer(orgID, vpcID, token, workingFolder string) {
	url := "https://anypoint.mulesoft.com/cloudhub/api/organizations/" + orgID + "/vpcs/" + vpcID + "/loadbalancers"

	bodyBytes := doHttpQuery(token, "GET", url, nil)
	if bodyBytes != nil {
		saveToFile(workingFolder, "VPC_"+vpcID+"_loadbalancers", bodyBytes)
	}
}

// AUDIT
// curl -H 'Authorization: bearer a7dedc7c-b76a-4244-8b0b-ca56fa09de3c' https://anypoint.mulesoft.com/audit/v2/organizations/9210f7fa-a53e-48cf-af4b-1b40f30df4cc/query?include_internal=true&limit=10000 -X POST -H 'Content-Type: application/json' -d'{"startDate": 1536595712000}'
func extractAudit(orgId, token, workingFolder string, now time.Time) {
	url := "https://anypoint.mulesoft.com/audit/v2/organizations/" + orgId + "/query?include_internal=true&limit=10000"
	lastWeekTimestamp := now.Unix() - 604800
	jsonStr := []byte("{\"startDate\":\"" + strconv.FormatInt(lastWeekTimestamp, 10) + "\"}")

	bodyBytes := doHttpQuery(token, "POST", url, bytes.NewBuffer(jsonStr))
	if bodyBytes != nil {
		saveToFile(workingFolder, "audit_since_"+strconv.FormatInt(lastWeekTimestamp, 10), bodyBytes)
	}
}

func isValidToken(token string) bool {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://anypoint.mulesoft.com/accounts/api/me", nil)
	req.Header.Add("Authorization", "bearer "+token)
	resp, err2 := client.Do(req)
	return err == nil && err2 == nil && resp.StatusCode == http.StatusOK
}

func doHttpQuery(token, method, url string, payload io.Reader) []byte {
	color.White("Do " + method + " " + url)
	client := &http.Client{}
	req, _ := http.NewRequest(method, url, payload)
	req.Header.Add("Authorization", "bearer "+token)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil {
		color.Red("Error", err)
	} else {
		if resp.StatusCode == http.StatusOK {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			return bodyBytes
		} else {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			color.Red("Error", string(bodyBytes))
		}
	}
	return nil
}

func saveToFile(workingFolder, title string, bodyBytes []byte) {
	var prettyJSON bytes.Buffer
	json.Indent(&prettyJSON, bodyBytes, "", "\t")
	path := filepath.FromSlash(workingFolder + "/" + title + ".json")
	ioutil.WriteFile(path, prettyJSON.Bytes(), 0644)
	color.Green(path)
}
