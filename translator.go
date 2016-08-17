/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"bytes"
	"encoding/json"
	"strconv"
)

type rule struct {
	Type            string `json:"type"`
	SourceIP        string `json:"source_ip"`
	SourcePort      string `json:"source_port"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort string `json:"destination_port"`
	Protocol        string `json:"protocol"`
}

type builderEvent struct {
	Uuid                  string `json:"_uuid"`
	BatchID               string `json:"_batch_id"`
	Type                  string `json:"type"`
	Service               string `json:"service"`
	Name                  string `json:"name"`
	Rules                 []rule `json:"rules"`
	RouterName            string `json:"router_name"`
	RouterType            string `json:"router_type"`
	RouterIP              string `json:"router_ip"`
	ClientName            string `json:"client_name"`
	DatacenterName        string `json:"datacenter_name"`
	DatacenterPassword    string `json:"datacenter_password"`
	DatacenterRegion      string `json:"datacenter_region"`
	DatacenterType        string `json:"datacenter_type"`
	DatacenterUsername    string `json:"datacenter_username"`
	DatacenterAccessToken string `json:"datacenter_token"`
	DatacenterAccessKey   string `json:"datacenter_secret"`
	NetworkName           string `json:"network_name"`
	SecurityGroupAWSID    string `json:"security_group_aws_id"`
	VCloudURL             string `json:"vcloud_url"`
	Status                string `json:"status"`
	ErrorCode             string `json:"error_code"`
	ErrorMessage          string `json:"error_message"`
}

type vcloudEvent struct {
	Uuid               string `json:"_uuid"`
	BatchID            string `json:"_batch_id"`
	Type               string `json:"_type"`
	Service            string `json:"service_id"`
	FirewallType       string `json:"firewall_type"`
	Name               string `json:"firewall_name"`
	Rules              []rule `json:"firewall_rules"`
	RouterName         string `json:"router_name"`
	RouterType         string `json:"router_type"`
	RouterIP           string `json:"router_ip"`
	ClientName         string `json:"client_name"`
	DatacenterName     string `json:"datacenter_name"`
	DatacenterPassword string `json:"datacenter_password"`
	DatacenterRegion   string `json:"datacenter_region"`
	DatacenterType     string `json:"datacenter_type"`
	DatacenterUsername string `json:"datacenter_username"`
	NetworkName        string `json:"network_name"`
	VCloudURL          string `json:"vcloud_url"`
	Status             string `json:"status"`
	ErrorCode          string `json:"error_code"`
	ErrorMessage       string `json:"error_message"`
}

type awsRule struct {
	IP       string `json:"ip"`
	From     int    `json:"from_port"`
	To       int    `json:"to_port"`
	Protocol string `json:"protocol"`
}

type awsEvent struct {
	Uuid                  string `json:"_uuid"`
	BatchID               string `json:"_batch_id"`
	Type                  string `json:"_type"`
	DatacenterRegion      string `json:"datacenter_region"`
	DatacenterAccessToken string `json:"datacenter_access_token"`
	DatacenterAccessKey   string `json:"datacenter_access_key"`
	DatacenterVPCID       string `json:"datacenter_vpc_id"`
	SecurityGroupName     string `json:"security_group_name"`
	SecurityGroupAWSID    string `json:"security_group_aws_id"`
	SecurityGroupRules    struct {
		Ingress []awsRule `json:"ingress"`
		Egress  []awsRule `json:"egress"`
	} `json:"security_group_rules"`
	ErrorMessage string `json:"error"`
}

type Translator struct{}

func (t Translator) BuilderToConnector(j []byte) []byte {
	var input builderEvent
	var output []byte
	json.Unmarshal(j, &input)

	switch input.DatacenterType {
	case "vcloud", "vcloud-fake", "fake":
		output = t.builderToVCloudConnector(input)
	case "aws", "aws-fake":
		output = t.builderToAwsConnector(input)
	}

	return output
}

func (t Translator) builderToVCloudConnector(input builderEvent) []byte {
	var output vcloudEvent

	output.Uuid = input.Uuid
	output.BatchID = input.BatchID
	output.Service = input.Service
	output.Type = input.DatacenterType
	output.Name = input.Name
	output.Rules = input.Rules
	output.FirewallType = "vcloud"
	output.RouterIP = input.RouterIP
	output.RouterName = input.RouterName
	output.RouterType = input.RouterType
	output.NetworkName = input.NetworkName
	output.ClientName = input.ClientName
	output.DatacenterName = input.DatacenterName
	output.DatacenterRegion = input.DatacenterRegion
	output.DatacenterUsername = input.DatacenterUsername
	output.DatacenterPassword = input.DatacenterPassword
	output.DatacenterType = input.DatacenterType
	output.VCloudURL = input.VCloudURL
	output.Status = input.Status
	output.ErrorCode = input.ErrorCode
	output.ErrorMessage = input.ErrorMessage

	body, _ := json.Marshal(output)

	return body
}

func (t Translator) builderToAwsConnector(input builderEvent) []byte {
	var output awsEvent

	output.Uuid = input.Uuid
	output.BatchID = input.BatchID
	output.Type = input.DatacenterType
	output.DatacenterRegion = input.DatacenterRegion
	output.DatacenterAccessToken = input.DatacenterAccessToken
	output.DatacenterAccessKey = input.DatacenterAccessKey
	output.DatacenterVPCID = input.DatacenterName
	output.SecurityGroupAWSID = input.SecurityGroupAWSID
	output.SecurityGroupName = input.Name
	for _, r := range input.Rules {
		from, _ := strconv.Atoi(r.SourcePort)
		to, _ := strconv.Atoi(r.DestinationPort)
		rule := awsRule{
			IP:       r.SourceIP,
			From:     from,
			To:       to,
			Protocol: r.Protocol,
		}
		if r.Type == "ingress" {
			output.SecurityGroupRules.Ingress = append(output.SecurityGroupRules.Ingress, rule)
		} else {
			output.SecurityGroupRules.Egress = append(output.SecurityGroupRules.Egress, rule)
		}
	}

	body, _ := json.Marshal(output)

	return body
}

func (t Translator) ConnectorToBuilder(j []byte) []byte {
	var output []byte
	var input map[string]interface{}

	dec := json.NewDecoder(bytes.NewReader(j))
	dec.Decode(&input)

	switch input["_type"] {
	case "vcloud", "vcloud-fake", "fake":
		output = t.vcloudConnectorToBuilder(j)
	case "aws", "aws-fake":
		output = t.awsConnectorToBuilder(j)
	}

	return output
}

func (t Translator) vcloudConnectorToBuilder(j []byte) []byte {
	var input vcloudEvent
	var output builderEvent
	json.Unmarshal(j, &input)

	output.Uuid = input.Uuid
	output.BatchID = input.BatchID
	output.RouterType = input.Type
	output.Name = input.Name
	output.Rules = input.Rules
	output.RouterIP = input.RouterIP
	output.RouterName = input.RouterName
	output.RouterType = input.RouterType
	output.NetworkName = input.NetworkName
	output.ClientName = input.ClientName
	output.DatacenterName = input.DatacenterName
	output.DatacenterRegion = input.DatacenterRegion
	output.DatacenterUsername = input.DatacenterUsername
	output.DatacenterPassword = input.DatacenterPassword
	output.DatacenterType = input.DatacenterType
	output.VCloudURL = input.VCloudURL

	if input.ErrorMessage != "" {
		output.Status = "errored"
		output.ErrorCode = "0"
		output.ErrorMessage = input.ErrorMessage
	}

	body, _ := json.Marshal(output)

	return body
}

func (t Translator) awsConnectorToBuilder(j []byte) []byte {
	var input awsEvent
	var output builderEvent
	json.Unmarshal(j, &input)

	output.Uuid = input.Uuid
	output.BatchID = input.BatchID
	output.Type = input.Type
	output.DatacenterRegion = input.DatacenterRegion
	output.DatacenterAccessToken = input.DatacenterAccessToken
	output.DatacenterAccessKey = input.DatacenterAccessKey
	output.DatacenterName = input.DatacenterVPCID
	output.SecurityGroupAWSID = input.SecurityGroupAWSID

	for _, r := range input.SecurityGroupRules.Ingress {
		from := strconv.Itoa(r.From)
		to := strconv.Itoa(r.To)
		output.Rules = append(output.Rules, rule{
			Type:            "ingress",
			SourceIP:        r.IP,
			SourcePort:      from,
			DestinationPort: to,
			Protocol:        r.Protocol,
		})
	}

	for _, r := range input.SecurityGroupRules.Egress {
		from := strconv.Itoa(r.From)
		to := strconv.Itoa(r.To)
		output.Rules = append(output.Rules, rule{
			Type:            "egress",
			SourceIP:        r.IP,
			SourcePort:      from,
			DestinationPort: to,
			Protocol:        r.Protocol,
		})
	}

	if input.ErrorMessage != "" {
		output.Status = "errored"
		output.ErrorCode = "0"
		output.ErrorMessage = input.ErrorMessage
	}

	body, _ := json.Marshal(output)

	return body
}
