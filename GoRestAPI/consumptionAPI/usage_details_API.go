package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func main() {
	authendpoint := "https://login.microsoftonline.com/cdb1a831-e551-4e34-ae8e-d1939d6830f3/oauth2/token"
	body := url.Values(map[string][]string{
		"resource":      {"https://management.azure.com/"},
		"client_id":     {"5827181c-e498-41c7-8ebc-xxxxx"},
		"client_secret": {"IqP8Q~sSrQ5OdDhLg0uhGnF.Oxxxxxxxxx"},
		"grant_type":    {"client_credentials"}})

	request, err := http.NewRequest(
		http.MethodPost,
		authendpoint,
		strings.NewReader(body.Encode()))
	if err != nil {
		panic(err)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	//fmt.Println(resp.StatusCode)
	defer resp.Body.Close()
	data := map[string]interface{}{}
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		//bodyString := string(bodyBytes)
		json.Unmarshal(bodyBytes, &data)
		fmt.Println("access token is :\n", data["access_token"])
	}

	//url := url.QueryEscape("https://management.azure.com/subscriptions/75dcc99f-f1b7-44f0-9646-a451740cac84/providers/Microsoft.Consumption/usageDetails?$filter=properties/usageStart ge '2022-07-01' and properties/usageEnd lt '2022-07-26'&api-version=2019-10-01&$top=2")
	url := "https://management.azure.com/subscriptions/75dcc99f-f1b7-44f0-9646-a451740cac84/providers/Microsoft.Consumption/usageDetails?$filter=properties/usageStart ge '2022-07-01' and properties/usageEnd lt '2022-07-26'&api-version=2019-10-01&$top=2"
	//url := "https://management.azure.com/subscriptions/75dcc99f-f1b7-44f0-9646-a451740cac84/providers/Microsoft.Consumption/usageDetails?api-version=2019-10-01&$top=2"
	//url := "https://management.azure.com/subscriptions/75dcc99f-f1b7-44f0-9646-a451740cac84/resourcegroups?api-version=2017-05-10"
	client1 := &http.Client{}
	acess_token := "bearer" + " " + data["access_token"].(string)
	fmt.Println("access token is :\n", acess_token)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", acess_token)
	res, _ := client1.Do(req)
	fmt.Println("response status is :\n", res.StatusCode)
	defer res.Body.Close()
	data1 := map[string]interface{}{}
	if res.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}
		//bodyString := string(bodyBytes)
		json.Unmarshal(bodyBytes, &data1)
		fmt.Println("access token is :\n", data1["nextLink"])
		//fmt.Println("access token is :\n", bodyString)
	} else {
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}
		bodyString := string(bodyBytes)
		fmt.Println("failed body is :\n", bodyString)
	}

	req1, _ := http.NewRequest("GET", data1["nextLink"].(string), nil)
	req1.Header.Set("Authorization", acess_token)
	res1, _ := client1.Do(req)
	fmt.Println("response status is :\n", res1.StatusCode)
}
