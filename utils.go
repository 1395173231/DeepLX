/*
 * @Author: Vincent Yang
 * @Date: 2024-04-23 00:17:27
 * @LastEditors: Vincent Yang
 * @LastEditTime: 2024-04-23 00:17:29
 * @FilePath: /DeepLX/utils.go
 * @Telegram: https://t.me/missuo
 * @GitHub: https://github.com/missuo
 *
 * Copyright © 2024 by Vincent, All Rights Reserved.
 */

package main

import (
	"encoding/json"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

func getICount(translateText string) int64 {
	return int64(strings.Count(translateText, "i"))
}

func getRandomNumber() int64 {
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)
	num := rng.Int63n(99999) + 8300000
	return num * 1000
}

func getTimeStamp(iCount int64) int64 {
	ts := time.Now().UnixMilli()
	if iCount != 0 {
		iCount = iCount + 1
		return ts - ts%iCount + iCount
	} else {
		return ts
	}
}

func checkUsageAuthKey(authKey string) (bool, error) {
	url := "https://api-free.deepl.com/v2/usage"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", "DeepL-Auth-Key "+authKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var response DeepLUsageResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return false, err
	}
	return response.CharacterCount < 499900, nil
}

func GetTLSClient(proxy string) tls_client.HttpClient {
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Safari_Ipad_15_6),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithCookieJar(jar),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithForceHttp1(),
	}
	if proxy != "" {
		options = append(options, tls_client.WithProxyUrl(proxy))
	} else {
		options = append(options, tls_client.WithTimeoutSeconds(900))
	}

	// get env DEBUG and set log level
	var client tls_client.HttpClient
	client, _ = tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	return client
}

var CFIPRanges = []string{
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"108.162.192.0/18",
	"131.0.72.0/22",
	"141.101.64.0/18",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
}

func randomIPFromRanges(ranges []string) (net.IP, error) {
	// 随机选择一个IP段
	rand.NewSource(time.Now().UnixNano())
	randomIndex := rand.Intn(len(ranges))
	selectedRange := ranges[randomIndex]

	// 解析CIDR以获取IP范围
	_, ipnet, err := net.ParseCIDR(selectedRange)
	if err != nil {
		return nil, err
	}

	// 随机生成IP地址
	randomIP := make(net.IP, len(ipnet.IP))
	for {
		copy(randomIP, ipnet.IP)
		for i := range randomIP {
			if ipnet.Mask[i] == 0xff {
				continue
			}
			randomIP[i] |= byte(rand.Intn(256) & ^int(ipnet.Mask[i]))
		}
		if ipnet.Contains(randomIP) {
			break
		}
	}

	return randomIP, nil
}

func RandomIPFromRanges() (net.IP, error) {
	return randomIPFromRanges(CFIPRanges)
}
