// main.go
package CSolver

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
)

const BASE = "https://api.csolver.xyz/"

type Solver struct {
	apiKey    string
	jobSleep  float64
	session   *http.Client
}

func NewSolver(apiKey string, jobSleep float64) *Solver {
	if apiKey == "" {
		apiKey = os.Getenv("api_key")
	}
	return &Solver{
		apiKey:   apiKey,
		jobSleep: jobSleep,
		session:  &http.Client{},
	}
}

func (s *Solver) Balance() (float64, error) {
	resp, err := s.session.Post(BASE+"getbal", "application/json", bytes.NewBufferString(`{"api_key":"`+s.apiKey+`"}`))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("bad request")
	}

	var result struct {
		Bal float64 `json:"bal"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	if result.Bal < 0.0005 {
		return 0, errors.New("no balance")
	}

	return result.Bal, nil
}

func (s *Solver) FetchResult(job interface{}, timeout float64) (string, error) {
	start := time.Now()

	for {
		if time.Since(start).Seconds() > timeout {
			return "", errors.New("timeout")
		}

		resp, err := s.session.Get(BASE + "result/" + strconv.Itoa(job.(int)))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", nil
		}

		var data struct {
			Status   string `json:"status"`
			Solution string `json:"solution"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return "", err
		}

		switch data.Status {
		case "completed":
			return data.Solution, nil
		case "processing":
			time.Sleep(time.Duration(s.jobSleep * float64(time.Second)))
		case "failed":
			return "", nil
		}
	}
}

func (s *Solver) HCaptcha(task, siteKey, site string, proxy, rqdata *string) (string, error) {
	if s.apiKey == "" {
		return "", errors.New("API key must be provided")
	}

	payload := map[string]interface{}{
		"task":    task,
		"sitekey": siteKey,
		"site":    site,
		"proxy":   proxy,
		"rqdata":  rqdata,
	}
	data, _ := json.Marshal(payload)

	resp, err := s.session.Post(BASE+"solve", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("bad request")
	}

	var result struct {
		JobID interface{} `json:"job_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.JobID != nil {
		return s.FetchResult(result.JobID, 30.0)
	}

	return "", nil
}

func (s *Solver) Recaptcha3(invisible bool, ua, anchor, reload string) (string, error) {
	headers := map[string]string{
		"User-Agent": ua,
	}

	req, _ := http.NewRequest("GET", anchor, nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := s.session.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("bad request")
	}

	body, _ := io.ReadAll(resp.Body)
	tokenMatch := regexp.MustCompile(`type="hidden" id="recaptcha-token" value="([^"]+)"`).FindStringSubmatch(string(body))
	if len(tokenMatch) < 2 {
		return "", errors.New("no token")
	}

	token := tokenMatch[1]
	uv := url.ParseQuery(resp.Request.URL.RawQuery)
	v, k, co := uv["v"][0], uv["k"][0], uv["co"][0]

	headers["Referer"] = resp.Request.URL.String()
	headers["Content-Type"] = "application/x-www-form-urlencoded"

	data := "v=" + v + "&reason=q&c=" + token + "&k=" + k + "&co=" + co + "&hl=en&size=" + map[bool]string{true: "invisible", false: "visible"}[invisible]

	resp, err = s.session.Post(reload, "application/x-www-form-urlencoded", bytes.NewBufferString(data))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ = io.ReadAll(resp.Body)
	return strings.Split(strings.Split(string(body), `["rresp","`)[1], `"`)[0], nil
}

