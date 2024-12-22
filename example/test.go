package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/NxyyLOL/CSolver"
)

type Config struct {
	APIKey   string  `json:"api_key"`
	JobSleep float64 `json:"job_sleep"`
}

type ProxyManager struct {
	proxies []string
	current int
	mu      sync.Mutex
}

type TokenManager struct {
	tokens []string
	current int
	mu      sync.Mutex
}

type DiscordClient struct {
	token       string
	proxy       string
	client      *http.Client
	userAgent   string
	csolver     *CSolver.Solver
	fingerprint string
}

// NewDiscordClient creates a new Discord client instance
func NewDiscordClient(token, proxy string, solver *CSolver.Solver) *DiscordClient {
	return &DiscordClient{
		token:     token,
		proxy:     proxy,
		client:    &http.Client{},
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		csolver:   solver,
	}
}

// getFingerprint fetches a Discord fingerprint
func (dc *DiscordClient) getFingerprint() error {
	req, err := http.NewRequest("GET", "https://discord.com/api/v9/experiments", nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", dc.userAgent)
	resp, err := dc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	dc.fingerprint = result.fingerprint
	return nil
}

// extractHCaptchaData extracts sitekey and rqdata from Discord
func (dc *DiscordClient) extractHCaptchaData(inviteCode string) (string, string, error) {
	url := fmt.Sprintf("https://discord.com/invite/%s", inviteCode)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", err
	}

	req.Header.Set("User-Agent", dc.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := dc.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	content := string(body)

	// Extract sitekey and rqdata
	sitekeyPattern := `data-sitekey="([^"]+)"`
	rqdataPattern := `data-rqdata="([^"]+)"`

	sitekeyMatches := regexp.MustCompile(sitekeyPattern).FindStringSubmatch(content)
	rqdataMatches := regexp.MustCompile(rqdataPattern).FindStringSubmatch(content)

	if len(sitekeyMatches) < 2 || len(rqdataMatches) < 2 {
		return "", "", fmt.Errorf("failed to extract captcha data")
	}

	return sitekeyMatches[1], rqdataMatches[1], nil
}

// joinServer attempts to join a Discord server
func (dc *DiscordClient) joinServer(inviteCode string) error {
	// Get captcha data
	sitekey, rqdata, err := dc.extractHCaptchaData(inviteCode)
	if err != nil {
		return fmt.Errorf("failed to get captcha data: %v", err)
	}

	// Solve captcha
	solution, err := dc.csolver.HCaptcha(
		"hCaptchaEnterprise",
		sitekey,
		"https://discord.com",
		&dc.proxy,
		&rqdata,
	)
	
	if err != nil {
		return fmt.Errorf("failed to solve captcha: %v", err)
	}

	// Join request
	payload := map[string]interface{}{
		"captcha_key": solution,
	}
	
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://discord.com/api/v9/invites/%s", inviteCode)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	// Set headers
	req.Header.Set("Authorization", dc.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", dc.userAgent)
	req.Header.Set("X-Fingerprint", dc.fingerprint)

	resp, err := dc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to join server: %s", string(body))
	}

	return nil
}

func NewTokenManager(filepath string) (*TokenManager, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var tokens []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		token := strings.TrimSpace(scanner.Text())
		if token != "" {
			tokens = append(tokens, token)
		}
	}

	if len(tokens) == 0 {
		return nil, fmt.Errorf("no tokens found")
	}

	return &TokenManager{
		tokens:  tokens,
		current: 0,
	}, nil
}

func (tm *TokenManager) GetNext() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	token := tm.tokens[tm.current]
	tm.current = (tm.current + 1) % len(tm.tokens)
	return token
}

func main() {
	// Load configuration
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Initialize managers
	proxyManager, err := NewProxyManager("proxies.txt")
	if err != nil {
		log.Fatalf("Failed to initialize proxy manager: %v", err)
	}

	tokenManager, err := NewTokenManager("tokens.txt")
	if err != nil {
		log.Fatalf("Failed to initialize token manager: %v", err)
	}

	// Initialize solver
	solver := CSolver.NewSolver(config.APIKey, config.JobSleep)

	// Get invite code from user
	fmt.Print("Enter Discord invite code (without discord.gg/): ")
	var inviteCode string
	fmt.Scanln(&inviteCode)

	// Join server with tokens
	for i := 0; i < 3; i++ { // Example: join with 3 tokens
		token := tokenManager.GetNext()
		proxy := proxyManager.GetNext()

		client := NewDiscordClient(token, proxy, solver)
		
		// Get fingerprint
		if err := client.getFingerprint(); err != nil {
			log.Printf("Failed to get fingerprint: %v", err)
			continue
		}

		// Join server
		if err := client.joinServer(inviteCode); err != nil {
			log.Printf("Failed to join with token: %v", err)
			continue
		}

		fmt.Printf("Successfully joined server with token: %s\n", token[:25]+"...")
		
		// Random delay between joins
		time.Sleep(time.Duration(rand.Intn(5)+3) * time.Second)
	}
}