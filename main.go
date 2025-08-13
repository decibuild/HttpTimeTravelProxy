package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Configuration constants
const (
	TimeTravelDateTime = "19990412"
	ProxyServerPort    = 8099
	ProxyServerName    = "HttpTimeTravelProxy/0.1"
	WaybackURL         = "https://web.archive.org/web/"
)

var (
	waybackURLRegex = regexp.MustCompile(`https://web\.archive\.org/web/([0-9a-z_]*)/(.*)`)
)

// Archive API response structure
type ArchiveResponse struct {
	ArchivedSnapshots struct {
		Closest struct {
			Available   bool   `json:"available"`
			URL         string `json:"url"`
			Timestamp   string `json:"timestamp"`
			StatusCode  string `json:"status"`
			ContentType string `json:"mimetype"`
		} `json:"closest"`
	} `json:"archived_snapshots"`
	URL string `json:"url"`
}

// HTTPResponse structure to hold response data
type HTTPResponse struct {
	Status struct {
		Code int
		Text string
	}
	Content struct {
		Type string
		Body []byte
	}
}

func main() {
	// Log server startup
	syslog(fmt.Sprintf("Starting HTTP Time Travel Proxy on port %d", ProxyServerPort))

	// Listen for incoming connections
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", ProxyServerPort))
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
	defer listener.Close()

	// Accept and handle connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			syslog(fmt.Sprintf("Error accepting connection: %v", err))
			continue
		}

		// Handle each connection in a goroutine
		go handleConnection(conn)
	}
}

// Handle a client connection
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set up a reader for the connection
	reader := bufio.NewReader(conn)

	// Read the request
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		if err != io.EOF {
			syslog(fmt.Sprintf("TCP_ERROR: %v", err))
		}
		return
	}

	// Parse the request
	requestParts := strings.Fields(requestLine)
	if len(requestParts) != 3 {
		returnHttpBadRequest(conn)
		return
	}

	// Check if this is a GET request
	if strings.ToLower(requestParts[0]) == "get" {
		// Drain the rest of the headers (we don't use them but need to consume them)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}

		// Process and return the response
		returnProxyResponse(conn, requestParts[1])
	} else {
		// Only support GET requests
		returnHttpBadRequest(conn)
	}
}

// Get the target URL from the Wayback Machine
func getTargetUrl(sourceUrl string) (string, error) {
	// Ensure URL has protocol
	if !strings.HasPrefix(sourceUrl, "http://") && !strings.HasPrefix(sourceUrl, "https://") {
		sourceUrl = "http://" + sourceUrl
	}

	syslog(fmt.Sprintf("Processing URL: %s", sourceUrl))

	// Try multiple variations exhaustively
	variations := generateUrlVariations(sourceUrl)
	
	for _, url := range variations {
		syslog(fmt.Sprintf("Trying variation: %s", url))
		targetUrl, err := fetchWaybackUrl(url)
		if err != nil {
			syslog(fmt.Sprintf("Error fetching %s: %v", url, err))
			continue
		}
		if targetUrl != "" {
			return targetUrl, nil
		}
	}

	// Content is not available in the archive
	return "", nil
}

// Generate all possible URL variations to try
func generateUrlVariations(baseUrl string) []string {
	var variations []string
	
	// Original URL
	variations = append(variations, baseUrl)
	
	// With/without trailing slash for root paths
	if strings.HasSuffix(baseUrl, "/") && strings.Count(baseUrl, "/") == 3 {
		// Root path with slash - also try without
		variations = append(variations, baseUrl[:len(baseUrl)-1])
	} else if !strings.HasSuffix(baseUrl, "/") {
		// No trailing slash - also try with (for some sites this matters)
		variations = append(variations, baseUrl+"/")
	}
	
	// Www/non-www variants
	variant := getVariantUrl(baseUrl)
	if variant != "" {
		variations = append(variations, variant)
		
		// Also try www/non-www with trailing slash variations
		if strings.HasSuffix(variant, "/") && strings.Count(variant, "/") == 3 {
			variations = append(variations, variant[:len(variant)-1])
		} else if !strings.HasSuffix(variant, "/") {
			variations = append(variations, variant+"/")
		}
	}
	
	// For the variant, also try the slash variations
	if variant != "" {
		variantVariant := getVariantUrl(variant)
		if variantVariant != "" && variantVariant != baseUrl {
			variations = append(variations, variantVariant)
		}
	}
	
	return variations
}

// Fetch Wayback URL from Archive API
func fetchWaybackUrl(url string) (string, error) {
	// Query the WaybackMachine API for archived content
	apiUrl := "https://archive.org/wayback/available?url=" + url + "&timestamp=" + TimeTravelDateTime
	syslog(fmt.Sprintf("Calling API: %s", apiUrl))
	
	resp, err := http.Get(apiUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	syslog(fmt.Sprintf("API Response for %s: %s", url, string(body)))

	// Parse the JSON response
	var apiResult ArchiveResponse
	if err := json.Unmarshal(body, &apiResult); err != nil {
		return "", err
	}

	// Check if we have an archived snapshot
	if closest := apiResult.ArchivedSnapshots.Closest; closest.Available && closest.Timestamp != "" {
		availableTimestamp := closest.Timestamp
		// Extract the domain from the archived URL
		archivedUrl := closest.URL
		originalDomain := extractOriginalDomain(archivedUrl)
		if originalDomain == "" {
			// Fallback to the API response URL
			originalDomain = apiResult.URL
		}
		if originalDomain == "" {
			// Final fallback
			originalDomain = url
		}
		targetUrl := WaybackURL + availableTimestamp + "id_/" + originalDomain
		syslog(fmt.Sprintf("Found archived URL: %s -> %s (archived: %s)", url, targetUrl, archivedUrl))
		return targetUrl, nil
	}

	syslog(fmt.Sprintf("No archive found for: %s", url))
	return "", nil
}

// Check if content exists using CDX API (more reliable)
func checkContentExists(url string) (bool, int, error) {
	// Remove protocol for CDX API
	cleanUrl := strings.TrimPrefix(url, "http://")
	cleanUrl = strings.TrimPrefix(cleanUrl, "https://")
	
	cdxUrl := "http://web.archive.org/cdx/search/cdx?url=" + cleanUrl + "&showNumPages=true"
	
	syslog(fmt.Sprintf("Checking CDX API: %s", cdxUrl))
	
	resp, err := http.Get(cdxUrl)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, err
	}
	
	result := strings.TrimSpace(string(body))
	pageCount, err := strconv.Atoi(result)
	if err != nil {
		return false, 0, fmt.Errorf("invalid CDX response: %s", result)
	}
	
	syslog(fmt.Sprintf("CDX API result for %s: %d pages", url, pageCount))
	
	// If pageCount > 1, content exists but API might be inconsistent
	return pageCount > 1, pageCount, nil
}

// Extract original domain from archived URL
func extractOriginalDomain(archivedUrl string) string {
	// Example: http://web.archive.org/web/20020605225933/http://icq.com:80/
	matches := regexp.MustCompile(`https?://web\.archive\.org/web/[0-9a-z_]+/(https?://.*)`).FindStringSubmatch(archivedUrl)
	if len(matches) >= 2 {
		originalUrl := matches[1]
		// Remove port if present
		if portIndex := strings.Index(originalUrl, ":80/"); portIndex != -1 {
			originalUrl = originalUrl[:portIndex] + originalUrl[portIndex+3:]
		}
		// Remove trailing :80 without slash
		if strings.HasSuffix(originalUrl, ":80") {
			originalUrl = originalUrl[:len(originalUrl)-3]
		}
		return originalUrl
	}
	return ""
}

// Get variant URL (www or non-www)
func getVariantUrl(url string) string {
	if strings.Contains(url, "://www.") {
		// Remove www
		return strings.Replace(url, "://www.", "://", 1)
	} else {
		// Add www after http:// or https://
		if strings.HasPrefix(url, "http://") {
			return "http://www." + url[7:]
		} else if strings.HasPrefix(url, "https://") {
			return "https://www." + url[8:]
		} else {
			return "http://www." + url
		}
	}
	return ""
}

// Process the client request and return the response
func returnProxyResponse(conn net.Conn, url string) {
	// Log the request
	syslog("Requesting: " + url)

	// Get the URL from the wayback machine
	targetUrl, err := getTargetUrl(url)
	if err != nil {
		syslog(fmt.Sprintf("Error getting target URL: %v", err))
		returnHttpNotFound(conn, url)
		return
	}

	if targetUrl == "" {
		syslog("No archived content found for: " + url)
		
		// Check if content actually exists using CDX API
		exists, pageCount, cdxErr := checkContentExists(url)
		if cdxErr == nil {
			if exists {
				// Content exists but API returned nothing - Wayback Machine inconsistency
				returnHttpWaybackError(conn, url, pageCount)
				return
			} else {
				// Content truly doesn't exist
				returnHttpNotFound(conn, url)
				return
			}
		} else {
			syslog(fmt.Sprintf("CDX API error: %v", cdxErr))
			// Fall back to regular 404 if CDX check fails
			returnHttpNotFound(conn, url)
			return
		}
	}

	syslog("Using archived URL: " + targetUrl)

	// Request the content from the archive
	resp, err := httpRequest(targetUrl)
	if err != nil {
		// Handle HTTP errors
		statusCode := 0
		if respErr, ok := err.(*HTTPError); ok {
			statusCode = respErr.StatusCode
			syslog(fmt.Sprintf("Exception in proxy request: HTTP %d - %s", statusCode, url))
		}

		if statusCode == 404 {
			returnHttpNotFound(conn, url)
		} else {
			returnHttpBadGateway(conn, fmt.Sprintf("The remote server returned HTTP %d", statusCode))
		}
		return
	}

	// Handle response based on status code
	if resp.StatusCode == 301 || resp.StatusCode == 302 {
		// Get the location header
		location := resp.Header.Get("Location")
		// Pass on the redirect with the original URL
		returnHttpRedirect(conn, resp.StatusCode, getOriginalUrl(location))
	} else {
		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			returnHttpBadGateway(conn, "Failed to read response body")
			return
		}
		defer resp.Body.Close()

		// Return the HTTP response
		returnHttpResponse(conn, HTTPResponse{
			Status: struct {
				Code int
				Text string
			}{
				Code: 200,
				Text: "OK",
			},
			Content: struct {
				Type string
				Body []byte
			}{
				Type: resp.Header.Get("Content-Type"),
				Body: body,
			},
		})
	}
}

// Perform an HTTP redirect (301 or 302)
func returnHttpRedirect(conn net.Conn, statusCode int, locationUrl string) {
	statusText := "Found"
	if statusCode == 301 {
		statusText = "Moved Permanently"
	}

	response := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\n"+
			"Location: %s\r\n"+
			"\r\n",
		statusCode, statusText, locationUrl)

	conn.Write([]byte(response))
}

// Return an HTTP response to the client
func returnHttpResponse(conn net.Conn, response HTTPResponse) {
	// Build the HTTP response
	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", response.Status.Code, response.Status.Text))
	buffer.WriteString(fmt.Sprintf("Server: %s\r\n", ProxyServerName))
	buffer.WriteString(fmt.Sprintf("Content-Type: %s\r\n", response.Content.Type))
	buffer.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(response.Content.Body)))
	buffer.WriteString("\r\n")

	// Write headers
	_, err := conn.Write(buffer.Bytes())
	if err != nil {
		syslog(fmt.Sprintf("Failed to write headers to socket: %v", err))
		return
	}

	// Write body
	_, err = conn.Write(response.Content.Body)
	if err != nil {
		syslog(fmt.Sprintf("Failed to write body to socket: %v", err))
	}
}

// Return an HTTP 404 Not Found response
func returnHttpNotFound(conn net.Conn, url string) {
	html := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The remote server could not find the content:</p>
<p><b>` + url + `</b></p>
<p>This content does not appear to be archived in the Wayback Machine.</p>
</body></html>
`

	returnHttpResponse(conn, HTTPResponse{
		Status: struct {
			Code int
			Text string
		}{
			Code: 404,
			Text: "Not Found",
		},
		Content: struct {
			Type string
			Body []byte
		}{
			Type: "text/html",
			Body: []byte(html),
		},
	})
}

// Return a specialized error for Wayback Machine API inconsistency
func returnHttpWaybackError(conn net.Conn, url string, pageCount int) {
	html := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Wayback Machine API Error</title>
</head><body>
<h1>Wayback Machine API Inconsistency</h1>
<p><b>` + url + `</b></p>
<p>Archived content for this site exists in the Wayback Machine (spanning ` + fmt.Sprintf("%d", pageCount) + ` page(s) of snapshots), but the API is currently returning inconsistent results.</p>
<p>This is a known issue with the Wayback Machine's <code>available</code> API endpoint.</p>
<p><b>Please try your request again in a few minutes.</b></p>
<p>Alternative ways to access archived content:</p>
<ul>
<li>Visit <a href="https://web.archive.org/web/*/` + url + `">web.archive.org/web/*/` + url + `</a> directly</li>
<li>Try accessing specific snapshots from the calendar view</li>
</ul>
<p>For more information about this issue, see: 
<a href="https://github.com/internetarchive/wayback/issues">Internet Archive Wayback Machine Issues</a></p>
</body></html>
`

	returnHttpResponse(conn, HTTPResponse{
		Status: struct {
			Code int
			Text string
		}{
			Code: 404,
			Text: "Not Found (API Inconsistency)",
		},
		Content: struct {
			Type string
			Body []byte
		}{
			Type: "text/html",
			Body: []byte(html),
		},
	})
}

// Return an HTTP 502 Bad Gateway response
func returnHttpBadGateway(conn net.Conn, text string) {
	html := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>502 Bad Gateway</title>
</head><body>
<h1>Bad Gateway</h1>
The proxy server encountered a problem when fetching the content:<br>
<b>` + text + `</b>
</body></html>
`

	returnHttpResponse(conn, HTTPResponse{
		Status: struct {
			Code int
			Text string
		}{
			Code: 502,
			Text: "Bad Gateway",
		},
		Content: struct {
			Type string
			Body []byte
		}{
			Type: "text/html",
			Body: []byte(html),
		},
	})
}

// Return an HTTP 400 Bad Request response
func returnHttpBadRequest(conn net.Conn) {
	html := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
The proxy server cannot understand the request or does not support the request method.
</body></html>
`

	returnHttpResponse(conn, HTTPResponse{
		Status: struct {
			Code int
			Text string
		}{
			Code: 400,
			Text: "Bad Request",
		},
		Content: struct {
			Type string
			Body []byte
		}{
			Type: "text/html",
			Body: []byte(html),
		},
	})
}

// Extract the original URL from the Wayback Machine URL
func getOriginalUrl(translatedUrl string) string {
	matches := waybackURLRegex.FindStringSubmatch(translatedUrl)
	if len(matches) == 3 {
		return strings.TrimSpace(matches[2])
	}
	return translatedUrl
}

// Custom error type for HTTP errors
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return e.Message
}

// Perform an HTTP request
func httpRequest(url string) (*http.Response, error) {
	client := &http.Client{
		// Don't automatically follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	// Check for error status codes
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return resp, nil
	} else if resp.StatusCode == 301 || resp.StatusCode == 302 {
		// Check if this is an internal wayback machine redirect
		location := resp.Header.Get("Location")
		originalSourceUrl := getOriginalUrl(url)
		originalLocationUrl := getOriginalUrl(location)

		if originalLocationUrl == originalSourceUrl ||
			originalLocationUrl == originalSourceUrl+"/" ||
			originalLocationUrl+"/" == originalSourceUrl {
			// Follow the redirect and return the result
			resp.Body.Close()
			return httpRequest(location)
		}

		// Otherwise, return the redirect for the client to handle
		return resp, nil
	}

	// Handle error responses
	defer resp.Body.Close()
	return nil, &HTTPError{
		StatusCode: resp.StatusCode,
		Message:    fmt.Sprintf("HTTP error: %d", resp.StatusCode),
	}
}

// Log messages with timestamp
func syslog(text string) {
	log.Printf("%s - %s", time.Now().Format(time.RFC3339), text)
}
