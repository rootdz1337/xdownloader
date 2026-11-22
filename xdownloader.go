package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type config struct {
	url        string
	dest       string
	sha256sum  string
	timeout    time.Duration
	retries    int
	exec       bool
	execArgs   string
	userAgent  string
	insecure   bool
	chunkSize  int64
}

// ---------------------------------------------------------------------------
// Downloader
// ---------------------------------------------------------------------------

type downloader struct {
	cfg    config
	client *http.Client
}

func newDownloader(cfg config) *downloader {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.insecure},
	}
	return &downloader{
		cfg: cfg,
		client: &http.Client{
			Timeout:   cfg.timeout,
			Transport: tr,
		},
	}
}

// Fetch downloads the URL to dest, resuming from a .part file if present.
func (d *downloader) Fetch() error {
	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(d.cfg.dest), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	part := d.cfg.dest + ".part"
	var lastErr error

	for attempt := 0; attempt <= d.cfg.retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * time.Second
			fmt.Printf("[*] retry %d/%d in %s (last: %v)\n", attempt, d.cfg.retries, backoff, lastErr)
			time.Sleep(backoff)
		}
		if err := d.fetchOnce(part); err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return lastErr
	}

	// Verify hash if provided
	if d.cfg.sha256sum != "" {
		if err := verifySHA256(part, d.cfg.sha256sum); err != nil {
			os.Remove(part)
			return err
		}
		fmt.Printf("[+] SHA256 verified\n")
	}

	// Rename .part -> final
	if err := os.Rename(part, d.cfg.dest); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	info, _ := os.Stat(d.cfg.dest)
	if info != nil {
		fmt.Printf("[+] saved %s (%d bytes)\n", d.cfg.dest, info.Size())
	}
	return nil
}

func (d *downloader) fetchOnce(part string) error {
	var offset int64
	if fi, err := os.Stat(part); err == nil {
		offset = fi.Size()
	}

	req, err := http.NewRequest("GET", d.cfg.url, nil)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("User-Agent", d.cfg.userAgent)
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		fmt.Printf("[*] resuming at %d bytes\n", offset)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Server ignored Range — start over
		offset = 0
	case http.StatusPartialContent:
		// good
	case http.StatusRequestedRangeNotSatisfiable:
		// already complete
		return nil
	default:
		return fmt.Errorf("http %d: %s", resp.StatusCode, resp.Status)
	}

	flags := os.O_CREATE | os.O_WRONLY
	if offset == 0 {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_APPEND
	}
	f, err := os.OpenFile(part, flags, 0644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	// Progress: log every ~4MB
	var written int64
	lastLog := time.Now()
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return fmt.Errorf("write: %w", werr)
			}
			written += int64(n)
			if time.Since(lastLog) > 2*time.Second {
				pct := ""
				if resp.ContentLength > 0 {
					total := offset + resp.ContentLength
					pct = fmt.Sprintf(" (%.1f%%)", 100*float64(offset+written)/float64(total))
				}
				fmt.Printf("[*] %d bytes%s\n", offset+written, pct)
				lastLog = time.Now()
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
	}
	return f.Sync()
}

func verifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	want = strings.ToLower(strings.TrimSpace(want))
	if got != want {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

func (d *downloader) Execute() error {
	if !d.cfg.exec {
		return nil
	}
	args := splitArgs(d.cfg.execArgs)

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// Use cmd.exe to allow built-ins / shell quoting
		full := append([]string{"/c", d.cfg.dest}, args...)
		cmd = exec.Command("cmd.exe", full...)
	default:
		os.Chmod(d.cfg.dest, 0755)
		cmd = exec.Command(d.cfg.dest, args...)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	fmt.Printf("[*] executing: %s %s\n", d.cfg.dest, strings.Join(args, " "))
	return cmd.Run()
}

// splitArgs is a tiny shell-like splitter (handles quotes, no env expansion).
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inSingle, inDouble, escaped := false, false, false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && !inSingle:
			escaped = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case (r == ' ' || r == '\t') && !inSingle && !inDouble:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	var cfg config
	flag.StringVar(&cfg.url, "url", "", "URL to download (required)")
	flag.StringVar(&cfg.dest, "out", "", "destination path (default: basename of URL)")
	flag.StringVar(&cfg.sha256sum, "sha256", "", "expected SHA256 hex (optional)")
	flag.DurationVar(&cfg.timeout, "timeout", 60*time.Second, "per-request timeout")
	flag.IntVar(&cfg.retries, "retries", 3, "retry attempts on failure")
	flag.BoolVar(&cfg.exec, "exec", false, "execute downloaded file")
	flag.StringVar(&cfg.execArgs, "args", "", "arguments passed to executed file")
	flag.StringVar(&cfg.userAgent, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GoDownloader/1.0", "User-Agent header")
	flag.BoolVar(&cfg.insecure, "insecure", false, "skip TLS certificate verification")
	flag.Parse()

	if cfg.url == "" {
		fmt.Fprintln(os.Stderr, "error: -url is required")
		flag.Usage()
		os.Exit(2)
	}
	if cfg.dest == "" {
		base := filepath.Base(cfg.url)
		if i := strings.IndexAny(base, "?#"); i >= 0 {
			base = base[:i]
		}
		if base == "" || base == "." || base == "/" {
			base = "payload.bin"
		}
		cfg.dest = base
	}

	fmt.Printf("[*] fetching %s -> %s\n", cfg.url, cfg.dest)
	d := newDownloader(cfg)
	if err := d.Fetch(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] fetch failed: %v\n", err)
		os.Exit(1)
	}
	if err := d.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] exec failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[+] done")
}
