// Command yadisk-download mirrors Yandex.Disk folders into a local directory, byte for byte.
//
//	yadisk-download -dest ~/backups -exclude disk:/tech/logs disk:/tech disk:/photos
//
// mirrors both folders into ~/backups/tech and ~/backups/photos in one run, leaving out disk:/tech/logs.
//
// Two local folders, both settable by flags (defaults sit next to the binary):
//
//	-dest   (default downloads/) the mirrored files, plus at most one NAME.part being downloaded
//	-state  (default .state/)   refresh-token, download.log, complete (written when everything is verified)
//
// Delete those two folders and nothing of this tool remains.
//
// One file at a time, resumable, every file verified against the md5/sha256 that Yandex reports.
// Stop it any time (Ctrl-C, closed terminal, lost network) and start it again: it continues.
// It only ends successfully when every remote file exists locally with a matching checksum.
//
// OAuth credentials are baked into the binary by build.sh (-ldflags -X), so it is a single file.
package main

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Set by build.sh via -ldflags "-X main.clientID=...".
var (
	clientID     string
	clientSecret string
	refreshToken string
)

// Variables (not constants) so tests can point them at a fake server and shorten the pauses.
var (
	apiBase           = "https://cloud-api.yandex.net/v1/disk"
	tokenURL          = "https://oauth.yandex.ru/token"
	pauseBetweenFiles = 2 * time.Second
	passPause         = 2 * time.Minute
	idleTimeout       = 60 * time.Second
	progressEvery     = 10 * time.Second
	pageSize          = 1000

	// Download slots: a new one is added every spawnEvery while no data has arrived for activeWindow
	// (and no checksum is being computed), up to maxSlots. While data flows, no slot is added.
	maxSlots     = 10
	spawnEvery   = 5 * time.Second
	activeWindow = 15 * time.Second
)

const (
	maxStalled = 2       // consecutive download attempts without a single new byte before skipping the file
	maxPasses  = 2       // full passes over the folder; files still failing after the last one are reported and the run ends
	freeMargin = 2 << 30 // keep this much disk free on top of the file being downloaded
)

type remoteFile struct {
	Rel    string // path relative to the mirrored folder, '/'-separated
	Path   string // full "disk:/..." path for API calls
	Size   int64
	MD5    string
	SHA256 string
}

type apiError struct {
	Status     int
	Body       string
	RetryAfter time.Duration
}

func (e *apiError) Error() string {
	return fmt.Sprintf("http %d: %s", e.Status, e.Body)
}

func (e *apiError) retryable() bool {
	switch e.Status {
	case http.StatusLocked, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// fatalError stops the whole run: retrying cannot help (bad credentials, full disk, missing folder).
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }

var errRejected = errors.New("oauth rejected the refresh token")

func newAPIError(resp *http.Response) *apiError {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	e := &apiError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	if seconds, err := time.ParseDuration(resp.Header.Get("Retry-After") + "s"); err == nil {
		e.RetryAfter = seconds
	}
	return e
}

func transient(err error) bool {
	var fatal *fatalError
	if errors.As(err, &fatal) {
		return false
	}
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		return apiErr.retryable()
	}
	return true // network errors, truncated bodies, stalls
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type client struct {
	http      *http.Client
	log       *slog.Logger
	tokenFile string // newest refresh token we obtained; preferred over the baked-in one

	mu     sync.Mutex // the lister and the downloaders share one client: guards access and serializes OAuth refreshes
	access string

	act      activity   // tells the slot scheduler whether anything is making progress
	spaceMu  sync.Mutex // guards reserved
	reserved int64      // bytes the running downloads may still write: kept out of the free-space estimate
}

// activity tells the slot scheduler whether anything is making progress right now:
// data arriving on an open transfer, or a checksum being computed.
type activity struct {
	mu        sync.Mutex
	transfers map[*atomic.Int64]struct{} // per open transfer: when data last arrived (unix nanos)
	verifying int
}

func (a *activity) openTransfer() *atomic.Int64 {
	last := new(atomic.Int64)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.transfers == nil {
		a.transfers = map[*atomic.Int64]struct{}{}
	}
	a.transfers[last] = struct{}{}
	return last
}

func (a *activity) closeTransfer(last *atomic.Int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.transfers, last)
}

// startVerify marks a checksum as being computed; call the result when it is done.
func (a *activity) startVerify() (done func()) {
	a.mu.Lock()
	a.verifying++
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		a.verifying--
		a.mu.Unlock()
	}
}

func (a *activity) busy() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.verifying > 0 {
		return true
	}
	now := time.Now().UnixNano()
	for last := range a.transfers {
		if now-last.Load() < int64(activeWindow) {
			return true
		}
	}
	return false
}

func newClient(log *slog.Logger, tokenFile string) *client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = idleTimeout
	return &client{http: &http.Client{Transport: transport}, log: log, tokenFile: tokenFile}
}

// ---------- OAuth ----------

func (c *client) refreshTokens() []string {
	var tokens []string
	if data, err := os.ReadFile(c.tokenFile); err == nil {
		if saved := strings.TrimSpace(string(data)); saved != "" {
			tokens = append(tokens, saved)
		}
	}
	if refreshToken != "" && (len(tokens) == 0 || tokens[0] != refreshToken) {
		tokens = append(tokens, refreshToken)
	}
	return tokens
}

// token returns the current access token, authorizing first if there is none. Only one caller refreshes at a time.
func (c *client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access == "" {
		if err := c.authorize(ctx); err != nil {
			return "", err
		}
	}
	return c.access, nil
}

// expire forgets the access token the server just rejected, unless another caller has already replaced it.
func (c *client) expire(rejected string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access == rejected {
		c.access = ""
	}
}

// authorize must be called with c.mu held.
func (c *client) authorize(ctx context.Context) error {
	var rejected error
	for _, token := range c.refreshTokens() {
		access, newRefresh, err := c.exchange(ctx, token)
		if errors.Is(err, errRejected) {
			rejected = err
			continue
		}
		if err != nil {
			return err
		}
		c.access = access
		if newRefresh != "" && newRefresh != token {
			if err := writeFileAtomic(c.tokenFile, []byte(newRefresh+"\n"), 0o600); err != nil {
				c.log.Warn("cannot save the new refresh token", "err", err)
			}
		}
		return nil
	}
	if rejected == nil {
		return &fatalError{errors.New("no refresh token: build with build.sh")}
	}
	return &fatalError{fmt.Errorf("%w; re-authorize in sozvon-konspekt and rebuild", rejected)}
}

func (c *client) exchange(ctx context.Context, token string) (access, newRefresh string, err error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		return "", "", fmt.Errorf("%w (http %d)", errRejected, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", newAPIError(resp)
	}
	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil || payload.AccessToken == "" {
		return "", "", fmt.Errorf("bad oauth response: %v", err)
	}
	return payload.AccessToken, payload.RefreshToken, nil
}

// ---------- API ----------

func (c *client) apiGet(ctx context.Context, rawURL string, out any) error {
	for attempt := 0; ; attempt++ {
		access, err := c.token(ctx)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "OAuth "+access)
		req.Header.Set("Accept", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			c.expire(access) // expired: authorize again and repeat once
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return newAPIError(resp)
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}
}

// retry repeats fn with a growing pause while the error looks temporary.
func (c *client) retry(ctx context.Context, what string, attempts int, fn func() error) error {
	delay := 5 * time.Second
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !transient(err) || attempt >= attempts {
			return err
		}
		wait := delay
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.RetryAfter > wait {
			wait = apiErr.RetryAfter
		}
		c.log.Warn("retrying", "what", what, "attempt", attempt, "in", wait.String(), "err", err)
		if err := sleep(ctx, wait); err != nil {
			return err
		}
		delay = min(delay*2, 5*time.Minute)
	}
}

func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

type diskItem struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Type   string `json:"type"` // "dir" or "file"
	Size   int64  `json:"size"`
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

// children returns the direct contents of one Disk folder, all pages.
func (c *client) children(ctx context.Context, dir string) ([]diskItem, error) {
	var items []diskItem
	for offset := 0; ; {
		var page struct {
			Embedded struct {
				Items []diskItem `json:"items"`
				Total int        `json:"total"`
			} `json:"_embedded"`
		}
		query := url.Values{
			"path":   {dir},
			"limit":  {fmt.Sprint(pageSize)},
			"offset": {fmt.Sprint(offset)},
			"fields": {"_embedded.items.name,_embedded.items.path,_embedded.items.type,_embedded.items.size," +
				"_embedded.items.md5,_embedded.items.sha256,_embedded.total"},
		}
		if err := c.apiGet(ctx, apiBase+"/resources?"+query.Encode(), &page); err != nil {
			return nil, err
		}
		for _, item := range page.Embedded.Items {
			if !validName(item.Name) {
				return nil, &fatalError{fmt.Errorf("unsafe name %q in %s", item.Name, dir)}
			}
		}
		items = append(items, page.Embedded.Items...)
		offset += len(page.Embedded.Items)
		if len(page.Embedded.Items) == 0 || offset >= page.Embedded.Total {
			return items, nil
		}
	}
}

// folderName is the local folder a mirrored Disk folder lands in: its own name, e.g. "disk:/a/b" -> "b".
func folderName(folder string) (string, error) {
	name := path.Base(strings.TrimSuffix(strings.TrimPrefix(folder, "disk:"), "/"))
	if !validName(name) {
		return "", &fatalError{fmt.Errorf("cannot mirror %q: it has no folder name", folder)}
	}
	return name, nil
}

// checkFolders refuses folders that cannot be mirrored side by side: no name, or the same name twice.
func checkFolders(folders []string) error {
	seen := map[string]bool{}
	for _, folder := range folders {
		name, err := folderName(folder)
		if err != nil {
			return err
		}
		if seen[name] {
			return &fatalError{fmt.Errorf("two folders are both named %q", name)}
		}
		seen[name] = true
	}
	return nil
}

// walkFolder emits every file under root, recursively, as "<root name>/<path inside root>".
// A folder's files come before its subfolders, so the first files are available almost at once.
// Items whose full Disk path is in excluded are skipped (a skipped folder is not even entered).
func (c *client) walkFolder(ctx context.Context, root string, excluded map[string]bool, emit func(remoteFile)) error {
	name, err := folderName(root)
	if err != nil {
		return err
	}
	var walk func(dir, rel string) error
	walk = func(dir, rel string) error {
		var items []diskItem
		err := c.retry(ctx, "list "+dir, 8, func() (listErr error) {
			items, listErr = c.children(ctx, dir)
			return listErr
		})
		if err != nil {
			return err
		}
		var dirs []diskItem
		for _, item := range items {
			if excluded[item.Path] {
				continue
			}
			switch item.Type {
			case "dir":
				dirs = append(dirs, item)
			case "file":
				emit(remoteFile{
					Rel: rel + "/" + item.Name, Path: item.Path, Size: item.Size,
					MD5: strings.ToLower(item.MD5), SHA256: strings.ToLower(item.SHA256),
				})
			}
		}
		for _, d := range dirs {
			if err := walk(d.Path, rel+"/"+d.Name); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, name); err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
			return &fatalError{fmt.Errorf("remote folder %s not found", root)}
		}
		return err
	}
	return nil
}

// walkFolders walks several Disk folders one after another, in the order given.
func (c *client) walkFolders(ctx context.Context, folders []string, excluded map[string]bool, emit func(remoteFile)) error {
	for _, folder := range folders {
		c.log.Info("listing folder", "folder", folder)
		files := 0
		err := c.walkFolder(ctx, folder, excluded, func(f remoteFile) {
			files++
			emit(f)
		})
		if err != nil {
			return err
		}
		c.log.Info("listed folder", "folder", folder, "files", files)
	}
	return nil
}

// feed is the growing list of files found so far: the lister appends, the download workers read from it.
type feed struct {
	mu      sync.Mutex
	files   []remoteFile
	bytes   int64
	done    bool          // the lister has finished
	err     error         // why it stopped early; nil when the list is complete
	changed chan struct{} // closed and replaced whenever the list grows or ends: wakes every waiting reader
}

func newFeed() *feed {
	return &feed{changed: make(chan struct{})}
}

// broadcast must be called with f.mu held.
func (f *feed) broadcast() {
	close(f.changed)
	f.changed = make(chan struct{})
}

func (f *feed) add(file remoteFile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files = append(f.files, file)
	f.bytes += file.Size
	f.broadcast()
}

func (f *feed) finish(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.done, f.err = true, err
	f.broadcast()
}

// get returns file number i, waiting for the lister if it has not found it yet.
// ok is false once the list has ended before reaching i; err is then why the list ended early (nil if complete).
func (f *feed) get(ctx context.Context, i int) (file remoteFile, ok bool, err error) {
	for {
		f.mu.Lock()
		switch {
		case i < len(f.files):
			file = f.files[i]
			f.mu.Unlock()
			return file, true, nil
		case f.done:
			err = f.err
			f.mu.Unlock()
			return remoteFile{}, false, err
		}
		changed := f.changed
		f.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return remoteFile{}, false, ctx.Err()
		}
	}
}

// stats reports what has been found so far.
func (f *feed) stats() (files int, bytes int64, done bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.files), f.bytes, f.done
}

// printDirs writes the names of the subfolders of dir, `depth` levels down (1 = only direct subfolders).
// It reads one folder per request and never touches files, so it stays cheap even on a huge Disk.
func (c *client) printDirs(ctx context.Context, w io.Writer, dir string, depth, level int) error {
	items, err := c.children(ctx, dir)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Type != "dir" {
			continue
		}
		fmt.Fprintf(w, "%s%s/\n", strings.Repeat("  ", level), item.Name)
		if level+1 < depth {
			if err := c.printDirs(ctx, w, item.Path, depth, level+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------- verification ----------

// verify checks size and every checksum Yandex reported for the file.
func verify(path string, f remoteFile) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() != f.Size {
		return fmt.Errorf("size %d, expected %d", info.Size(), f.Size)
	}
	if f.MD5 == "" && f.SHA256 == "" {
		return errors.New("Yandex reported no checksum, cannot verify")
	}
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	var md5Hash, sha256Hash hash.Hash
	var writers []io.Writer
	if f.MD5 != "" {
		md5Hash = md5.New()
		writers = append(writers, md5Hash)
	}
	if f.SHA256 != "" {
		sha256Hash = sha256.New()
		writers = append(writers, sha256Hash)
	}
	if _, err := io.Copy(io.MultiWriter(writers...), in); err != nil {
		return err
	}
	if md5Hash != nil && hex.EncodeToString(md5Hash.Sum(nil)) != f.MD5 {
		return errors.New("md5 mismatch")
	}
	if sha256Hash != nil && hex.EncodeToString(sha256Hash.Sum(nil)) != f.SHA256 {
		return errors.New("sha256 mismatch")
	}
	return nil
}

// ---------- download ----------

type progress struct {
	log   *slog.Logger
	label string
	size  int64
	base  int64
	start time.Time
	last  time.Time
}

func (p *progress) report(done int64) {
	if time.Since(p.last) < progressEvery {
		return
	}
	p.last = time.Now()
	rate := float64(done-p.base) / max(time.Since(p.start).Seconds(), 0.001)
	eta := "?"
	if rate > 0 {
		eta = (time.Duration(float64(p.size-done)/rate) * time.Second).Round(time.Second).String()
	}
	p.log.Info("downloading", "file", p.label, "done", fmt.Sprintf("%.0f%%", 100*float64(done)/float64(max(p.size, 1))),
		"mb", fmt.Sprintf("%d/%d", done>>20, p.size>>20), "speed", fmt.Sprintf("%.1f MB/s", rate/1e6), "eta", eta)
}

func stalledOr(ctx, requestCtx context.Context, err error) error {
	if ctx.Err() == nil && requestCtx.Err() != nil {
		return fmt.Errorf("no data for %s: %w", idleTimeout, err)
	}
	return err
}

// fetchRange appends the rest of the file (from byte `have`) to part; returns how many new bytes were written.
func (c *client) fetchRange(ctx context.Context, f remoteFile, part string, have int64, label string) (int64, error) {
	var link struct {
		Href string `json:"href"`
	}
	query := url.Values{"path": {f.Path}}
	err := c.retry(ctx, "download link", 5, func() error {
		return c.apiGet(ctx, apiBase+"/resources/download?"+query.Encode(), &link)
	})
	if err != nil {
		return 0, err
	}

	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(idleTimeout, cancel) // fires when nothing arrives for idleTimeout
	defer idle.Stop()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, link.Href, nil)
	if err != nil {
		return 0, err
	}
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, stalledOr(ctx, requestCtx, err)
	}
	defer resp.Body.Close()

	flags := os.O_WRONLY | os.O_CREATE
	switch resp.StatusCode {
	case http.StatusPartialContent:
		if !strings.HasPrefix(resp.Header.Get("Content-Range"), fmt.Sprintf("bytes %d-", have)) {
			return 0, fmt.Errorf("unexpected Content-Range %q", resp.Header.Get("Content-Range"))
		}
		flags |= os.O_APPEND
	case http.StatusOK: // the server ignored Range: start over
		have = 0
		flags |= os.O_TRUNC
	case http.StatusRequestedRangeNotSatisfiable:
		_ = os.Remove(part)
		return 0, errors.New("range not satisfiable, restarting from zero")
	default:
		return 0, newAPIError(resp)
	}

	out, err := os.OpenFile(part, flags, 0o644)
	if err != nil {
		return 0, &fatalError{err}
	}
	defer out.Close()

	lastData := c.act.openTransfer()
	defer c.act.closeTransfer(lastData)
	prog := &progress{log: c.log, label: label, size: f.Size, base: have, start: time.Now(), last: time.Now()}
	buf := make([]byte, 1<<20)
	var written int64
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			lastData.Store(time.Now().UnixNano())
			idle.Reset(idleTimeout)
			if _, err := out.Write(buf[:n]); err != nil {
				if errors.Is(err, syscall.ENOSPC) {
					return written, &fatalError{errors.New("disk is full")}
				}
				return written, err
			}
			written += int64(n)
			prog.report(have + written)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return written, stalledOr(ctx, requestCtx, readErr)
		}
	}
	if err := out.Sync(); err != nil {
		return written, err
	}
	if have+written != f.Size {
		return written, io.ErrUnexpectedEOF
	}
	return written, nil
}

func fileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

// freeBytes is a variable so tests can fake the free space.
var freeBytes = func(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// reserveSpace claims `need` more bytes for one download. Several downloads run at once, so it counts what the
// others may still write: it fails fatally when the disk could not hold the file even alone, and with a temporary
// error when it is only the other downloads that leave no room (the file is then retried on the next pass).
func (c *client) reserveSpace(dir string, need int64, name string) (release func(), err error) {
	free, statErr := freeBytes(dir)
	c.spaceMu.Lock()
	defer c.spaceMu.Unlock()
	if statErr == nil {
		switch {
		case free < uint64(need)+freeMargin:
			return nil, &fatalError{fmt.Errorf("not enough disk space for %s: %d MB free", name, free>>20)}
		case free < uint64(c.reserved+need)+freeMargin:
			return nil, fmt.Errorf("no room for %s while the other downloads are running", name)
		}
	}
	c.reserved += need
	return func() {
		c.spaceMu.Lock()
		c.reserved -= need
		c.spaceMu.Unlock()
	}, nil
}

// download fetches f into final via final+".part" (resuming it), verifies it and renames it into place.
func (c *client) download(ctx context.Context, f remoteFile, final, label string) error {
	part := final + ".part"
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return &fatalError{err}
	}
	stalled := 0
	for {
		have := fileSize(part)
		if have > f.Size {
			_ = os.Remove(part)
			have = 0
		}
		if have == f.Size {
			if f.Size == 0 {
				if err := os.WriteFile(part, nil, 0o644); err != nil {
					return &fatalError{err}
				}
			}
			break
		}
		release, err := c.reserveSpace(filepath.Dir(final), f.Size-have, f.Rel)
		if err != nil {
			return err
		}
		written, err := c.fetchRange(ctx, f, part, have, label)
		release()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !transient(err) {
			return err
		}
		if written > 0 {
			stalled = 0
		} else if stalled++; stalled >= maxStalled {
			return fmt.Errorf("no progress after %d attempts: %w", stalled, err)
		}
		wait := time.Duration(min(stalled, 6)+1) * 5 * time.Second
		c.log.Warn("download interrupted, resuming", "file", label, "in", wait.String(), "err", err)
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
	verifyDone := c.act.startVerify()
	err := verify(part, f)
	verifyDone()
	if err != nil {
		_ = os.Remove(part)
		return fmt.Errorf("downloaded copy is corrupt (%w), deleted, will retry", err)
	}
	return os.Rename(part, final)
}

// ---------- run ----------

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type totals struct {
	files, bytes int64
}

// verifiedSet remembers the files already checked in this run, so later passes skip them.
type verifiedSet struct {
	mu   sync.Mutex
	keys map[string]bool
}

func (v *verifiedSet) has(key string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.keys[key]
}

func (v *verifiedSet) add(key string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys[key] = true
}

// ensure makes sure one file is present and verified; returns true if it had to download it.
func (c *client) ensure(ctx context.Context, f remoteFile, dest, label string, verified *verifiedSet) (bool, error) {
	final := filepath.Join(dest, filepath.FromSlash(f.Rel))
	key := f.Rel + "|" + f.MD5 + "|" + f.SHA256
	if verified.has(key) {
		return false, nil
	}
	if _, err := os.Stat(final); err == nil {
		verifyDone := c.act.startVerify()
		err := verify(final, f)
		verifyDone()
		if err == nil {
			verified.add(key)
			c.log.Info("already here, verified", "file", label)
			return false, nil
		}
		c.log.Warn("local copy differs from Disk, replacing", "file", label, "why", err)
		if err := os.Remove(final); err != nil {
			return false, err
		}
	}
	c.log.Info("start", "file", label, "size_mb", f.Size>>20)
	if err := c.download(ctx, f, final, label); err != nil {
		return false, err
	}
	verified.add(key)
	c.log.Info("done, verified", "file", label)
	return true, nil
}

// reportExtras lists local files inside the mirrored folders that are not on the Disk; they are never deleted.
func (c *client) reportExtras(dest string, files []remoteFile) {
	want := make(map[string]bool, len(files))
	tops := map[string]bool{}
	for _, f := range files {
		want[f.Rel] = true
		top, _, _ := strings.Cut(f.Rel, "/")
		tops[top] = true
	}
	for top := range tops {
		_ = filepath.WalkDir(filepath.Join(dest, top), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			if rel, err := filepath.Rel(dest, path); err == nil && !want[filepath.ToSlash(rel)] {
				c.log.Warn("local file is not on the Disk (left untouched)", "file", rel)
			}
			return nil
		})
	}
}

// run mirrors the folders into dest/<folder name>/..., skipping the excluded Disk paths.
func (c *client) run(ctx context.Context, folders, excluded []string, dest, doneMarker string) error {
	skip := make(map[string]bool, len(excluded))
	for _, p := range excluded {
		skip[strings.TrimSuffix(p, "/")] = true
	}
	if err := checkFolders(folders); err != nil {
		return err
	}
	verified := &verifiedSet{keys: map[string]bool{}}
	_ = os.Remove(doneMarker)
	for pass := 1; ; {
		files, failed, listErr, err := c.runPass(ctx, pass, folders, skip, dest, verified)
		if err != nil {
			return err
		}
		if listErr != nil {
			if !transient(listErr) {
				return listErr
			}
			// The list is incomplete, so nothing can be declared done: list again from scratch (verified files are skipped).
			c.log.Warn("listing stopped early, will try again", "err", listErr, "in", passPause.String())
			if err := sleep(ctx, passPause); err != nil {
				return err
			}
			continue
		}
		if len(failed) == 0 {
			var totalBytes int64
			for _, f := range files {
				totalBytes += f.Size
			}
			c.reportExtras(dest, files)
			c.log.Info("ALL DONE: every file is present and matches its checksum",
				"files", len(files), "gb", fmt.Sprintf("%.2f", float64(totalBytes)/(1<<30)))
			return writeFileAtomic(doneMarker, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644)
		}
		if pass >= maxPasses {
			c.log.Error("GAVE UP on files Yandex cannot serve; run again later to retry them", "files", len(failed), "list", strings.Join(failed, " | "))
			return fmt.Errorf("%d of %d files are missing", len(failed), len(files))
		}
		c.log.Warn("pass finished with failures", "failed", len(failed), "next pass in", passPause.String())
		if err := sleep(ctx, passPause); err != nil {
			return err
		}
		pass++
	}
}

// passState is what the download workers of one pass share: which file is handed out next and what they report.
type passState struct {
	mu      sync.Mutex
	next    int // index of the next file to hand out
	failed  []string
	done    totals
	listErr error // why the list ended early, if it did
	fatal   error // an error that must end the whole run
}

func (s *passState) take() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return s.next - 1
}

func (s *passState) nextIndex() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

func (s *passState) addFailed(rel string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = append(s.failed, rel)
}

func (s *passState) addDone(size int64) totals {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done.files++
	s.done.bytes += size
	return s.done
}

func (s *passState) setListErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr == nil {
		s.listErr = err
	}
}

func (s *passState) setFatal(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fatal == nil {
		s.fatal = err
	}
}

// runPass lists the folders and downloads at the same time: the lister runs ahead in its own goroutine and
// the download workers take every file the moment it is found. One worker starts at once; another is added
// every spawnEvery while nothing is transferring data (up to maxSlots), so files whose server hangs
// do not hold up the others. It returns the complete file list, the files that could not be fetched,
// and listErr when the listing stopped early (then files is partial). err is for anything that must end the whole run.
func (c *client) runPass(ctx context.Context, pass int, folders []string, skip map[string]bool, dest string, verified *verifiedSet) (
	files []remoteFile, failed []string, listErr, err error) {
	workCtx, stopWork := context.WithCancel(ctx)
	found := newFeed()
	listerExited := make(chan struct{})
	go func() {
		defer close(listerExited)
		found.finish(c.walkFolders(workCtx, folders, skip, found.add))
	}()
	defer func() {
		stopWork()
		<-listerExited // never leave the lister running: it shares the client with the next pass
	}()

	c.log.Info("pass started", "pass", pass)
	st := &passState{}
	var workers sync.WaitGroup
	var running atomic.Int32
	exited := make(chan struct{}, 1)
	startWorker := func() {
		workers.Add(1)
		running.Add(1)
		go func() {
			defer func() {
				running.Add(-1)
				workers.Done()
				select {
				case exited <- struct{}{}:
				default:
				}
			}()
			c.work(workCtx, st, found, dest, verified, &running, stopWork)
		}()
	}
	// moreWork: some file has not been handed out yet, or the list may still grow. It never turns true again.
	moreWork := func() bool {
		n, _, listed := found.stats()
		return !listed || st.nextIndex() < n
	}
	// claimable: a file is waiting that no worker has taken, so one more worker would have something to do.
	claimable := func() bool {
		n, _, _ := found.stats()
		return st.nextIndex() < n
	}

	startWorker()
	ticker := time.NewTicker(spawnEvery)
	defer ticker.Stop()
	for workCtx.Err() == nil && moreWork() {
		select {
		case <-workCtx.Done():
		case <-exited:
		case <-ticker.C:
			if int(running.Load()) < maxSlots && claimable() && !c.act.busy() {
				c.log.Info("no data is flowing, adding a download slot", "slots", running.Load()+1)
				startWorker()
			}
		}
	}
	workers.Wait()

	st.mu.Lock()
	defer st.mu.Unlock()
	if st.fatal != nil {
		return nil, nil, nil, st.fatal
	}
	if ctx.Err() != nil {
		return nil, nil, nil, ctx.Err()
	}
	found.mu.Lock()
	files = found.files
	found.mu.Unlock()
	return files, st.failed, st.listErr, nil
}

// work is one download slot: it takes files from the list one after another until the list is exhausted.
func (c *client) work(ctx context.Context, st *passState, found *feed, dest string, verified *verifiedSet, running *atomic.Int32, abort context.CancelFunc) {
	for {
		i := st.take()
		f, ok, endErr := found.get(ctx, i)
		if ctx.Err() != nil {
			return
		}
		if !ok {
			st.setListErr(endErr)
			return
		}
		n, bytes, listed := found.stats()
		total := fmt.Sprint(n)
		if !listed {
			total += "+" // the list is still growing
		}
		label := fmt.Sprintf("[%d/%s] %s", i+1, total, f.Rel)
		downloaded, err := c.ensure(ctx, f, dest, label, verified)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !transient(err) {
				st.setFatal(err)
				abort()
				return
			}
			st.addFailed(f.Rel)
			c.log.Error("file failed, skipping it", "file", label, "err", err)
			continue
		}
		done := st.addDone(f.Size)
		if downloaded {
			c.log.Info("progress", "files", fmt.Sprintf("%d/%s", done.files, total),
				"gb", fmt.Sprintf("%.2f/%.2f", float64(done.bytes)/(1<<30), float64(bytes)/(1<<30)), "slots", running.Load())
			if err := sleep(ctx, pauseBetweenFiles); err != nil {
				return
			}
		}
	}
}

// lockState takes an exclusive lock on the state folder, so two copies can never write the same .part files.
// The lock is released when the process ends, however it ends.
func lockState(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another yadisk-download is already running with the state folder %s", dir)
	}
	return f, nil
}

// workDir is the folder holding this binary: everything the tool creates lives inside it,
// so deleting that one folder removes every trace.
func workDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

func main() {
	defaultDir, err := workDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dest := flag.String("dest", filepath.Join(defaultDir, "downloads"), "local folder; each Disk folder lands in <dest>/<its name>")
	stateDir := flag.String("state", filepath.Join(defaultDir, ".state"), "local folder for refresh-token, download.log and the complete marker")
	var excluded []string
	flag.Func("exclude", "full Disk path (e.g. disk:/a/b) to skip; repeat the flag for several", func(p string) error {
		excluded = append(excluded, p)
		return nil
	})
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] disk:/folder1 [disk:/folder2 ...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	tree := flag.String("tree", "", "do not download: print the subfolder names of this Disk folder (e.g. disk:/), then exit")
	depth := flag.Int("depth", 2, "with -tree: how many folder levels to print")
	flag.Parse()

	if clientID == "" || clientSecret == "" || refreshToken == "" {
		fmt.Fprintln(os.Stderr, "credentials are not baked into this binary: build it with build.sh")
		os.Exit(1)
	}
	if *tree == "" && flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logFile, err := os.OpenFile(filepath.Join(*stateDir, "download.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer logFile.Close()
	compactTime := func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			a.Value = slog.StringValue(a.Value.Time().Format("15:04:05"))
		}
		return a
	}
	log := slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, logFile), &slog.HandlerOptions{ReplaceAttr: compactTime}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	c := newClient(log, filepath.Join(*stateDir, "refresh-token"))
	if *tree != "" {
		if err := c.printDirs(ctx, os.Stdout, *tree, *depth, 0); err != nil {
			log.Error("cannot list", "err", err)
			os.Exit(1)
		}
		return
	}

	lock, err := lockState(*stateDir)
	if err != nil {
		log.Error("cannot start", "err", err)
		os.Exit(1)
	}
	defer lock.Close()

	log.Info("start", "folders", strings.Join(flag.Args(), " | "), "excluded", strings.Join(excluded, " | "), "dest", *dest)
	err = c.run(ctx, flag.Args(), excluded, *dest, filepath.Join(*stateDir, "complete"))
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled):
		log.Info("interrupted, run again to resume")
		os.Exit(130)
	default:
		log.Error("stopped", "err", err)
		os.Exit(1)
	}
}
