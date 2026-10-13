package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDisk imitates the parts of Yandex.Disk and its OAuth server that the downloader touches.
type fakeDisk struct {
	t     *testing.T
	srv   *httptest.Server
	files map[string][]byte // remote path relative to the root, e.g. "sub/b.mkv"

	mu            sync.Mutex
	tokenCalls    int
	blobHits      int
	ranges        []string
	ignoreRange   bool // answer 200 with the whole body even when Range is requested
	corruptOnce   bool // first blob response has a flipped byte
	expireOnce    bool // first API request answers 401
	rotateRefresh bool // token endpoint returns a new refresh token

	broken map[string]bool // files whose content always answers 500

	failListing    map[string]int // folder (relative to root) -> how many listing requests still answer 500
	holdListing    string         // listing of this folder (relative to root) waits until some file content has been served
	firstBlob      chan struct{}  // closed when the first file content is requested
	firstBlobOnce  sync.Once
	releasedByBlob bool // the held listing was released by a download, not by the timeout

	hang      map[string]bool // content requests for these files wait until release is closed
	release   chan struct{}
	hungNow   int    // requests waiting right now
	hungPeak  int    // the most requests that ever waited at once
	slowFile  string // this file is streamed in small chunks with pauses (about 1.2 s in all)
	eventsLog []string
}

func (d *fakeDisk) event(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.eventsLog = append(d.eventsLog, name)
}

func (d *fakeDisk) eventIndex(name string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, e := range d.eventsLog {
		if e == name {
			return i
		}
	}
	return -1
}

const root = "disk:/root"

func newFakeDisk(t *testing.T, files map[string][]byte) *fakeDisk {
	t.Helper()
	d := &fakeDisk{t: t, files: files, firstBlob: make(chan struct{}), release: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", d.handleToken)
	mux.HandleFunc("/v1/disk/resources/download", d.handleLink)
	mux.HandleFunc("/v1/disk/resources", d.handleList)
	mux.HandleFunc("/blob/", d.handleBlob)
	d.srv = httptest.NewServer(mux)
	t.Cleanup(d.srv.Close)
	return d
}

func (d *fakeDisk) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokenCalls++
	if r.Form.Get("refresh_token") != "good-refresh" || r.Form.Get("client_id") != "cid" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	payload := map[string]string{"access_token": "acc"}
	if d.rotateRefresh {
		payload["refresh_token"] = "rotated-refresh"
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func (d *fakeDisk) authorized(w http.ResponseWriter, r *http.Request) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.expireOnce || r.Header.Get("Authorization") != "OAuth acc" {
		d.expireOnce = false
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func hexSum(sum []byte) string { return hex.EncodeToString(sum) }

func (d *fakeDisk) handleList(w http.ResponseWriter, r *http.Request) {
	if !d.authorized(w, r) {
		return
	}
	if !strings.HasPrefix(r.URL.Query().Get("path"), root) {
		http.NotFound(w, r)
		return
	}
	dir := strings.TrimPrefix(strings.TrimPrefix(r.URL.Query().Get("path"), root), "/")
	if d.failListing[dir] > 0 {
		d.failListing[dir]--
		http.Error(w, "temporarily broken", http.StatusInternalServerError)
		return
	}
	if d.holdListing != "" && dir == d.holdListing {
		select {
		case <-d.firstBlob:
			d.mu.Lock()
			d.releasedByBlob = true
			d.mu.Unlock()
		case <-time.After(5 * time.Second):
		}
	}
	var items []map[string]any
	seenDirs := map[string]bool{}
	for rel, data := range d.files {
		inside, ok := strings.CutPrefix(rel, dir)
		if dir != "" {
			inside, ok = strings.CutPrefix(rel, dir+"/")
		}
		if !ok {
			continue
		}
		if name, _, nested := strings.Cut(inside, "/"); nested {
			if !seenDirs[name] {
				seenDirs[name] = true
				items = append(items, map[string]any{"name": name, "path": root + "/" + strings.TrimPrefix(dir+"/"+name, "/"), "type": "dir"})
			}
			continue
		}
		m, s := md5.Sum(data), sha256.Sum256(data)
		items = append(items, map[string]any{
			"name": inside, "path": root + "/" + rel, "type": "file", "size": len(data),
			"md5": hexSum(m[:]), "sha256": hexSum(s[:]),
		})
	}
	// deterministic order and real pagination
	sortItems(items)
	offset, limit := atoi(r.URL.Query().Get("offset")), atoi(r.URL.Query().Get("limit"))
	end := min(offset+limit, len(items))
	page := items[min(offset, len(items)):end]
	_ = json.NewEncoder(w).Encode(map[string]any{"_embedded": map[string]any{"items": page, "total": len(items)}})
}

func sortItems(items []map[string]any) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j]["name"].(string) < items[j-1]["name"].(string); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func atoi(s string) int {
	var n int
	_, _ = fmt.Sscan(s, &n)
	return n
}

func (d *fakeDisk) handleLink(w http.ResponseWriter, r *http.Request) {
	if !d.authorized(w, r) {
		return
	}
	rel := strings.TrimPrefix(r.URL.Query().Get("path"), root+"/")
	_ = json.NewEncoder(w).Encode(map[string]string{"href": d.srv.URL + "/blob/" + rel})
}

func (d *fakeDisk) handleBlob(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/blob/")
	data, ok := d.files[rel]
	if !ok {
		http.NotFound(w, r)
		return
	}
	d.firstBlobOnce.Do(func() { close(d.firstBlob) })
	if d.broken[rel] {
		http.Error(w, "file IO failure: no more reliable hosts", http.StatusInternalServerError)
		return
	}
	d.event("start:" + rel)
	defer d.event("end:" + rel)
	if d.hang[rel] {
		d.mu.Lock()
		d.hungNow++
		d.hungPeak = max(d.hungPeak, d.hungNow)
		d.mu.Unlock()
		select {
		case <-d.release:
		case <-r.Context().Done():
		}
		d.mu.Lock()
		d.hungNow--
		d.mu.Unlock()
	}
	if rel == d.slowFile {
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		for chunk := 0; chunk < len(data); chunk += len(data) / 40 {
			end := min(chunk+len(data)/40, len(data))
			_, _ = w.Write(data[chunk:end])
			w.(http.Flusher).Flush()
			time.Sleep(30 * time.Millisecond)
		}
		return
	}
	d.mu.Lock()
	d.blobHits++
	d.ranges = append(d.ranges, r.Header.Get("Range"))
	if d.ignoreRange {
		r.Header.Del("Range")
	}
	if d.corruptOnce {
		d.corruptOnce = false
		data = append([]byte(nil), data...)
		data[len(data)/2] ^= 0xff
	}
	d.mu.Unlock()
	http.ServeContent(w, r, rel, time.Time{}, bytes.NewReader(data))
}

func payload(seed byte, size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = seed + byte(i*7)
	}
	return data
}

type env struct {
	disk      *fakeDisk
	client    *client
	parent    string // what -dest points at
	dest      string // parent/root: where the mirrored `root` folder lands
	tokenFile string
	marker    string
}

func setup(t *testing.T, files map[string][]byte) *env {
	t.Helper()
	d := newFakeDisk(t, files)
	oldVals := [...]any{apiBase, tokenURL, pauseBetweenFiles, passPause, idleTimeout, pageSize, clientID, clientSecret, refreshToken}
	oldSlots, oldSpawn, oldWindow := maxSlots, spawnEvery, activeWindow
	apiBase, tokenURL = d.srv.URL+"/v1/disk", d.srv.URL+"/token"
	pauseBetweenFiles, passPause, idleTimeout, pageSize = 0, 10*time.Millisecond, 5*time.Second, 2
	spawnEvery = time.Hour // one worker, like before; the slot tests shorten this
	clientID, clientSecret, refreshToken = "cid", "secret", "good-refresh"
	t.Cleanup(func() {
		maxSlots, spawnEvery, activeWindow = oldSlots, oldSpawn, oldWindow
		apiBase, tokenURL = oldVals[0].(string), oldVals[1].(string)
		pauseBetweenFiles, passPause, idleTimeout = oldVals[2].(time.Duration), oldVals[3].(time.Duration), oldVals[4].(time.Duration)
		pageSize = oldVals[5].(int)
		clientID, clientSecret, refreshToken = oldVals[6].(string), oldVals[7].(string), oldVals[8].(string)
	})
	tmp := t.TempDir()
	e := &env{disk: d, parent: tmp, dest: filepath.Join(tmp, "root"), tokenFile: filepath.Join(tmp, "state", "refresh-token"), marker: filepath.Join(tmp, "state", "complete")}
	e.client = newClient(slog.New(slog.NewTextHandler(io.Discard, nil)), e.tokenFile)
	return e
}

func (e *env) run(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return e.client.run(ctx, []string{root}, nil, e.parent, e.marker)
}

func (e *env) assertMirrored(t *testing.T) {
	t.Helper()
	for rel, want := range e.disk.files {
		got, err := os.ReadFile(filepath.Join(e.dest, filepath.FromSlash(rel)))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: content mismatch (err=%v)", rel, err)
		}
	}
	if parts, _ := filepath.Glob(filepath.Join(e.dest, "*", "*.part")); len(parts) != 0 {
		t.Errorf("leftover .part files: %v", parts)
	}
}

func testFiles() map[string][]byte {
	return map[string][]byte{
		"a.mkv":       payload(1, 3<<20+123),
		"b.mkv":       payload(2, 1000),
		"sub/c.mkv":   payload(3, 2<<20),
		"sub/d.mkv":   payload(4, 5),
		"empty.mkv":   {},
		"sub/e/f.mp4": payload(5, 777),
	}
}

func TestMirrorsEverythingThenSkipsVerifiedFiles(t *testing.T) {
	e := setup(t, testFiles())
	e.disk.rotateRefresh = true
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
	if _, err := os.Stat(e.marker); err != nil {
		t.Errorf("completion marker missing: %v", err)
	}
	saved, _ := os.ReadFile(e.tokenFile)
	if strings.TrimSpace(string(saved)) != "rotated-refresh" {
		t.Errorf("rotated refresh token not saved, got %q", saved)
	}

	hits := e.disk.blobHits
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if e.disk.blobHits != hits {
		t.Errorf("second run downloaded again: %d -> %d blob requests", hits, e.disk.blobHits)
	}
}

func TestResumesPartialDownload(t *testing.T) {
	files := map[string][]byte{"a.mkv": payload(1, 3<<20)}
	e := setup(t, files)
	if err := os.MkdirAll(e.dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dest, "a.mkv.part"), files["a.mkv"][:1<<20], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
	if len(e.disk.ranges) != 1 || e.disk.ranges[0] != fmt.Sprintf("bytes=%d-", 1<<20) {
		t.Errorf("expected one ranged request, got %q", e.disk.ranges)
	}
}

func TestServerThatIgnoresRangeRestartsFromZero(t *testing.T) {
	files := map[string][]byte{"a.mkv": payload(1, 3<<20)}
	e := setup(t, files)
	e.disk.ignoreRange = true
	_ = os.MkdirAll(e.dest, 0o755)
	_ = os.WriteFile(filepath.Join(e.dest, "a.mkv.part"), files["a.mkv"][:1<<20], 0o644)
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
}

func TestPartLargerThanRemoteIsDiscarded(t *testing.T) {
	files := map[string][]byte{"a.mkv": payload(1, 1000)}
	e := setup(t, files)
	_ = os.MkdirAll(e.dest, 0o755)
	_ = os.WriteFile(filepath.Join(e.dest, "a.mkv.part"), payload(9, 5000), 0o644)
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
}

func TestDifferentLocalCopyIsReplaced(t *testing.T) {
	files := map[string][]byte{"a.mkv": payload(1, 5000)}
	e := setup(t, files)
	_ = os.MkdirAll(e.dest, 0o755)
	same := payload(1, 5000)
	same[100] ^= 1 // same size, one flipped byte: only a checksum notices
	_ = os.WriteFile(filepath.Join(e.dest, "a.mkv"), same, 0o644)
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
}

func TestCorruptDownloadIsRetriedOnNextPass(t *testing.T) {
	e := setup(t, map[string][]byte{"a.mkv": payload(1, 4<<20)})
	e.disk.corruptOnce = true
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
	if e.disk.blobHits != 2 {
		t.Errorf("expected exactly two downloads (corrupt + good), got %d", e.disk.blobHits)
	}
}

func TestUnservableFileIsSkippedThenReportedAndRerunFetchesIt(t *testing.T) {
	e := setup(t, testFiles())
	e.disk.broken = map[string]bool{"b.mkv": true}
	if err := e.run(t); err == nil || !strings.Contains(err.Error(), "1 of") {
		t.Fatalf("want an error naming the missing file count, got %v", err)
	}
	if _, err := os.Stat(e.marker); err == nil {
		t.Error("completion marker must not exist while a file is missing")
	}
	if _, err := os.ReadFile(filepath.Join(e.dest, "sub", "c.mkv")); err != nil {
		t.Errorf("other files must still be downloaded: %v", err)
	}

	e.disk.broken = nil // Yandex restored the file
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
}

func TestSeveralFoldersAndExclusionsInOneRun(t *testing.T) {
	e := setup(t, testFiles())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	folders := []string{root, root + "/sub"}
	if err := e.client.run(ctx, folders, []string{root + "/sub/e", root + "/b.mkv"}, e.parent, e.marker); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"root/a.mkv", "root/sub/c.mkv", "sub/c.mkv", "sub/d.mkv"} {
		if _, err := os.Stat(filepath.Join(e.parent, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s must be downloaded: %v", rel, err)
		}
	}
	for _, rel := range []string{"root/b.mkv", "root/sub/e", "sub/e"} {
		if _, err := os.Stat(filepath.Join(e.parent, filepath.FromSlash(rel))); err == nil {
			t.Errorf("%s is excluded and must not exist", rel)
		}
	}
	if _, err := os.Stat(e.marker); err != nil {
		t.Errorf("completion marker missing: %v", err)
	}
}

func TestDownloadingStartsBeforeListingFinishes(t *testing.T) {
	e := setup(t, testFiles())
	e.disk.holdListing = "sub" // the lister cannot enter "sub" until a download has begun
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
	e.disk.mu.Lock()
	released := e.disk.releasedByBlob
	e.disk.mu.Unlock()
	if !released {
		t.Error("listing finished first: downloads did not run alongside it")
	}
}

func TestListingThatFailsMidwayNeverDeclaresDone(t *testing.T) {
	e := setup(t, testFiles())
	e.disk.failListing = map[string]int{"sub": 100} // "sub" cannot be listed at all, 500 every time
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := e.client.run(ctx, []string{root}, nil, e.parent, e.marker)
	if err == nil {
		t.Fatal("run must not succeed while a folder cannot be listed")
	}
	if _, statErr := os.Stat(e.marker); statErr == nil {
		t.Error("completion marker must not exist with an incomplete list")
	}
	if _, readErr := os.ReadFile(filepath.Join(e.dest, "a.mkv")); readErr != nil {
		t.Errorf("files found before the failure must still be downloaded: %v", readErr)
	}
}

func TestAHangingFileDoesNotHoldUpTheOthers(t *testing.T) {
	e := setup(t, testFiles())
	spawnEvery = 30 * time.Millisecond
	e.disk.hang = map[string]bool{"a.mkv": true} // the first file never delivers data until released
	result := make(chan error, 1)
	go func() { result <- e.run(t) }()

	others := []string{"b.mkv", "sub/c.mkv", "sub/d.mkv", "sub/e/f.mp4"}
	deadline := time.Now().Add(3 * time.Second)
	for missing := len(others); missing > 0 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
		missing = 0
		for _, rel := range others {
			if _, err := os.Stat(filepath.Join(e.dest, filepath.FromSlash(rel))); err != nil {
				missing++
			}
		}
	}
	for _, rel := range others {
		if _, err := os.Stat(filepath.Join(e.dest, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s was not downloaded while a.mkv hung: %v", rel, err)
		}
	}
	close(e.disk.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
}

func TestSlotsStopAtTheLimit(t *testing.T) {
	e := setup(t, testFiles())
	spawnEvery, maxSlots = 20*time.Millisecond, 3
	e.disk.hang = map[string]bool{"a.mkv": true, "b.mkv": true, "sub/c.mkv": true, "sub/d.mkv": true, "sub/e/f.mp4": true}
	result := make(chan error, 1)
	go func() { result <- e.run(t) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		e.disk.mu.Lock()
		hung := e.disk.hungNow
		e.disk.mu.Unlock()
		if hung == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // time for a fourth slot to appear, if the limit were broken
	e.disk.mu.Lock()
	peak := e.disk.hungPeak
	e.disk.mu.Unlock()
	if peak != 3 {
		t.Errorf("most requests waiting at once = %d, want exactly 3", peak)
	}
	close(e.disk.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
}

func TestNoNewSlotWhileDataFlows(t *testing.T) {
	e := setup(t, testFiles())
	spawnEvery, activeWindow = 100*time.Millisecond, 600*time.Millisecond
	e.disk.slowFile = "a.mkv" // streams for about 1.2 s, steadily
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
	endA, startB := e.disk.eventIndex("end:a.mkv"), e.disk.eventIndex("start:b.mkv")
	if endA < 0 || startB < 0 || startB < endA {
		t.Errorf("b.mkv was requested while a.mkv was still streaming (end:a at %d, start:b at %d)", endA, startB)
	}
}

func TestReserveSpaceCountsTheOtherDownloads(t *testing.T) {
	e := setup(t, nil)
	old := freeBytes
	freeBytes = func(string) (uint64, error) { return 5 << 30, nil }
	t.Cleanup(func() { freeBytes = old })

	release, err := e.client.reserveSpace("x", 2<<30, "one") // 2 GiB + the 2 GiB margin fit into 5 GiB
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.reserveSpace("x", 2<<30, "two"); err == nil || !transient(err) {
		t.Errorf("a second 2 GiB file must wait (temporary error), got %v", err)
	}
	if _, err := e.client.reserveSpace("x", 4<<30, "huge"); err == nil || transient(err) {
		t.Errorf("a 4 GiB file can never fit: want a fatal error, got %v", err)
	}
	release()
	if _, err := e.client.reserveSpace("x", 2<<30, "two"); err != nil {
		t.Errorf("after the first download ended there is room again: %v", err)
	}
}

func TestOnlyOneCopyCanUseAStateFolder(t *testing.T) {
	dir := t.TempDir()
	first, err := lockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockState(dir); err == nil {
		t.Error("a second copy must not get the lock")
	}
	first.Close()
	again, err := lockState(dir)
	if err != nil {
		t.Fatalf("the lock must be free after the first copy ended: %v", err)
	}
	again.Close()
}

func TestTwoFoldersWithTheSameNameAreRefused(t *testing.T) {
	e := setup(t, testFiles())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := e.client.run(ctx, []string{root, "disk:/other/root"}, nil, e.parent, e.marker)
	if err == nil || !strings.Contains(err.Error(), "both named") {
		t.Fatalf("want a same-name error, got %v", err)
	}
}

func TestReauthorizesOnUnauthorized(t *testing.T) {
	e := setup(t, map[string][]byte{"a.mkv": payload(1, 100)})
	e.disk.expireOnce = true
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
	if e.disk.tokenCalls != 2 {
		t.Errorf("expected 2 token exchanges, got %d", e.disk.tokenCalls)
	}
}

func TestRejectedRefreshTokenIsFatal(t *testing.T) {
	e := setup(t, map[string][]byte{"a.mkv": payload(1, 100)})
	refreshToken = "revoked"
	err := e.run(t)
	var fatal *fatalError
	if !errors.As(err, &fatal) || !errors.Is(err, errRejected) {
		t.Fatalf("expected fatal rejected error, got %v", err)
	}
}

func TestSavedRefreshTokenIsTriedFirstAndBakedOneIsFallback(t *testing.T) {
	e := setup(t, map[string][]byte{"a.mkv": payload(1, 100)})
	_ = os.MkdirAll(filepath.Dir(e.tokenFile), 0o700)
	_ = os.WriteFile(e.tokenFile, []byte("stale-saved\n"), 0o600)
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e.assertMirrored(t)
	if e.disk.tokenCalls != 2 {
		t.Errorf("expected stale saved token then baked token, got %d exchanges", e.disk.tokenCalls)
	}
}

func TestMissingRemoteFolderIsFatal(t *testing.T) {
	e := setup(t, testFiles())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := e.client.run(ctx, []string{"disk:/nope"}, nil, e.parent, e.marker)
	var fatal *fatalError
	if !errors.As(err, &fatal) {
		t.Fatalf("expected fatal error, got %v", err)
	}
}

func TestVerify(t *testing.T) {
	data := payload(1, 1000)
	m, s := md5.Sum(data), sha256.Sum256(data)
	good := remoteFile{Size: 1000, MD5: hexSum(m[:]), SHA256: hexSum(s[:])}
	path := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(path, data, 0o644)

	tests := []struct {
		name    string
		mutate  func(*remoteFile)
		wantErr bool
	}{
		{"ok", func(*remoteFile) {}, false},
		{"only md5", func(f *remoteFile) { f.SHA256 = "" }, false},
		{"wrong size", func(f *remoteFile) { f.Size = 999 }, true},
		{"wrong md5", func(f *remoteFile) { f.MD5 = strings.Repeat("0", 32) }, true},
		{"wrong sha256", func(f *remoteFile) { f.SHA256 = strings.Repeat("0", 64) }, true},
		{"no checksums", func(f *remoteFile) { f.MD5, f.SHA256 = "", "" }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := good
			tt.mutate(&f)
			if err := verify(path, f); (err != nil) != tt.wantErr {
				t.Errorf("verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidName(t *testing.T) {
	tests := map[string]bool{
		"2025-11-28 15-59-16.mkv":     true,
		"2024-08-15 !!! БИЛД !!!.mkv": true,
		"":                            false,
		".":                           false,
		"..":                          false,
		"a/b":                         false,
		"../etc":                      false,
	}
	for name, want := range tests {
		if got := validName(name); got != want {
			t.Errorf("validName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPrintDirs(t *testing.T) {
	e := setup(t, testFiles())
	tests := []struct {
		depth int
		want  string
	}{
		{1, "sub/\n"},
		{2, "sub/\n  e/\n"},
	}
	for _, tt := range tests {
		var out bytes.Buffer
		if err := e.client.printDirs(context.Background(), &out, root, tt.depth, 0); err != nil {
			t.Fatal(err)
		}
		if out.String() != tt.want {
			t.Errorf("depth %d: got %q, want %q", tt.depth, out.String(), tt.want)
		}
	}
}
