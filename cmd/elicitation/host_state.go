package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	hostStateMaxScopes   = 16
	hostStateMaxRecords  = 128
	hostStateMaxBytes    = 8 << 20
	hostStateTTL         = 15 * time.Minute
	hostStateLockTimeout = 5 * time.Second
)

type pinnedRequest struct {
	Request O
	Bodies  map[string][]byte
}
type hostRecord struct {
	Pinned  pinnedRequest
	Expires time.Time
}
type hostDisk struct {
	Scope   string
	Records map[string]hostRecord
}
type hostState struct {
	mu   sync.Mutex
	path string
	lock *os.File
	disk hostDisk
}

// Storage pins caller-accepted originals; it does not authenticate or validate envelopes.
func openHostState(ctx context.Context, endpoint, token, explicitPath string) (*hostState, error) {
	scopeBytes, _ := json.Marshal([]string{endpoint, token})
	digest := sha256.Sum256(scopeBytes)
	scope := hex.EncodeToString(digest[:])
	path := explicitPath
	root := ""
	if path == "" {
		temp, err := filepath.EvalSymlinks(os.TempDir())
		if err != nil {
			return nil, err
		}
		root = filepath.Join(temp, fmt.Sprintf("ahp-elicitation-host-%d", os.Getuid()))
		path = filepath.Join(root, scope, "state.json")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// Resolve only the OS-provided temp prefix (e.g. macOS /var), never
	// caller-controlled directory or file symlinks below that prefix.
	temp := filepath.Clean(os.TempDir())
	if strings.HasPrefix(path, temp+string(os.PathSeparator)) {
		realTemp, err := filepath.EvalSymlinks(temp)
		if err != nil {
			return nil, err
		}
		path = filepath.Join(realTemp, strings.TrimPrefix(path, temp+string(os.PathSeparator)))
	}
	dir := filepath.Dir(path)
	lockDir := dir
	if root != "" {
		lockDir = root
	}
	if err := hostPrivateDir(lockDir); err != nil {
		return nil, err
	}
	lock, err := hostOpenPrivate(filepath.Join(lockDir, ".host-state.lock"), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	deadline := time.NewTimer(hostStateLockTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			lock.Close()
			return nil, err
		}
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			lock.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			lock.Close()
			return nil, ctx.Err()
		case <-deadline.C:
			lock.Close()
			return nil, errors.New("host state lock timeout")
		case <-ticker.C:
		}
	}
	s := &hostState{path: path, lock: lock, disk: hostDisk{Scope: scope, Records: map[string]hostRecord{}}}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	if root != "" {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		count := 0
		for _, entry := range entries {
			if entry.Name() == ".host-state.lock" {
				continue
			}
			if len(entry.Name()) != 64 || !entry.IsDir() {
				return nil, errors.New("unexpected host state scope entry")
			}
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			// All scope operations hold the root lock; stale scopes cannot be in use.
			if entry.Name() != scope && time.Since(info.ModTime()) >= hostStateTTL {
				if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
					return nil, err
				}
				continue
			}
			count++
		}
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) && count >= hostStateMaxScopes {
			return nil, errors.New("host state scope limit exceeded")
		}
		if err := hostPrivateDir(dir); err != nil {
			return nil, err
		}
	}
	f, err := hostOpenPrivate(path, os.O_RDONLY)
	if err == nil {
		raw, readErr := io.ReadAll(io.LimitReader(f, hostStateMaxBytes+1))
		f.Close()
		if readErr != nil {
			return nil, readErr
		}
		if len(raw) > hostStateMaxBytes {
			return nil, errors.New("host state byte limit exceeded")
		}
		if err := json.Unmarshal(raw, &s.disk); err != nil {
			return nil, fmt.Errorf("invalid host state: %w", err)
		}
		if s.disk.Scope != scope {
			return nil, errors.New("host state endpoint/token scope mismatch")
		}
		if len(s.disk.Records) > hostStateMaxRecords {
			return nil, errors.New("host state record limit exceeded")
		}
		if s.disk.Records == nil {
			s.disk.Records = map[string]hostRecord{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.prune() {
		if err := s.write(); err != nil {
			return nil, err
		}
	}
	ok = true
	return s, nil
}

func hostPrivateDir(path string) error {
	for p := path; p != filepath.Dir(p); p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
			return errors.New("host state directory contains symlink or non-directory")
		}
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0700 || !ok || stat.Uid != uint32(os.Getuid()) {
		return errors.New("host state directory must be owned by current user and mode 0700")
	}
	return nil
}

func hostOpenPrivate(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		f.Close()
		return nil, errors.New("host state file must be private, regular and exclusively owned")
	}
	return f, nil
}

func hostKey(message O, result bool) (string, error) {
	event := obj(obj(message["params"])["event"])
	field := "id"
	if result {
		field = "parentEventId"
	}
	source, id := str(event["source"]), str(event[field])
	if source == "" || id == "" {
		return "", errors.New("host state requires source and request correlation id")
	}
	key, _ := json.Marshal([]string{source, id})
	return string(key), nil
}
func (s *hostState) prune() bool {
	changed := false
	for key, r := range s.disk.Records {
		if !time.Now().Before(r.Expires) {
			delete(s.disk.Records, key)
			changed = true
		}
	}
	return changed
}
func (s *hostState) write() error {
	raw, err := json.Marshal(s.disk)
	if err != nil {
		return err
	}
	if len(raw) > hostStateMaxBytes {
		return errors.New("host state byte limit exceeded")
	}
	if f, err := hostOpenPrivate(s.path, os.O_RDONLY); err == nil {
		f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(filepath.Dir(s.path), now, now)
}
func (s *hostState) put(p pinnedRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return errors.New("host state closed")
	}
	key, err := hostKey(p.Request, false)
	if err != nil {
		return err
	}
	if len(p.Bodies) > 1 {
		return errors.New("host state stores only the selected original body")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(raw) > hostStateMaxBytes {
		return errors.New("host state byte limit exceeded")
	}
	var owned pinnedRequest
	if err = json.Unmarshal(raw, &owned); err != nil {
		return err
	}
	s.prune()
	if previous, exists := s.disk.Records[key]; exists {
		old, _ := json.Marshal(previous.Pinned)
		if bytes.Equal(old, raw) {
			return nil
		}
		return errors.New("host state original request already pinned with different content")
	}
	if len(s.disk.Records) >= hostStateMaxRecords {
		return errors.New("host state record limit exceeded")
	}
	s.disk.Records[key] = hostRecord{Pinned: owned, Expires: time.Now().Add(hostStateTTL)}
	if err = s.write(); err != nil {
		delete(s.disk.Records, key)
		return err
	}
	return nil
}
func (s *hostState) get(result O) (pinnedRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return pinnedRequest{}, errors.New("host state closed")
	}
	key, err := hostKey(result, true)
	if err != nil {
		return pinnedRequest{}, err
	}
	if s.prune() {
		if err = s.write(); err != nil {
			return pinnedRequest{}, err
		}
	}
	r, ok := s.disk.Records[key]
	if !ok {
		return pinnedRequest{}, errors.New("missing prior host-owned elicitation request")
	}
	raw, err := json.Marshal(r.Pinned)
	if err != nil {
		return pinnedRequest{}, err
	}
	var p pinnedRequest
	err = json.Unmarshal(raw, &p)
	return p, err
}
func (s *hostState) remove(result O) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return errors.New("host state closed")
	}
	key, err := hostKey(result, true)
	if err != nil {
		return err
	}
	prior, exists := s.disk.Records[key]
	delete(s.disk.Records, key)
	s.prune()
	if err = s.write(); err != nil {
		if exists {
			s.disk.Records[key] = prior
		}
		return err
	}
	return nil
}
func (s *hostState) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	f := s.lock
	s.lock = nil
	unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	closeErr := f.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
