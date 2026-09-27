package transfer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const maxRecordBytes = 64 << 10

// Journal serializes durable task snapshots under a permanent process lock.
// A failed Save may already have replaced a file; callers must fail closed
// rather than infer that an error means no persistent change occurred.
type Journal struct {
	mu            sync.Mutex
	root          *os.Root
	lock          *os.File
	closed        bool
	closeErr      error
	replace       func(*os.Root, string, string) error
	syncDirectory func(string) error
}

func OpenJournal(directory string) (_ *Journal, retErr error) {
	if directory == "" {
		return nil, errors.New("transfer metadata directory is required")
	}
	if err := createJournalDirectory(directory); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open transfer metadata directory: %w", err)
	}
	keepRoot := false
	defer func() {
		if !keepRoot {
			retErr = errors.Join(retErr, closeJournalResource(root, "directory"))
		}
	}()
	file, err := root.OpenFile("service.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open transfer metadata lock: %w", err)
	}
	keepFile := false
	defer func() {
		if !keepFile {
			retErr = errors.Join(retErr, closeJournalResource(file, "file"))
		}
	}()
	if err := checkJournalFile(root, file, "service.lock"); err != nil {
		return nil, err
	}
	if err := lockJournal(file); err != nil {
		return nil, fmt.Errorf("lock transfer metadata: %w", err)
	}
	keepRoot, keepFile = true, true
	return &Journal{root: root, lock: file, replace: replaceJournalFile, syncDirectory: syncJournalDirectory}, nil
}

func createJournalDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err == nil {
		if !info.IsDir() || !privateJournalMode(info.Mode()) {
			return errors.New("transfer metadata directory must be a private directory, not a symbolic link")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect transfer metadata directory: %w", err)
	}
	parent := filepath.Dir(directory)
	if parent != directory {
		if _, err := os.Stat(parent); errors.Is(err, os.ErrNotExist) {
			if err := createJournalDirectory(parent); err != nil {
				return err
			}
		} else if err != nil {
			return fmt.Errorf("inspect transfer metadata parent: %w", err)
		}
	}
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create transfer metadata directory: %w", err)
	}
	if err := syncJournalDirectory(parent); err != nil {
		return err
	}
	return createJournalDirectory(directory)
}

func checkJournalFile(root *os.Root, file *os.File, name string) error {
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened transfer metadata: %w", err)
	}
	entry, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("inspect transfer metadata entry: %w", err)
	}
	if !opened.Mode().IsRegular() || !entry.Mode().IsRegular() || !os.SameFile(opened, entry) || !privateJournalMode(opened.Mode()) {
		return errors.New("transfer metadata must be a private regular file")
	}
	return nil
}

func (j *Journal) Load(limit int) (_ []Record, retErr error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, ErrClosed
	}
	if limit <= 0 {
		return nil, errors.New("transfer metadata record limit must be positive")
	}
	directory, err := j.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open transfer metadata inventory: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, closeJournalResource(directory, "inventory")) }()
	entries, err := directory.ReadDir(limit + 66)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read transfer metadata inventory: %w", err)
	}
	if len(entries) >= limit+66 {
		return nil, errors.New("transfer metadata directory exceeds inventory limit")
	}
	var records []Record
	for _, entry := range entries {
		name := entry.Name()
		if name == "service.lock" || (strings.HasPrefix(name, ".pending-") && validHex(strings.TrimPrefix(name, ".pending-"), 16)) {
			continue
		}
		if !strings.HasSuffix(name, ".json") || !validHex(strings.TrimSuffix(name, ".json"), 16) {
			return nil, fmt.Errorf("unexpected transfer metadata entry %q", name)
		}
		if len(records) == limit {
			return nil, errors.New("transfer metadata record limit exceeded")
		}
		record, err := j.read(name)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func (j *Journal) read(name string) (_ Record, retErr error) {
	file, err := j.root.Open(name)
	if err != nil {
		return Record{}, fmt.Errorf("open transfer record: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, closeJournalResource(file, "file")) }()
	if err := checkJournalFile(j.root, file, name); err != nil {
		return Record{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil {
		return Record{}, fmt.Errorf("read transfer record: %w", err)
	}
	if len(data) > maxRecordBytes {
		return Record{}, errors.New("transfer record exceeds size limit")
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Record{}, fmt.Errorf("decode transfer record: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("transfer record contains trailing data")
	}
	if record.ID+".json" != name {
		return Record{}, errors.New("transfer record identity does not match its filename")
	}
	if err := record.validate(); err != nil {
		return Record{}, fmt.Errorf("validate transfer record: %w", err)
	}
	return record, nil
}

func (j *Journal) Save(record Record) (retErr error) {
	if err := record.validate(); err != nil {
		return fmt.Errorf("persist transfer record: %w", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode transfer record: %w", err)
	}
	if len(data) > maxRecordBytes {
		return errors.New("transfer record exceeds size limit")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	id, err := randomHex(16)
	if err != nil {
		return err
	}
	temporary := ".pending-" + id
	file, err := j.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create transfer record temporary file: %w", err)
	}
	closed, renamed := false, false
	defer func() {
		if !closed {
			retErr = errors.Join(retErr, closeJournalResource(file, "file"))
		}
		if !renamed {
			if err := j.root.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf("remove temporary transfer record: %w", err))
			}
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write transfer record: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync transfer record: %w", err)
	}
	closed = true
	if err := file.Close(); err != nil {
		return fmt.Errorf("close transfer record: %w", err)
	}
	if err := j.replace(j.root, temporary, record.ID+".json"); err != nil {
		return err
	}
	renamed = true
	return j.syncDirectory(j.root.Name())
}

func (j *Journal) Remove(id string) error {
	if !validHex(id, 16) {
		return errors.New("invalid transfer record identity")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return ErrClosed
	}
	if err := j.root.Remove(id + ".json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove transfer record: %w", err)
	}
	return j.syncDirectory(j.root.Name())
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return j.closeErr
	}
	j.closed = true
	// Closing the lock file releases the OS lock; never unlink its inode.
	j.closeErr = errors.Join(closeJournalResource(j.lock, "lock"), closeJournalResource(j.root, "directory"))
	return j.closeErr
}

func closeJournalResource(closer io.Closer, resource string) error {
	if err := closer.Close(); err != nil {
		return fmt.Errorf("close transfer metadata %s: %w", resource, err)
	}
	return nil
}
