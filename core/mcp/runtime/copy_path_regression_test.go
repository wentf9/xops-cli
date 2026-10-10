package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	coresftp "github.com/wentf9/xops-cli/core/sftp"
)

// The SFTP peer intentionally leaves REALPATH lexical (the library default),
// requiring the copy adapter to resolve symbolic-link referents explicitly.
// Directory metadata is not modeled by InMemHandler; tolerate only Setstat on
// directories. Preserve the peer's POSIX rename support to detect link replacement.
type copyFixtureCommands struct {
	cmd  pkgsftp.FileCmder
	list pkgsftp.FileLister
}

func (c copyFixtureCommands) Filecmd(request *pkgsftp.Request) error {
	if request.Method == "Setstat" {
		entries, err := c.list.Filelist(pkgsftp.NewRequest("Stat", request.Filepath))
		if err != nil {
			return err
		}
		info := make([]os.FileInfo, 1)
		if n, err := entries.ListAt(info, 0); n == 1 && (err == nil || errors.Is(err, io.EOF)) && info[0].IsDir() {
			return nil
		}
	}
	return c.cmd.Filecmd(request)
}
func (c copyFixtureCommands) PosixRename(request *pkgsftp.Request) error {
	if cmd, ok := c.cmd.(pkgsftp.PosixRenameFileCmder); ok {
		return cmd.PosixRename(request)
	}
	return pkgsftp.ErrSSHFxOpUnsupported
}

type copyPathFixture struct {
	ctx    context.Context
	files  *coresftp.Client
	client *mcp.ClientSession
}

func newCopyPathFixture(t *testing.T) copyPathFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = copyFixtureCommands{handlers.FileCmd, handlers.FileList}
	provider := startTransferSSH(t, handlers)
	r, err := NewRuntime(ctx, WithConfigProvider(provider))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)
	connection, err := r.connectFixtureNode(ctx, "files")
	if err != nil {
		t.Fatal(err)
	}
	files, err := coresftp.NewClient(ctx, connection)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := files.Close(); err != nil {
			t.Error(err)
		}
	})
	return copyPathFixture{ctx, files, client}
}

func writeCopyFixtureFile(c *pkgsftp.Client, name, content string) (retErr error) {
	file, err := c.Create(name)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, file.Close()) }()
	_, err = io.WriteString(file, content)
	return err
}
func readCopyFixtureFile(c *pkgsftp.Client, name string) (content string, retErr error) {
	file, err := c.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { retErr = errors.Join(retErr, file.Close()) }()
	data, err := io.ReadAll(file)
	return string(data), err
}
func (f copyPathFixture) copy(t *testing.T, src, dest string) {
	t.Helper()
	result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "xops_fs_cp", Arguments: FSCpInput{NodeID: "files", Src: src, Dest: dest}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		for _, content := range result.Content {
			if text, ok := content.(*mcp.TextContent); ok {
				t.Log(text.Text)
			}
		}
		t.Fatalf("copy %q -> %q failed", src, dest)
	}
}

func TestFSCopyPreservesDestinationFileSymlinks(t *testing.T) {
	for _, test := range []struct{ name, dest, target string }{
		{"direct absolute", "/destination", "/targets/config"},
		{"direct relative", "/destination", "targets/config"},
		{"destination link chain", "/destination", "/targets/alias"},
		{"inside destination directory", "/backup", "../targets/config"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCopyPathFixture(t)
			link := "/destination"
			if test.dest == "/backup" {
				link = "/backup/source"
			}
			if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
				if err := c.MkdirAll("/targets"); err != nil {
					return err
				}
				if err := c.MkdirAll("/backup"); err != nil {
					return err
				}
				if err := writeCopyFixtureFile(c, "/source", "new contents"); err != nil {
					return err
				}
				if err := writeCopyFixtureFile(c, "/targets/config", "old contents"); err != nil {
					return err
				}
				if test.target == "/targets/alias" {
					if err := c.Symlink("config", "/targets/alias"); err != nil {
						return err
					}
				}
				return c.Symlink(test.target, link)
			}); err != nil {
				t.Fatal(err)
			}
			f.copy(t, "/source", test.dest)
			if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
				info, err := c.Lstat(link)
				if err != nil {
					return err
				}
				if info.Mode()&os.ModeSymlink == 0 {
					return fmt.Errorf("destination link replaced: %q", link)
				}
				target, err := c.ReadLink(link)
				if err != nil {
					return err
				}
				if target != test.target {
					return fmt.Errorf("destination link target changed: %q", target)
				}
				content, err := readCopyFixtureFile(c, "/targets/config")
				if err != nil {
					return err
				}
				if content != "new contents" {
					return fmt.Errorf("target not updated: %q", content)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFSCopyDirectoryQualifiedSymlinkSources(t *testing.T) {
	for _, test := range []struct {
		name, src, dest, want string
		existing              bool
	}{
		{"slash new destination", "/link/", "/new", "/new/file", false},
		{"slash existing destination", "/link/", "/backup", "/backup/link/file", true},
		{"slash repeated", "/link///", "/backup", "/backup/link/file", true},
		{"dot new destination", "/link/.", "/new", "/new/file", false},
		{"dot existing destination", "/link/.", "/backup", "/backup/file", true},
		{"dot with slash", "/link/.//", "/backup", "/backup/file", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCopyPathFixture(t)
			if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
				if err := c.MkdirAll("/actual"); err != nil {
					return err
				}
				if test.existing {
					if err := c.MkdirAll(test.dest); err != nil {
						return err
					}
				}
				if err := writeCopyFixtureFile(c, "/actual/file", "source contents"); err != nil {
					return err
				}
				return c.Symlink("/actual", "/link")
			}); err != nil {
				t.Fatal(err)
			}
			f.copy(t, test.src, test.dest)
			if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
				info, err := c.Lstat(path.Dir(test.want))
				if err != nil {
					return err
				}
				if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("destination is not an independent directory: %v", info.Mode())
				}
				content, err := readCopyFixtureFile(c, test.want)
				if err != nil {
					return err
				}
				if content != "source contents" {
					return fmt.Errorf("wrong copied contents: %q", content)
				}
				if err := writeCopyFixtureFile(c, test.want, "changed copy"); err != nil {
					return err
				}
				original, err := readCopyFixtureFile(c, "/actual/file")
				if err != nil {
					return err
				}
				if original != "source contents" {
					return fmt.Errorf("directory copy still aliases source: %q", original)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFSCopyPreservesLiteralPathCharacters(t *testing.T) {
	for _, name := range []string{". ", ".\t", ".\\", "\\.", "report ", "report\\"} {
		t.Run(name, func(t *testing.T) {
			f := newCopyPathFixture(t)
			if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
				if err := c.MkdirAll("/data"); err != nil {
					return err
				}
				if err := c.MkdirAll("/backup"); err != nil {
					return err
				}
				if err := writeCopyFixtureFile(c, "/data/unrelated", "must not copy"); err != nil {
					return err
				}
				return writeCopyFixtureFile(c, "/data/"+name, "literal file")
			}); err != nil {
				t.Fatal(err)
			}
			f.copy(t, "/data/"+name, "/backup")
			if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
				entries, err := c.ReadDir("/backup")
				if err != nil {
					return err
				}
				if len(entries) != 1 || entries[0].Name() != name {
					names := make([]string, len(entries))
					for i, entry := range entries {
						names[i] = entry.Name()
					}
					return fmt.Errorf("copied entries %q instead of literal %q", names, name)
				}
				content, err := readCopyFixtureFile(c, "/backup/"+name)
				if err != nil {
					return err
				}
				if content != "literal file" {
					return fmt.Errorf("wrong literal file contents: %q", content)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFSCopyUnqualifiedSourceLinkRemainsALink(t *testing.T) {
	f := newCopyPathFixture(t)
	if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
		if err := writeCopyFixtureFile(c, "/source-target", "source target"); err != nil {
			return err
		}
		if err := writeCopyFixtureFile(c, "/untouched-target", "destination target"); err != nil {
			return err
		}
		if err := c.Symlink("/source-target", "/source-link"); err != nil {
			return err
		}
		return c.Symlink("/untouched-target", "/destination-link")
	}); err != nil {
		t.Fatal(err)
	}
	f.copy(t, "/source-link", "/destination-link")
	if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
		target, err := c.ReadLink("/destination-link")
		if err != nil {
			return err
		}
		if target != "/source-target" {
			return fmt.Errorf("source link was dereferenced: %q", target)
		}
		content, err := readCopyFixtureFile(c, "/untouched-target")
		if err != nil {
			return err
		}
		if content != "destination target" {
			return fmt.Errorf("unqualified source link overwrote destination target: %q", content)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFSCopyRejectsDanglingDestinationLinkWithoutReplacingIt(t *testing.T) {
	f := newCopyPathFixture(t)
	if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
		if err := writeCopyFixtureFile(c, "/source", "source data"); err != nil {
			return err
		}
		return c.Symlink("/missing", "/destination")
	}); err != nil {
		t.Fatal(err)
	}
	result, err := f.client.CallTool(f.ctx, &mcp.CallToolParams{Name: "xops_fs_cp", Arguments: FSCpInput{NodeID: "files", Src: "/source", Dest: "/destination"}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("dangling destination link was silently replaced")
	}
	if err := f.files.Do(f.ctx, func(c *pkgsftp.Client) error {
		target, err := c.ReadLink("/destination")
		if err != nil {
			return err
		}
		if target != "/missing" {
			return fmt.Errorf("dangling link target changed: %q", target)
		}
		if _, err := c.Lstat("/missing"); err == nil {
			return fmt.Errorf("copy unexpectedly created dangling target")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect dangling target: %w", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
