package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/gensometa/masktext/internal/mask"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const maxBytes = 32 * 1024 * 1024

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	fs := flag.NewFlagSet("masktext", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var file, text, out, config string
	var force, check, stats, phone, showVersion bool
	for _, n := range []string{"f", "file"} {
		fs.StringVar(&file, n, "", "Input UTF-8 file; - reads stdin")
	}
	for _, n := range []string{"t", "text"} {
		fs.StringVar(&text, n, "", "Input literal text (visible in shell history/process arguments)")
	}
	for _, n := range []string{"o", "output"} {
		fs.StringVar(&out, n, "", "Output file; - writes stdout")
	}
	fs.StringVar(&config, "config", "", "JSON file with custom literal/RE2 rules")
	fs.BoolVar(&force, "force", false, "Replace an existing output file (never the input)")
	fs.BoolVar(&check, "check", false, "Detect only: exit 1 if found; never emit input or write files")
	fs.BoolVar(&stats, "stats", false, "Write redaction counts as JSON to stderr")
	fs.BoolVar(&phone, "phone", false, "Enable heuristic phone number detection")
	fs.BoolVar(&showVersion, "version", false, "Print version")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: masktext [-f FILE | -t TEXT] [-o FILE] [options]\n\nNo input option: read stdin. File input: save beside source as name.masked.ext.\nText/stdin: write stdout. Use -o - for stdout. Options precede positional text.\nExit codes: 0 success/clean, 1 findings with --check, 2 error.\n\nOptions:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	hasFile := provided["f"] || provided["file"]
	hasText := provided["t"] || provided["text"]
	fail := func(message string) int { fmt.Fprintln(stderr, "masktext: "+message); return 2 }
	if fs.NArg() > 0 {
		if fs.NArg() != 1 || hasText || hasFile {
			return fail("provide one input source; use -f for a file or -t for text")
		}
		text = fs.Arg(0)
		hasText = true
	}
	if hasFile && hasText {
		return fail("--file and --text are mutually exclusive")
	}
	if hasFile && file == "" {
		return fail("input path must not be empty")
	}
	if (provided["o"] || provided["output"]) && out == "" {
		return fail("output path must not be empty")
	}
	if check && (out != "" || force) {
		return fail("--check cannot be combined with --output or --force")
	}
	var c mask.Config
	if config != "" {
		f, err := os.Open(config)
		if err != nil {
			return fail("cannot open configuration")
		}
		c, err = mask.ReadConfig(io.LimitReader(f, 1024*1024))
		f.Close()
		if err != nil {
			return fail(err.Error())
		}
	}
	engine, err := mask.New(c, phone)
	if err != nil {
		return fail(err.Error())
	}
	var input io.Reader = stdin
	var sourceInfo os.FileInfo
	if hasText {
		input = strings.NewReader(text)
	} else if hasFile && file != "-" {
		f, err := os.Open(file)
		if err != nil {
			return fail("cannot open input file")
		}
		defer f.Close()
		sourceInfo, err = f.Stat()
		if err != nil || !sourceInfo.Mode().IsRegular() {
			return fail("input must be a regular file")
		}
		input = f
	} else if f, ok := stdin.(*os.File); ok {
		info, _ := f.Stat()
		if info != nil && info.Mode()&os.ModeCharDevice != 0 {
			fs.Usage()
			return fail("provide a file, text, or piped input")
		}
	}
	b, err := io.ReadAll(io.LimitReader(input, maxBytes+1))
	if err != nil {
		return fail("cannot read input")
	}
	if len(b) > maxBytes {
		return fail("input exceeds 32 MiB limit")
	}
	if !utf8.Valid(b) || strings.ContainsRune(string(b), 0) {
		return fail("input must be UTF-8 text without NUL bytes; convert other encodings first")
	}
	result := engine.Mask(string(b))
	if stats {
		if err := json.NewEncoder(stderr).Encode(result.Counts); err != nil {
			return 2
		}
	}
	if check {
		if len(result.Counts) > 0 {
			return 1
		}
		return 0
	}
	if out == "" {
		if sourceInfo != nil {
			ext := filepath.Ext(file)
			out = strings.TrimSuffix(file, ext) + ".masked" + ext
		} else {
			out = "-"
		}
	}
	if out == "-" {
		if _, err := io.WriteString(stdout, result.Text); err != nil {
			return fail("cannot write output")
		}
		return 0
	}
	// Check both inode identity (hardlinks) and resolved paths (symlinks).
	if sourceInfo != nil {
		if dst, err := os.Stat(out); err == nil && os.SameFile(sourceInfo, dst) {
			return fail("output must not be the input file")
		}
		srcAbs, _ := filepath.Abs(file)
		dstAbs, _ := filepath.Abs(out)
		if srcAbs == dstAbs {
			return fail("output must not be the input file")
		}
	}
	if err := writeOutput(out, []byte(result.Text), force); err != nil {
		return fail(err.Error())
	}
	return 0
}

func writeOutput(path string, data []byte, force bool) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("output must be a regular file, not a symlink")
		}
		if !force {
			return errors.New("output already exists; use --force to replace it")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect output path")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".masktext-*")
	if err != nil {
		return errors.New("cannot create output; parent directory must exist")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return errors.New("cannot write output")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return errors.New("cannot sync output")
	}
	if err = f.Close(); err != nil {
		return errors.New("cannot close output")
	}
	if force {
		err = os.Rename(tmp, path)
	} else {
		err = os.Link(tmp, path)
	}
	if err != nil {
		return errors.New("cannot save output (it may already exist)")
	}
	return nil
}
