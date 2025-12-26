package main

import (
	"bytes"
	"os"
	"runtime"
	"testing"
)

// ensure tests run without network and validate consent & dry-run behavior
func TestMissingConsentReturnsUsage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	// capture stderr and stdout
	oldOut := os.Stdout
	oldErr := os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	// run command with required allowlist but without consent
	rootCmd.SetArgs([]string{"--allowlist", "127.0.0.1"})
	err := rootCmd.Execute()

	// close writers to read
	wOut.Close()
	wErr.Close()
	var bufOut bytes.Buffer
	var bufErr bytes.Buffer
	if _, err := bufOut.ReadFrom(rOut); err != nil {
		t.Fatalf("failed reading stdout pipe: %v", err)
	}
	if _, err := bufErr.ReadFrom(rErr); err != nil {
		t.Fatalf("failed reading stderr pipe: %v", err)
	}

	// restore
	os.Stdout = oldOut
	os.Stderr = oldErr

	if err == nil {
		t.Fatalf("expected error when consent missing")
	}
	if _, ok := err.(*usageError); !ok {
		t.Fatalf("expected usageError, got: %T %v", err, err)
	}
	if !bytes.Contains(bufErr.Bytes(), []byte("consent required")) {
		t.Fatalf("expected stderr to contain consent required, got: %q", bufErr.String())
	}
	if bufOut.Len() != 0 {
		t.Fatalf("expected no stdout output, got: %q", bufOut.String())
	}
}

func TestDryRunWithConsentWritesDryRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	oldOut := os.Stdout
	oldErr := os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout = wOut
	os.Stderr = wErr

	rootCmd.SetArgs([]string{"--allowlist", "127.0.0.1", "--i-am-authorized", "--dry-run"})
	err := rootCmd.Execute()

	wOut.Close()
	wErr.Close()
	var bufOut bytes.Buffer
	var bufErr bytes.Buffer
	if _, err := bufOut.ReadFrom(rOut); err != nil {
		t.Fatalf("failed reading stdout pipe: %v", err)
	}
	if _, err := bufErr.ReadFrom(rErr); err != nil {
		t.Fatalf("failed reading stderr pipe: %v", err)
	}

	os.Stdout = oldOut
	os.Stderr = oldErr

	if err != nil {
		t.Fatalf("expected no error for dry-run, got: %v", err)
	}
	if !bytes.Contains(bufErr.Bytes(), []byte("Dry run")) && !bytes.Contains(bufErr.Bytes(), []byte("dry run")) {
		t.Fatalf("expected stderr to contain dry-run hint, got: %q", bufErr.String())
	}
	if bufOut.Len() != 0 {
		t.Fatalf("expected no stdout output, got: %q", bufOut.String())
	}
}
