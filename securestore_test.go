package securestore

import (
        "context"
        "encoding/json"
        "fmt"
        "io"
        "os"
        "os/exec"
        "strings"
        "testing"
        "time"
)

const (
        vaultPath = "secrets.testing.json"
        keyFile  = "secrets.testing.key"
        password = "password123\n"
)

type SecretEntry struct {
        IV      interface{} `json:"iv"`
        HMAC    interface{} `json:"hmac"`
        Payload interface{} `json:"payload"`
}

type SecretFile struct {
        Secrets map[string]SecretEntry `json:"secrets"`
}

func TestMain(m *testing.M) {
        // Create the secrets and key file
		err := runCommand(5*time.Second, "",
				"ssclient", "create", "--password", password,
				"--export-key", keyFile, vaultPath)
        if err != nil {
                fmt.Printf("`ssclient` failure: %v\n", err)
                os.Exit(1)
        }

        if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
                fmt.Printf("Store creation failure: %s was not created\n", vaultPath)
                os.Exit(1)
        }
        if _, err := os.Stat(keyFile); os.IsNotExist(err) {
                fmt.Printf("Store creation failure: %s was not created\n", keyFile)
                os.Exit(1)
        }

        // Assign first secret (foo -> bar) inline with password-based decryption
        err = runCommand(5*time.Second, password,
                "ssclient", "-s", vaultPath, "set", "foo", "bar", "--password", password)
        if err != nil {
                fmt.Printf("Failed to assign secret 'foo': %v\n", err)
                os.Exit(1)
        }
        if err := validateSecretKey(vaultPath, "foo"); err != nil {
                fmt.Printf("Failed to verify creation of secret 'foo': %v\n", err)
                os.Exit(1)
        }

        // Assign second secret (baz -> qux) at the prompt, with key-based decryption
        err = runCommand(5*time.Second, "qux\n",
                "ssclient", "-s", vaultPath, "-k", keyFile, "set", "baz")
        if err != nil {
                fmt.Printf("Failed to assign secret 'baz': %v\n", err)
                os.Exit(1)
        }
        if err := validateSecretKey(vaultPath, "baz"); err != nil {
                fmt.Printf("Failed to verify creation of secret 'baz': %v\n", err)
                os.Exit(1)
        }

		// Now run module tests with the the vault and keys created
        exitCode := m.Run()

        // ..and clean up all temporary files after tests have completed
        os.Remove(vaultPath)
        os.Remove(keyFile)

        os.Exit(exitCode)
}

// runCommand handles the execution (with timeout) and piping into stdin
func runCommand(timeout time.Duration, stdinContent string, name string, args ...string) error {
        ctx, cancel := context.WithTimeout(context.Background(), timeout)
        defer cancel()

        cmd := exec.CommandContext(ctx, name, args...)

        stdin, err := cmd.StdinPipe()
        if err != nil {
                return err
        }

        var stderr strings.Builder
        cmd.Stderr = &stderr

        if err := cmd.Start(); err != nil {
                return err
        }

        io.WriteString(stdin, stdinContent)
        stdin.Close()

        err = cmd.Wait()

        if ctx.Err() == context.DeadlineExceeded {
                return fmt.Errorf("command timed out after %v", timeout)
        }

        if err != nil {
                return fmt.Errorf("command exited with error: %v (stderr: %s)", err, stderr.String())
        }

        return nil
}

// validateSecretKey checks if the JSON file has the expected structure
func validateSecretKey(filename string, keyName string) error {
        data, err := os.ReadFile(filename)
        if err != nil {
                return err
        }

        var sf SecretFile
        if err := json.Unmarshal(data, &sf); err != nil {
                return fmt.Errorf("failed to parse JSON: %v", err)
        }

        entry, ok := sf.Secrets[keyName]
        if !ok {
                return fmt.Errorf("key '.secrets.%s' not found in %s", keyName, filename)
        }

        // Check for presence of child keys
        if entry.IV == nil || entry.HMAC == nil || entry.Payload == nil {
                return fmt.Errorf("key '.secrets.%s' is missing required fields (iv, hmac, or payload)", keyName)
        }

        return nil
}

/**
 * TestLoadSecretsWithPassword reads the vault and
 * attempts to decrypt a known key to verify the port works, using
 * password-based decryption.
 */
func TestLoadSecretsWithPassword(t *testing.T) {
	// Attempt to load the vault with the password
	sm, err := LoadWithPassword(vaultPath, password)
	if err != nil {
		t.Fatalf("Failed to load vault from %s with password: %v", vaultPath, err)
	}

	assertLoadSecret(t, sm, "baz", "qux", "password")
}

/**
 * TestLoadSecretsWithKey reads the vault and
 * attempts to decrypt a known key to verify the port works, using
 * key-based decryption.
 */
func TestLoadSecretsWithKey(t *testing.T) {
	// Attempt to load the vault with the key file
	sm, err := LoadWithKeyFile(vaultPath, keyFile)
	if err != nil {
		t.Fatalf("Failed to load vault from %s with decryption key: %v", vaultPath, err)
	}

	assertLoadSecret(t, sm, "foo", "bar", "key file")
}

/**
 * TestLoadNotFound reads the vault and tries to load a non-existent secrets
 */
func TestLoadNotFound(t *testing.T) {
	// Attempt to load the vault with the key file
	sm, err := LoadWithKeyFile(vaultPath, keyFile)
	if err != nil {
		t.Fatalf("Failed to load vault from %s with decryption key: %v", vaultPath, err)
	}

	val, err := sm.Get("404")
	if err != ErrSecretNotFound {
		t.Fatalf("Expected `ErrSecretNotFound` but got err '%v' and val '%v'", err, val)
	}
}

func assertLoadSecret(t *testing.T, sm *SecretsManager, name string, expected string, method string) {
	testKey := name
	// Check if the expected key exists
	keys := sm.Keys()
	found := false
	for _, k := range keys {
		if k == testKey {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected key %s not found in vault. Available keys: %v", testKey, keys)
	}

	// Attempt to decrypt the secret
	val, err := sm.Get(testKey)
	if err != nil {
		t.Fatalf("Failed to decrypt secret '%s' with %s: %v", testKey, method, err)
	}

	if val != expected {
		t.Errorf("Decrypted value is incorrect with %s", method)
	}

	t.Logf("Successfully decrypted '%s' with %s. Value: %s", testKey, method, val)
}

