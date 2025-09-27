package assets

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

//go:embed logo.txt
var LogoContent string

//go:embed docker-compose.yml
var dockerComposeContent []byte

var (
	dockerComposeFile string
	once              sync.Once
)

func GetDockerComposeFile() (string, error) {
	var err error
	once.Do(func() {
		tmpDir := os.TempDir()
		tmpFile := filepath.Join(tmpDir, "docker-compose.yml")

		err = os.WriteFile(tmpFile, dockerComposeContent, 0644)
		if err != nil {
			err = fmt.Errorf("failed to create temp docker-compose file: %w", err)
			return
		}

		dockerComposeFile = tmpFile
	})

	return dockerComposeFile, err
}
