package userdata

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers/aws"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers/azure"
	"github.com/confidential-containers/cloud-api-adaptor/src/cloud-providers/docker"
	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v2"
)

const (
	ConfigParent = "/run/peerpod"

	AaCfgPath     = "/run/peerpod/aa.toml"
	AgentCfgPath  = "/run/peerpod/agent-config.toml"
	AuthJsonPath  = "/run/peerpod/auth.json"
	CdhCfgPath    = "/run/peerpod/cdh.toml"
	DaemonCfgPath = "/run/peerpod/daemon.json"

	InitdataMeta = "/run/peerpod/initdata.meta"
	DigestPath   = "/run/peerpod/initdata.digest"
)

var logger = log.New(log.Writer(), "[userdata/provision] ", log.LstdFlags|log.Lmsgprefix)

var StaticFiles = []string{"/run/peerpod/aa.toml", "/run/peerpod/cdh.toml", "/run/peerpod/policy.rego"}

type paths struct {
	aaConfig     string
	agentConfig  string
	authJson     string
	cdhConfig    string
	daemonConfig string
}

type Config struct {
	fetchTimeout int
	paths        paths
	digestPath   string
	initdataMeta string
	parentPath   string
	staticFiles  []string
}

func NewConfig(fetchTimeout int) *Config {
	ps := paths{
		aaConfig:     AaCfgPath,
		agentConfig:  AgentCfgPath,
		authJson:     AuthJsonPath,
		cdhConfig:    CdhCfgPath,
		daemonConfig: DaemonCfgPath,
	}
	return &Config{
		fetchTimeout: fetchTimeout,
		paths:        ps,
		parentPath:   ConfigParent,
		initdataMeta: InitdataMeta,
		digestPath:   DigestPath,
		staticFiles:  StaticFiles,
	}
}

type entry struct {
	path     string
	optional bool
}

type WriteFile struct {
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
}

type CloudConfig struct {
	WriteFiles []WriteFile `yaml:"write_files"`
}

type InitData struct {
	Algorithm string            `toml:"algorithm"`
	Version   string            `toml:"version"`
	Data      map[string]string `toml:"data,omitempty"`
}

type UserDataProvider interface {
	GetUserData(ctx context.Context) ([]byte, error)
	GetRetryDelay() time.Duration
}

type DefaultRetry struct{}

func (d DefaultRetry) GetRetryDelay() time.Duration {
	return 5 * time.Second
}

type AzureUserDataProvider struct{ DefaultRetry }

func (a AzureUserDataProvider) GetUserData(ctx context.Context) ([]byte, error) {
	url := azure.AzureUserDataImdsUrl
	logger.Printf("provider: Azure, userDataUrl: %s\n", url)
	return azure.GetUserData(ctx, url)
}

type AWSUserDataProvider struct{ DefaultRetry }

func (a AWSUserDataProvider) GetUserData(ctx context.Context) ([]byte, error) {
	url := aws.AWSUserDataImdsUrl
	logger.Printf("provider: AWS, userDataUrl: %s\n", url)
	return aws.GetUserData(ctx, url)
}

type DockerUserDataProvider struct{ DefaultRetry }

func (a DockerUserDataProvider) GetUserData(ctx context.Context) ([]byte, error) {
	url := docker.DockerUserDataUrl
	logger.Printf("provider: Docker, userDataUrl: %s\n", url)
	return docker.GetUserData(ctx, url)
}

func newProvider(ctx context.Context) (UserDataProvider, error) {

	// This checks for the presence of a file and doesn't rely on http req like the
	// azure, aws ones, thereby making it faster and hence checking this first
	if docker.IsDocker(ctx) {
		return DockerUserDataProvider{}, nil
	}
	if azure.IsAzure(ctx) {
		return AzureUserDataProvider{}, nil
	}

	if aws.IsAWS(ctx) {
		return AWSUserDataProvider{}, nil
	}

	return nil, fmt.Errorf("unsupported user data provider")
}

func retrieveCloudConfig(ctx context.Context, provider UserDataProvider) (*CloudConfig, error) {
	var cc CloudConfig

	// Use retry.Do to retry the getUserData function until it succeeds
	// This is needed because the VM's userData is not available immediately
	err := retry.Do(
		func() error {
			ud, err := provider.GetUserData(ctx)
			if err != nil {
				return fmt.Errorf("failed to get user data: %w", err)
			}

			// We parse user data now, b/c we want to retry if it's not valid
			parsed, err := parseUserData(ud)
			if err != nil {
				return fmt.Errorf("failed to parse user data: %w", err)
			}
			cc = *parsed

			// Valid user data, stop retrying
			return nil
		},
		retry.Context(ctx),
		retry.Delay(provider.GetRetryDelay()),
		retry.LastErrorOnly(true),
		retry.DelayType(retry.FixedDelay),
		retry.OnRetry(func(n uint, err error) {
			logger.Printf("Retry attempt %d: %v\n", n, err)
		}),
	)

	return &cc, err
}

func parseUserData(userData []byte) (*CloudConfig, error) {
	var cc CloudConfig
	err := yaml.UnmarshalStrict(userData, &cc)
	if err != nil {
		return nil, err
	}
	return &cc, nil
}

func findConfigEntry(path string, cc *CloudConfig) []byte {
	for _, wf := range cc.WriteFiles {
		if wf.Path != path {
			continue
		}
		return []byte(wf.Content)
	}
	return nil
}

func writeFile(path string, bytes []byte) error {
	// Ensure the parent directory exists
	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	err = os.WriteFile(path, bytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}
	logger.Printf("Wrote %s\n", path)
	return nil
}

func isPredefinedConfigEntry(path string, entries []entry) bool {
	for _, e := range entries {
		if e.path == path {
			return true
		}
	}
	return false
}

func processCloudConfig(cfg *Config, cc *CloudConfig) error {
	entries := []entry{
		{path: cfg.paths.agentConfig, optional: false},
		{path: cfg.paths.daemonConfig, optional: false},
		{path: cfg.paths.aaConfig, optional: true},
		{path: cfg.paths.cdhConfig, optional: true},
		{path: cfg.paths.authJson, optional: true},
	}

	// entries pre-defined
	for _, e := range entries {
		bytes := findConfigEntry(e.path, cc)
		if bytes == nil {
			if !e.optional {
				return fmt.Errorf("failed to find %s entry in cloud config", e.path)
			}
			continue
		}
		err := writeFile(e.path, bytes)
		if err != nil {
			return err
		}
	}

	// entries not pre-defined by caa, we have some special config for some specific providers, handle it here...
	for _, wf := range cc.WriteFiles {
		path := wf.Path
		bytes := []byte(wf.Content)
		if bytes != nil && !isPredefinedConfigEntry(path, entries) {
			if err := writeFile(path, bytes); err != nil {
				return fmt.Errorf("failed to write config file %s: %w", path, err)
			}
		}
	}

	return nil
}

func calculateUserDataHash(cfg *Config) error {
	initToml, err := os.ReadFile(cfg.initdataMeta)
	if err != nil {
		return err
	}
	var initdata InitData
	err = toml.Unmarshal(initToml, &initdata)
	if err != nil {
		return err
	}

	checksumStr := ""
	var byteData []byte
	for _, file := range cfg.staticFiles {
		if _, err := os.Stat(file); err == nil {
			logger.Printf("calculateUserDataHash and reading file %s\n", file)
			bytes, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("Error reading file %s: %v", file, err)
			}
			byteData = append(byteData, bytes...)
		}
	}

	switch initdata.Algorithm {
	case "sha256":
		hash := sha256.Sum256(byteData)
		checksumStr = hex.EncodeToString(hash[:])
	case "sha384":
		hash := sha512.Sum384(byteData)
		checksumStr = hex.EncodeToString(hash[:])
	case "sha512":
		hash := sha512.Sum512(byteData)
		checksumStr = hex.EncodeToString(hash[:])
	default:
		return fmt.Errorf("Error creating initdata hash, the Algorithm %s not supported", initdata.Algorithm)
	}

	err = os.WriteFile(cfg.digestPath, []byte(checksumStr), 0644) // the hash in digestPath will also be used by attester
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", cfg.digestPath, err)
	}

	return nil
}

func ProvisionFiles(cfg *Config) error {
	bg := context.Background()
	duration := time.Duration(cfg.fetchTimeout) * time.Second
	ctx, cancel := context.WithTimeout(bg, duration)
	defer cancel()

	// some providers provision config files via process-user-data
	// some providers rely on cloud-init provision config files
	// all providers need calculate the hash value for attesters usage
	provider, _ := newProvider(ctx)
	if provider != nil {
		cc, err := retrieveCloudConfig(ctx, provider)
		if err != nil {
			return fmt.Errorf("failed to retrieve cloud config: %w", err)
		}

		if err = processCloudConfig(cfg, cc); err != nil {
			return fmt.Errorf("failed to process cloud config: %w", err)
		}
	} else {
		logger.Printf("unsupported user data provider, we calculate initdata hash only.\n")
	}

	if err := calculateUserDataHash(cfg); err != nil {
		return fmt.Errorf("failed to calculate initdata hash: %w", err)
	}

	return nil
}
