package clashapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type ConfigManager struct {
	mu       sync.Mutex
	ctx      context.Context
	filePath string
}

func NewConfigManager(ctx context.Context, filePath string) *ConfigManager {
	return &ConfigManager{
		ctx:      ctx,
		filePath: filePath,
	}
}

func (m *ConfigManager) ReadConfig() (option.Options, error) {
	content, err := os.ReadFile(m.filePath)
	if err != nil {
		return option.Options{}, E.Cause(err, "read config file")
	}
	options, err := json.UnmarshalExtendedContext[option.Options](m.ctx, content)
	if err != nil {
		return option.Options{}, E.Cause(err, "decode config")
	}
	return options, nil
}

func (m *ConfigManager) WriteConfig(options option.Options) error {
	cleaned, err := badjson.Omitempty(m.ctx, options)
	if err != nil {
		return E.Cause(err, "clean config")
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoderContext(m.ctx, &buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(cleaned)
	if err != nil {
		return E.Cause(err, "encode config")
	}
	dir := filepath.Dir(m.filePath)
	tmpFile, err := os.CreateTemp(dir, ".sing-box-config-*.tmp")
	if err != nil {
		return E.Cause(err, "create temp file")
	}
	tmpPath := tmpFile.Name()
	_, err = tmpFile.Write(buffer.Bytes())
	if closeErr := tmpFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmpPath)
		return E.Cause(err, "write temp file")
	}
	err = os.Rename(tmpPath, m.filePath)
	if err != nil {
		os.Remove(tmpPath)
		return E.Cause(err, "rename config file")
	}
	return nil
}

func (m *ConfigManager) ModifyConfig(modifier func(option.Options) (option.Options, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	options, err := m.ReadConfig()
	if err != nil {
		return err
	}
	options, err = modifier(options)
	if err != nil {
		return err
	}
	return m.WriteConfig(options)
}
