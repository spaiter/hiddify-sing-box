package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	runtimeDebug "runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/fswatch"
	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"

	"github.com/spf13/cobra"
)

var (
	commandRun = &cobra.Command{
		Use:   "run",
		Short: "Run service",
		Run: func(cmd *cobra.Command, args []string) {
			err := run()
			if err != nil {
				log.Fatal(err)
			}
		},
	}
	watchConfig bool
)

func init() {
	mainCommand.AddCommand(commandRun)
	commandRun.Flags().BoolVar(&watchConfig, "watch", false, "Watch config files for changes and auto-reload")
}

type OptionsEntry struct {
	content []byte
	path    string
	options option.Options
}

func readConfigAt(path string) (*OptionsEntry, error) {
	var (
		configContent []byte
		err           error
	)
	if path == "stdin" {
		configContent, err = io.ReadAll(os.Stdin)
	} else {
		configContent, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, E.Cause(err, "read config at ", path)
	}
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, configContent)
	if err != nil {
		return nil, E.Cause(err, "decode config at ", path)
	}
	return &OptionsEntry{
		content: configContent,
		path:    path,
		options: options,
	}, nil
}

func readConfig() ([]*OptionsEntry, error) {
	var optionsList []*OptionsEntry
	for _, path := range configPaths {
		optionsEntry, err := readConfigAt(path)
		if err != nil {
			return nil, err
		}
		optionsList = append(optionsList, optionsEntry)
	}
	for _, directory := range configDirectories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, E.Cause(err, "read config directory at ", directory)
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") || entry.IsDir() {
				continue
			}
			optionsEntry, err := readConfigAt(filepath.Join(directory, entry.Name()))
			if err != nil {
				return nil, err
			}
			optionsList = append(optionsList, optionsEntry)
		}
	}
	sort.Slice(optionsList, func(i, j int) bool {
		return optionsList[i].path < optionsList[j].path
	})
	return optionsList, nil
}

func readConfigAndMerge() (option.Options, error) {
	optionsList, err := readConfig()
	if err != nil {
		return option.Options{}, err
	}
	if len(optionsList) == 1 {
		return optionsList[0].options, nil
	}
	var mergedMessage json.RawMessage
	for _, options := range optionsList {
		mergedMessage, err = badjson.MergeJSON(globalCtx, options.options.RawMessage, mergedMessage, false)
		if err != nil {
			return option.Options{}, E.Cause(err, "merge config at ", options.path)
		}
	}
	var mergedOptions option.Options
	err = mergedOptions.UnmarshalJSONContext(globalCtx, mergedMessage)
	if err != nil {
		return option.Options{}, E.Cause(err, "unmarshal merged config")
	}
	return mergedOptions, nil
}

func newInstance(options option.Options) (*box.Box, context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(globalCtx)
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		cancel()
		return nil, nil, nil, E.Cause(err, "create service")
	}
	return instance, ctx, cancel, nil
}

func create() (*box.Box, context.CancelFunc, error) {
	options, err := readConfigAndMerge()
	if err != nil {
		return nil, nil, err
	}
	if disableColor {
		if options.Log == nil {
			options.Log = &option.LogOptions{}
		}
		options.Log.DisableColor = true
	}
	instance, _, cancel, err := newInstance(options)
	if err != nil {
		return nil, nil, err
	}

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(osSignals)
		close(osSignals)
	}()
	startCtx, finishStart := context.WithCancel(context.Background())
	go func() {
		_, loaded := <-osSignals
		if loaded {
			cancel()
			closeMonitor(startCtx)
		}
	}()
	err = instance.Start()
	finishStart()
	if err != nil {
		cancel()
		return nil, nil, E.Cause(err, "start service")
	}
	return instance, cancel, nil
}

func createWithPreStart(options option.Options) (*box.Box, context.CancelFunc, error) {
	instance, _, cancel, err := newInstance(options)
	if err != nil {
		return nil, nil, err
	}
	err = instance.PreStart()
	if err != nil {
		cancel()
		return nil, nil, E.Cause(err, "pre-start service")
	}
	return instance, cancel, nil
}

func run() error {
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(osSignals)

	var (
		watcher     *fswatch.Watcher
		reloadChan  chan struct{}
		debounceMu  sync.Mutex
		debounceTimer *time.Timer
	)

	if watchConfig {
		reloadChan = make(chan struct{}, 1)
		var watchPaths []string
		watchPaths = append(watchPaths, configPaths...)
		watchPaths = append(watchPaths, configDirectories...)
		if len(watchPaths) > 0 {
			var err error
			watcher, err = fswatch.NewWatcher(fswatch.Options{
				Path: watchPaths,
				Callback: func(_ string) {
					debounceMu.Lock()
					defer debounceMu.Unlock()
					if debounceTimer != nil {
						debounceTimer.Stop()
					}
					debounceTimer = time.AfterFunc(time.Second, func() {
						select {
						case reloadChan <- struct{}{}:
						default:
						}
					})
				},
			})
			if err != nil {
				return E.Cause(err, "create config file watcher")
			}
			defer watcher.Close()
			err = watcher.Start()
			if err != nil {
				return E.Cause(err, "start config file watcher")
			}
			log.Info("watching config files for changes")
		}
	}

	for {
		instance, cancel, err := create()
		if err != nil {
			return err
		}
		runtimeDebug.FreeOSMemory()
		for {
			var reload bool
			if reloadChan != nil {
				select {
				case osSignal := <-osSignals:
					if osSignal == syscall.SIGHUP {
						reload = true
					}
				case <-reloadChan:
					reload = true
				}
			} else {
				osSignal := <-osSignals
				if osSignal == syscall.SIGHUP {
					reload = true
				}
			}

			if !reload {
				// SIGINT or SIGTERM — shut down
				cancel()
				closeCtx, closed := context.WithCancel(context.Background())
				go closeMonitor(closeCtx)
				err = instance.Close()
				closed()
				if err != nil {
					log.Error(E.Cause(err, "sing-box did not closed properly"))
				}
				return nil
			}

			// Reload: read and validate new config
			log.Info("config reload triggered, reading new config...")
			options, err := readConfigAndMerge()
			if err != nil {
				log.Error(E.Cause(err, "reload: read config"))
				continue
			}
			if disableColor {
				if options.Log == nil {
					options.Log = &option.LogOptions{}
				}
				options.Log.DisableColor = true
			}

			// PreStart new instance (outbounds, DNS, routing — not inbounds)
			newInstance, newCancel, err := createWithPreStart(options)
			if err != nil {
				log.Error(E.Cause(err, "reload: pre-start new service"))
				continue
			}

			// Close old instance (releases ports)
			cancel()
			closeCtx, closed := context.WithCancel(context.Background())
			go closeMonitor(closeCtx)
			err = instance.Close()
			closed()
			if err != nil {
				log.Error(E.Cause(err, "reload: close old service"))
			}

			// FinishStart new instance (binds ports, starts inbounds)
			err = newInstance.FinishStart()
			if err != nil {
				newCancel()
				log.Fatal(E.Cause(err, "reload: finish start new service"))
			}

			instance = newInstance
			cancel = newCancel
			runtimeDebug.FreeOSMemory()
			continue
		}
	}
}

func closeMonitor(ctx context.Context) {
	time.Sleep(C.FatalStopTimeout)
	select {
	case <-ctx.Done():
		return
	default:
	}
	log.Fatal("sing-box did not close!")
}
