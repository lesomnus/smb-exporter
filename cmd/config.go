package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/lesomnus/mkot"
	"github.com/lesomnus/otx"
	"github.com/lesomnus/otx/log"
	"github.com/lesomnus/smb-exporter/cmd/version"
	"github.com/lesomnus/smb-exporter/smb"
	"github.com/lesomnus/xli"
	"github.com/lesomnus/xli/flg"
	"github.com/lesomnus/z"
	"go.opentelemetry.io/otel/attribute"
	nooplog "go.opentelemetry.io/otel/log/noop"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	nooptrace "go.opentelemetry.io/otel/trace/noop"

	_ "github.com/lesomnus/mkot/otlp"
	"github.com/lesomnus/mkot/pretty"
	"github.com/lesomnus/mkot/prometheus"
)

var use_config = z.NewUse[*Config]()

func WithConfig(h xli.HandlerFunc) xli.HandlerFunc {
	return func(ctx context.Context, cmd *xli.Command, next xli.Next) error {
		if _, ok := use_config.From(ctx); ok {
			return h(ctx, cmd, next)
		}

		path_to_lookup := []string{}
		if p, ok := flg.Find[string](cmd, "config"); ok {
			if _, err := os.Stat(p); err != nil {
				return fmt.Errorf("stat config file: %w", err)
			}
			path_to_lookup = append(path_to_lookup, p)
		}

		c, err := readConfig(path_to_lookup...)
		if err != nil {
			return fmt.Errorf("read config: %w", err)
		}

		ctx, o, err := c.Otel.Build(ctx)
		if err != nil {
			return fmt.Errorf("build otel: %w", err)
		}
		if err := o.Start(ctx); err != nil {
			return fmt.Errorf("start otel: %w", err)
		}
		defer o.Shutdown(ctx)

		l := log.From(ctx)
		l.Info("config loaded", slog.String("path", c.path))

		ctx = use_config.Into(ctx, c)
		return h(ctx, cmd, next)
	}
}

func NewCmdConfig() *xli.Command {
	return &xli.Command{
		Name: "config",
		Handler: xli.OnRun(WithConfig(func(ctx context.Context, cmd *xli.Command, next xli.Next) error {
			c := use_config.Must(ctx)
			return yaml.NewEncoder(cmd).Encode(c)
		})),
	}
}

type Config struct {
	path string

	// Interval is how often the socket and session tables are read. The byte
	// counters are cumulative per connection, so a longer interval loses
	// accuracy only for connections that open and close within it.
	Interval time.Duration

	Ss        []string
	Smbstatus []string

	Audit  AuditConfig
	Health HealthConfig
	Otel   OtelConfig
}

// AuditConfig points at Samba's full_audit log.
//
// Off by default: it requires `vfs objects = full_audit` on the server, and
// without it the operation metrics are simply absent rather than wrong.
type AuditConfig struct {
	Enabled *bool
	Path    string
}

func (c *AuditConfig) Evaluate() error {
	if c.Path == "" {
		c.Path = "/var/log/samba/audit.log"
	}
	return nil
}

func (c *AuditConfig) IsEnabled() bool { return c.Enabled != nil && *c.Enabled }

type HealthConfig struct {
	Enabled      *bool
	StaleTimeout time.Duration `yaml:"stale_timeout"`
	Endpoint     string
}

func (c *HealthConfig) Evaluate() error {
	if c.StaleTimeout == 0 {
		c.StaleTimeout = 60 * time.Second
	}
	if c.Endpoint == "" {
		c.Endpoint = ":8081"
	}
	return nil
}

func readConfig(path_to_lookup ...string) (*Config, error) {
	if len(path_to_lookup) == 0 {
		path_to_lookup = []string{
			"smb-exporter.yaml",
			"smb-exporter.yml",
		}
	}

	var (
		r  io.Reader
		rp string
	)
	for _, rp = range path_to_lookup {
		f, err := os.Open(rp)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("open config file: %w", err)
		}
		r = f
		break
	}

	var c Config
	if r == nil {
		rp = "(default)"
	} else {
		if err := yaml.NewDecoder(r).Decode(&c); err != nil {
			return nil, fmt.Errorf("decode config: %w", err)
		}
	}
	if err := c.Evaluate(); err != nil {
		return nil, fmt.Errorf("evaluate config: %w", err)
	}

	c.path = rp
	return &c, nil
}

func (c *Config) Evaluate() error {
	if c.Interval == 0 {
		c.Interval = 30 * time.Second
	}
	d := smb.DefaultSource()
	if len(c.Ss) == 0 {
		c.Ss = d.Ss
	}
	// c.Smbstatus stays empty unless configured; see smb.DefaultSource.
	if err := c.Audit.Evaluate(); err != nil {
		return err
	}
	return c.Health.Evaluate()
}

type OtelConfig struct {
	mkot.Config `yaml:",inline"`
}

func (c *OtelConfig) Build(ctx context.Context) (context.Context, *otx.Otx, error) {
	otc := mkot.NewConfig()
	if c != nil {
		otc = &c.Config
	}

	if otc.Processors == nil {
		otc.Processors = map[mkot.Id]mkot.ProcessorConfig{}
	}
	if otc.Exporters == nil {
		otc.Exporters = map[mkot.Id]mkot.ExporterConfig{}
	}
	if otc.Providers == nil {
		otc.Providers = map[mkot.Id]*mkot.ProviderConfig{}
	}

	const ServiceResourceId mkot.Id = "resource/smb-exporter"
	if _, ok := otc.Processors[ServiceResourceId]; !ok {
		otc.Processors[ServiceResourceId] = &mkot.Resource{
			Attributes: []mkot.Attr{
				{Key: "service.name", Value: attribute.StringValue("smb-exporter")},
				{Key: "service.version", Value: attribute.StringValue(version.Get().Version)},
			},
		}
	}
	if _, ok := otc.Exporters["pretty"]; !ok {
		otc.Exporters["pretty"] = pretty.ExporterConfig{}
	}
	if _, ok := otc.Exporters["prometheus/local"]; !ok {
		otc.Exporters["prometheus/local"] = &prometheus.ExporterConfig{
			Namespace: "smb_exporter",
			Endpoint:  ":8888",
		}
	}
	if _, ok := otc.Providers["logger"]; !ok {
		otc.Providers["logger"] = &mkot.ProviderConfig{
			Exporters: []mkot.Id{"pretty"},
		}
	}
	if _, ok := otc.Providers["meter"]; !ok {
		otc.Providers["meter"] = &mkot.ProviderConfig{
			Exporters:  []mkot.Id{"prometheus/local"},
			Processors: []mkot.Id{ServiceResourceId},
		}
	}

	resolver := mkot.Make(ctx, otc)

	tracer_provider, err := resolver.Tracer(ctx, "")
	if err != nil {
		if !errors.Is(err, mkot.ErrNotExist) {
			return nil, nil, fmt.Errorf("resolve tracer provider: %w", err)
		}
		tracer_provider = nooptrace.NewTracerProvider()
	}
	meter_provider, err := resolver.Meter(ctx, "")
	if err != nil {
		if !errors.Is(err, mkot.ErrNotExist) {
			return nil, nil, fmt.Errorf("resolve meter provider: %w", err)
		}
		meter_provider = noopmetric.NewMeterProvider()
	}
	logger_provider, err := resolver.Logger(ctx, "")
	if err != nil {
		if !errors.Is(err, mkot.ErrNotExist) {
			return nil, nil, fmt.Errorf("resolve logger provider: %w", err)
		}
		logger_provider = nooplog.NewLoggerProvider()
	}

	v := otx.New(
		otx.WithController(resolver),
		otx.WithTracerProvider(tracer_provider),
		otx.WithMeterProvider(meter_provider),
		otx.WithLoggerProvider(logger_provider),
	)
	return otx.Into(ctx, v), v, nil
}
