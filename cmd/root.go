package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/lesomnus/otx"
	"github.com/lesomnus/otx/log"
	"github.com/lesomnus/smb-exporter/smb"
	"github.com/lesomnus/xli"
	"github.com/lesomnus/xli/flg"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sync/errgroup"
)

func NewCmdRoot() *xli.Command {
	return &xli.Command{
		Name: "smb-exporter",

		Flags: flg.Flags{
			&flg.String{Name: "config", Alias: 'c'},
		},
		Commands: xli.Commands{
			NewCmdVersion(),
			NewCmdConfig(),
		},
		Handler: xli.Chain(
			xli.OnRun(WithConfig(func(ctx context.Context, cmd *xli.Command, next xli.Next) error {
				c := use_config.Must(ctx)
				l := log.From(ctx)

				record, err := newCollector(ctx)
				if err != nil {
					return fmt.Errorf("create collector: %w", err)
				}

				var audit *smb.AuditCounter
				if c.Audit.IsEnabled() {
					l.Info("following audit log", slog.String("path", c.Audit.Path))
					audit = smb.NewAuditCounter(c.Audit.Path)
				} else {
					l.Warn("audit disabled; operation metrics will not be produced")
				}

				var last atomic.Pointer[time.Time]
				last.Store(new(time.Time))

				eg, ctx := errgroup.WithContext(ctx)

				if c.Health.Enabled != nil && !*c.Health.Enabled {
					l.Warn("health check disabled")
				} else {
					l.Info("health check enabled",
						slog.String("endpoint", c.Health.Endpoint),
						slog.String("stale_timeout", c.Health.StaleTimeout.String()),
					)
					mux := http.NewServeMux()
					mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
						fmt.Fprintln(w, "ok")
					})
					mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
						if time.Since(*last.Load()) > c.Health.StaleTimeout {
							http.Error(w, "unhealthy", http.StatusInternalServerError)
							return
						}
						w.WriteHeader(http.StatusOK)
						fmt.Fprintln(w, "ok")
					})
					srv := &http.Server{Addr: c.Health.Endpoint, Handler: mux}
					eg.Go(func() error {
						if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
							return err
						}
						return nil
					})
					defer srv.Shutdown(context.WithoutCancel(ctx))
				}

				if audit != nil {
					eg.Go(func() error { return audit.Follow(ctx) })
				}

				eg.Go(func() error {
					src := smb.Source{Ss: c.Ss, Smbstatus: c.Smbstatus}
					col := smb.NewCollector()
					t := time.NewTicker(c.Interval)
					defer t.Stop()

					for {
						s, err := src.Sample(ctx)
						if err != nil {
							// A failed poll is not fatal: smbd may be
							// restarting. Skipping keeps the deltas honest
							// because the previous sample is left in place.
							l.Error("sample", slog.String("err", err.Error()))
						} else {
							var ops map[smb.Op]int64
							if audit != nil {
								ops = audit.Drain()
								// smbstatus, when available, is authoritative;
								// the audit-derived map fills the rest.
								audit.Sessions.Merge(s.Sessions)
								s.Sessions = audit.Sessions.Snapshot()
								audit.Sessions.Retain(s.Conns)
							}
							record(s, col.Apply(s), ops)
							last.Store(new(time.Now()))
						}

						select {
						case <-ctx.Done():
							return nil
						case <-t.C:
						}
					}
				})

				eg.Wait()
				return next(ctx)
			})),
		),
	}
}

func newCollector(ctx context.Context) (func(*smb.Sample, []smb.Delta, map[smb.Op]int64), error) {
	meter := otx.Meter(ctx)

	errs := []error{}
	bytes_sent := newInt64Counter(&errs, meter, "smb.bytes.sent", "Bytes served to clients", "By")
	bytes_recv := newInt64Counter(&errs, meter, "smb.bytes.received", "Bytes received from clients", "By")
	ops_total := newInt64Counter(&errs, meter, "smb.operations", "File operations observed by full_audit", "{operation}")
	conns := newInt64Gauge(&errs, meter, "smb.connections", "Established connections to the SMB port", "{connection}")
	sessions := newInt64Gauge(&errs, meter, "smb.sessions", "Authenticated SMB sessions", "{session}")

	if len(errs) > 0 {
		return nil, fmt.Errorf("create instruments: %w", errors.Join(errs...))
	}

	return func(s *smb.Sample, ds []smb.Delta, ops map[smb.Op]int64) {
		conns.Record(ctx, int64(len(s.Conns)))
		sessions.Record(ctx, int64(len(s.Sessions)))

		for _, d := range ds {
			attr := metric.WithAttributes(attribute.String("user", d.User))
			// Zero adds are skipped so an idle account does not hold a series
			// alive forever.
			if d.BytesSent > 0 {
				bytes_sent.Add(ctx, d.BytesSent, attr)
			}
			if d.BytesRecv > 0 {
				bytes_recv.Add(ctx, d.BytesRecv, attr)
			}
		}

		for op, n := range ops {
			ops_total.Add(ctx, n, metric.WithAttributes(
				attribute.String("user", op.User),
				attribute.String("share", op.Share),
				attribute.String("operation", op.Op),
			))
		}
	}, nil
}

func newInt64Counter(errs *[]error, m metric.Meter, name string, desc string, unit string) metric.Int64Counter {
	v, err := m.Int64Counter(name, metric.WithDescription(desc), metric.WithUnit(unit))
	if err != nil {
		*errs = append(*errs, err)
	}
	return v
}

func newInt64Gauge(errs *[]error, m metric.Meter, name string, desc string, unit string) metric.Int64Gauge {
	v, err := m.Int64Gauge(name, metric.WithDescription(desc), metric.WithUnit(unit))
	if err != nil {
		*errs = append(*errs, err)
	}
	return v
}
