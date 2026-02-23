package observability

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"pentagi/pkg/config"
	"pentagi/pkg/observability/langfuse"
	"pentagi/pkg/version"
)

const (
	DefaultObservationInterval = time.Second * 10
	DefaultObservationTimeout  = time.Second * 10
	DefaultMaxAttempts         = 3
	DefaultQueueSize           = 10
)

type LangfuseClient interface {
	API() langfuse.Client
	Observer() langfuse.Observer
	Shutdown(ctx context.Context) error
	ForceFlush(ctx context.Context) error
}

type langfuseClient struct {
	http     *http.Client
	client   *langfuse.Client
	observer langfuse.Observer
}

func (c *langfuseClient) API() langfuse.Client {
	if c.client == nil {
		return langfuse.Client{}
	}
	return *c.client
}

func (c *langfuseClient) Observer() langfuse.Observer {
	return c.observer
}

func (c *langfuseClient) Shutdown(ctx context.Context) error {
	if err := c.observer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown observer: %w", err)
	}
	c.http.CloseIdleConnections()
	return nil
}

func (c *langfuseClient) ForceFlush(ctx context.Context) error {
	if err := c.observer.ForceFlush(ctx); err != nil {
		return fmt.Errorf("failed to force flush observer: %w", err)
	}
	return nil
}

func NewLangfuseClient(ctx context.Context, cfg *config.Config) (LangfuseClient, error) {
	if cfg.LangfuseBaseURL == "" {
		return nil, fmt.Errorf("langfuse base url is not set: %w", ErrNotConfigured)
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.ExternalSSLInsecure}
	if cfg.ExternalSSLCAPath != "" {
		caPool, err := x509.SystemCertPool()
		if err != nil {
			caPool = x509.NewCertPool()
		}
		caPEM, err := os.ReadFile(cfg.ExternalSSLCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from '%s': %w", cfg.ExternalSSLCAPath, err)
		}
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate from '%s'", cfg.ExternalSSLCAPath)
		}
		tlsCfg.RootCAs = caPool
	}

	httpClient := &http.Client{
		Timeout: DefaultObservationTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     tlsCfg,
		},
	}

	opts := []langfuse.ClientContextOption{
		langfuse.WithBaseURL(cfg.LangfuseBaseURL),
		langfuse.WithPublicKey(cfg.LangfusePublicKey),
		langfuse.WithSecretKey(cfg.LangfuseSecretKey),
		langfuse.WithProjectID(cfg.LangfuseProjectID),
		langfuse.WithHTTPClient(httpClient),
		langfuse.WithMaxAttempts(DefaultMaxAttempts),
	}

	client, err := langfuse.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create langfuse client: %w", err)
	}

	observer := langfuse.NewObserver(client,
		langfuse.WithSendInterval(DefaultObservationInterval),
		langfuse.WithSendTimeout(DefaultObservationTimeout),
		langfuse.WithQueueSize(DefaultQueueSize),
		langfuse.WithProject(cfg.LangfuseProjectID),
		langfuse.WithRelease(version.GetBinaryVersion()),
	)

	return &langfuseClient{
		http:     httpClient,
		client:   client,
		observer: observer,
	}, nil
}
