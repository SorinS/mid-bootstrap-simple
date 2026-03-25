package vsphere

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// Config holds vSphere connection settings.
type Config struct {
	VCenterAddr    string        // e.g., "vcenter.example.com"
	Username       string        // vCenter username
	PasswordFile   string        // path to file containing vCenter password
	Datacenter     string        // datacenter to search (empty = default)
	SkipVerify     bool          // skip TLS verification
	CacheTTL       time.Duration // how long to cache VM lookups (default 5m)
	EKBinding      bool          // enable EK fingerprint verification
	RequireEK      bool          // fail if EK data unavailable from vSphere
}

// Client is a lightweight vSphere client for vTPM identity lookup.
type Client struct {
	cfg    *Config
	client *govmomi.Client
	finder *find.Finder

	// IP → VMInfo cache
	cacheMu sync.RWMutex
	cache   map[string]*cacheEntry
}

type cacheEntry struct {
	vm      *VMInfo
	expires time.Time
}

// NewClient creates a new vSphere client. Call Connect() to establish the session.
func NewClient(cfg *Config) *Client {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	return &Client{
		cfg:   cfg,
		cache: make(map[string]*cacheEntry),
	}
}

// Connect establishes a session with vCenter.
func (c *Client) Connect(ctx context.Context) error {
	password, err := c.readPassword()
	if err != nil {
		return fmt.Errorf("failed to read vSphere password: %w", err)
	}

	u, err := url.Parse(fmt.Sprintf("https://%s/sdk", c.cfg.VCenterAddr))
	if err != nil {
		return fmt.Errorf("failed to parse vCenter URL: %w", err)
	}
	u.User = url.UserPassword(c.cfg.Username, password)

	client, err := govmomi.NewClient(ctx, u, c.cfg.SkipVerify)
	if err != nil {
		return fmt.Errorf("failed to connect to vCenter %s: %w", c.cfg.VCenterAddr, err)
	}

	c.client = client
	c.finder = find.NewFinder(client.Client, true)

	// Set datacenter if specified
	if c.cfg.Datacenter != "" {
		dc, err := c.finder.Datacenter(ctx, c.cfg.Datacenter)
		if err != nil {
			return fmt.Errorf("failed to find datacenter %q: %w", c.cfg.Datacenter, err)
		}
		c.finder.SetDatacenter(dc)
	}

	log.Printf("[vSphere] Connected to vCenter %s", c.cfg.VCenterAddr)
	return nil
}

// Close closes the vCenter session.
func (c *Client) Close(ctx context.Context) error {
	if c.client != nil {
		return c.client.Logout(ctx)
	}
	return nil
}

// LookupVMByIP resolves an IP address to a VM and extracts vTPM EK data.
// Returns nil, nil if the IP is not found in vCenter (not a vSphere VM).
func (c *Client) LookupVMByIP(ctx context.Context, ip string) (*VMInfo, error) {
	// Check cache first
	if info := c.getCached(ip); info != nil {
		return info, nil
	}

	// Search vCenter for VM by IP
	searcher := object.NewSearchIndex(c.client.Client)
	ref, err := searcher.FindByIp(ctx, nil, ip, true) // true = search guest IPs
	if err != nil {
		return nil, fmt.Errorf("vSphere FindByIp failed: %w", err)
	}
	if ref == nil {
		// Not found in vCenter — not a vSphere VM
		return nil, nil
	}

	// Fetch VM properties
	pc := property.DefaultCollector(c.client.Client)
	var vm mo.VirtualMachine
	err = pc.RetrieveOne(ctx, ref.Reference(), []string{
		"name",
		"config.uuid",
		"config.hardware.device",
		"guest.net",
	}, &vm)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch VM properties: %w", err)
	}

	info := &VMInfo{
		Name:     vm.Name,
		MoRef:    ref.Reference().Value,
		LastSeen: time.Now(),
	}

	if vm.Config != nil {
		info.BIOSUUID = vm.Config.Uuid
	}

	// Extract IPs from guest networking
	if vm.Guest != nil {
		for _, nic := range vm.Guest.Net {
			info.IPAddresses = append(info.IPAddresses, nic.IpAddress...)
		}
	}

	// Find vTPM device and extract EK certificates
	if vm.Config != nil {
		for _, dev := range vm.Config.Hardware.Device {
			vtpm, ok := dev.(*types.VirtualTPM)
			if !ok {
				continue
			}
			info.HasVTPM = true

			for _, ekDER := range vtpm.EndorsementKeyCertificate {
				if len(ekDER) == 0 {
					continue
				}
				info.EKCertificatesDER = append(info.EKCertificatesDER, ekDER)

				// Compute SHA-256 fingerprint
				fp := sha256.Sum256(ekDER)
				info.EKCertFingerprints = append(info.EKCertFingerprints, fmt.Sprintf("%x", fp))

				// Log parsed cert info for debugging
				if cert, err := x509.ParseCertificate(ekDER); err == nil {
					log.Printf("[vSphere] VM %s vTPM EK cert: issuer=%s, serial=%s, fingerprint=%x",
						vm.Name, cert.Issuer.CommonName, cert.SerialNumber, fp)
				}
			}

			if len(vtpm.EndorsementKeyCertificate) == 0 {
				log.Printf("[vSphere] WARNING: VM %s has vTPM but no EK certificates (older vSphere?)", vm.Name)
			}
			break // only one vTPM per VM
		}
	}

	// Cache the result
	c.setCached(ip, info)

	return info, nil
}

// EKBindingEnabled returns whether EK fingerprint verification is enabled.
func (c *Client) EKBindingEnabled() bool {
	return c.cfg.EKBinding
}

// RequireEK returns whether EK data is required for attestation.
func (c *Client) RequireEK() bool {
	return c.cfg.RequireEK
}

func (c *Client) readPassword() (string, error) {
	data, err := os.ReadFile(c.cfg.PasswordFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (c *Client) getCached(ip string) *VMInfo {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	entry, ok := c.cache[ip]
	if !ok || time.Now().After(entry.expires) {
		return nil
	}
	return entry.vm
}

func (c *Client) setCached(ip string, info *VMInfo) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	c.cache[ip] = &cacheEntry{
		vm:      info,
		expires: time.Now().Add(c.cfg.CacheTTL),
	}
}
