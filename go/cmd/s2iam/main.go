package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/singlestore-labs/singlestore-auth-iam/go/s2iam"
)

// Config holds the command configuration
type Config struct {
	// JWT type
	JWTType string

	// Database JWT options
	WorkspaceGroupID string

	// GCP options
	GCPAudience string

	// Provider options
	Provider   string
	AssumeRole string
	Timeout    time.Duration
	ServerURL  string

	// Output options
	EnvName   string
	EnvStatus string
	Verbose   bool

	// Control options
	ForceDetect bool
}

var osExit = os.Exit

func main() {
	if err := realMain(os.Args, os.Exit); err != nil {
		osExit(1)
	}
}

func realMain(args []string, exitFunc func(int)) error {
	flagSet := flag.NewFlagSet(args[0], flag.ExitOnError)
	config, err := parseFlags(flagSet, args)
	if err != nil {
		log.Printf("Error: %v", err)
		return err
	}

	if err := run(config); err != nil {
		if config.EnvStatus != "" {
			fmt.Printf("%s=1\n", config.EnvStatus)
		}
		if config.Verbose {
			log.Printf("Error: %+v", err)
		} else {
			log.Printf("Error: %v", err)
		}
		return err
	}
	return nil
}

func parseFlags(flagSet *flag.FlagSet, args []string) (Config, error) {
	config := Config{}
	var help bool

	// Define flags
	flagSet.StringVar(&config.JWTType, "jwt-type", "database", "JWT type: 'database' or 'api'")
	flagSet.StringVar(&config.WorkspaceGroupID, "workspace-group-id", "", "Workspace group ID (required for database JWT)")
	flagSet.StringVar(&config.GCPAudience, "gcp-audience", "", "GCP audience for identity token")
	flagSet.StringVar(&config.Provider, "provider", "", "Cloud provider: 'aws', 'gcp', or 'azure' (auto-detect if not specified)")
	flagSet.StringVar(&config.AssumeRole, "assume-role", "", "Role to assume (ARN for AWS, service account for GCP, managed identity for Azure)")
	flagSet.DurationVar(&config.Timeout, "timeout", 10*time.Second, "Timeout for operations")
	flagSet.StringVar(&config.ServerURL, "server-url", "", "Authentication server URL (uses default if not specified)")
	flagSet.StringVar(&config.EnvName, "env-name", "", "Environment variable name for JWT output")
	flagSet.StringVar(&config.EnvStatus, "env-status", "", "Environment variable name for status output")
	flagSet.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flagSet.BoolVar(&config.ForceDetect, "force-detect", false, "Force provider detection even if provider is specified")
	flagSet.BoolVar(&help, "help", false, "Show command options")

	// Custom usage
	flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", args[0])
		fmt.Fprintf(os.Stderr, "Obtain a JWT from SingleStore IAM authentication.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flagSet.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Get database JWT for a workspace\n")
		fmt.Fprintf(os.Stderr, "  %s --workspace-group-id=my-workspace\n\n", args[0])
		fmt.Fprintf(os.Stderr, "  # Get API JWT\n")
		fmt.Fprintf(os.Stderr, "  %s --jwt-type=api\n\n", args[0])
		fmt.Fprintf(os.Stderr, "  # Output for shell evaluation\n")
		fmt.Fprintf(os.Stderr, "  eval $(%s --env-status=STATUS --env-name=TOKEN)\n\n", args[0])
		fmt.Fprintf(os.Stderr, "  # Use with specific provider and role\n")
		fmt.Fprintf(os.Stderr, "  %s --provider=aws --assume-role=arn:aws:iam::123456789012:role/MyRole\n", args[0])
	}

	// Parse flags, skipping program name
	err := flagSet.Parse(args[1:])
	if err != nil {
		return config, err
	}
	if help {
		flagSet.Usage()
		os.Exit(0)
	}

	// Validate flags
	if config.JWTType != "database" && config.JWTType != "api" {
		return config, fmt.Errorf("invalid JWT type: %s (must be 'database' or 'api')", config.JWTType)
	}

	if config.JWTType == "database" && config.WorkspaceGroupID == "" {
		return config, errors.New("--workspace-group-id is required for database JWT")
	}

	if config.Provider != "" {
		validProviders := map[string]bool{
			"aws":   true,
			"gcp":   true,
			"azure": true,
		}
		if !validProviders[config.Provider] {
			return config, fmt.Errorf("invalid provider: %s (must be 'aws', 'gcp', or 'azure')", config.Provider)
		}
	}

	return config, nil
}

func run(config Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	// Build options
	var opts []s2iam.JWTOption

	// Provider detection or selection
	if config.Provider != "" && !config.ForceDetect {
		// Use specified provider
		var provider s2iam.CloudProviderClient
		var err error

		logger := getLogger(config)

		switch config.Provider {
		case "aws":
			provider = s2iam.NewAWSClient(logger)
		case "gcp":
			provider = s2iam.NewGCPClient(logger)
		case "azure":
			provider = s2iam.NewAzureClient(logger)
		}

		// Detect if this provider is available
		err = provider.Detect(ctx)
		if err != nil {
			return fmt.Errorf("specified provider %s not available: %w", config.Provider, err)
		}

		opts = append(opts, s2iam.WithProvider(provider))
	} else {
		// Auto-detect provider
		if config.Verbose && config.ForceDetect {
			log.Println("Forcing provider detection...")
		}
		opts = append(opts, s2iam.WithLogger(getLogger(config)))
	}

	// Common options
	if config.AssumeRole != "" {
		opts = append(opts, s2iam.WithAssumeRole(config.AssumeRole))
	}

	if config.GCPAudience != "" {
		opts = append(opts, s2iam.WithGCPAudience(config.GCPAudience))
	}

	if config.ServerURL != "" {
		opts = append(opts, s2iam.WithServerURL(config.ServerURL))
	}

	// Get JWT
	var jwt string
	var err error

	if config.JWTType == "database" {
		if config.Verbose {
			log.Printf("Getting database JWT for workspace group: %s", config.WorkspaceGroupID)
		}
		jwt, err = s2iam.GetDatabaseJWT(ctx, config.WorkspaceGroupID, opts...)
	} else {
		if config.Verbose {
			log.Println("Getting API JWT")
		}
		jwt, err = s2iam.GetAPIJWT(ctx, opts...)
	}

	if err != nil {
		return err
	}

	// Output the JWT
	if config.EnvName != "" {
		// Environment variable format
		if config.EnvStatus != "" {
			fmt.Printf("%s=0\n", config.EnvStatus)
		}
		fmt.Printf("%s=%s\n", config.EnvName, jwt)
	} else {
		// Plain output
		fmt.Println(jwt)
	}

	return nil
}

// getLogger returns a logger if verbose mode is enabled
func getLogger(config Config) s2iam.Logger {
	if config.Verbose {
		return verboseLogger{}
	}
	return nil
}

// verboseLogger implements the s2iam.Logger interface
type verboseLogger struct{}

func (l verboseLogger) Logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}
