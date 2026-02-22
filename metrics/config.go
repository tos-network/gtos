package metrics

// Config contains the configuration for the metric collection.
type Config struct {
	Enabled          bool   `toml:",omitempty"`
	EnabledExpensive bool   `toml:",omitempty"`
	HTTP             string `toml:",omitempty"`
	Port             int    `toml:",omitempty"`
	EnableInfluxDB   bool   `toml:",omitempty"`
	InfluxDBEndpoint string `toml:",omitempty"`
	InfluxDBDatabase string `toml:",omitempty"`
	InfluxDBUsername string `toml:",omitempty"`
	InfluxDBPassword string `toml:",omitempty"`
	InfluxDBTags     string `toml:",omitempty"`

	EnableInfluxDBV2     bool   `toml:",omitempty"`
	InfluxDBToken        string `toml:",omitempty"`
	InfluxDBBucket       string `toml:",omitempty"`
	InfluxDBOrganization string `toml:",omitempty"`
}

// DefaultConfig is the default config for metrics used in go-tos.
var DefaultConfig = Config{
	Enabled:          false,
	EnabledExpensive: false,
	HTTP:             "127.0.0.1",
	Port:             6060,
	EnableInfluxDB:   false,
	InfluxDBEndpoint: "http://localhost:8086",
	InfluxDBDatabase: "gtos",
	InfluxDBUsername: "test",
	InfluxDBPassword: "test",
	InfluxDBTags:     "host=localhost",

	// influxdbv2-specific flags
	EnableInfluxDBV2:     false,
	InfluxDBToken:        "test",
	InfluxDBBucket:       "gtos",
	InfluxDBOrganization: "gtos",
}
