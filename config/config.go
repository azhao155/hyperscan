package config

// Main is the top level configuration.
type Main struct {
	Sites []Site
}

// Site is a site-specific configuration.
type Site struct {
	Name string
}
