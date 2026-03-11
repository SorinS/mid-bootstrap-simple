package version

import "fmt"

const (
	Prefix  = "v"
	Major   = "0"
	Minor   = "6"
	Patch   = "9"
	Release = "dev"
)

var Version = fmt.Sprintf("%s%s.%s.%s-%s", Prefix, Major, Minor, Patch, Release)
