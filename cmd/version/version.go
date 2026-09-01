package version

type Info struct {
	Version string
}

var version = "(devel)"

func Get() Info { return Info{Version: version} }
