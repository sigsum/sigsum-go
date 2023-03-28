module sigsum.org/sigsum-go

// We don't want to depend on golang version later than is available
// in debian's stable or backports repos.
go 1.19

require (
	github.com/pborman/getopt/v2 v2.1.0
	golang.org/x/net v0.5.0
	golang.org/x/text v0.6.0
)
