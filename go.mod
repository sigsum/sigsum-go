module sigsum.org/sigsum-go

// We don't want to depend on golang version later than is available
// in debian's stable or backports repos.
go 1.22

require (
	github.com/dchest/safefile v0.0.0-20151022103144-855e8d98f185
	github.com/golang/mock v1.6.0
	github.com/pborman/getopt/v2 v2.1.0
	golang.org/x/net v0.31.0
	golang.org/x/text v0.20.0
)

require (
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
)
