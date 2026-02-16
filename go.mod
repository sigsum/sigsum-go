module sigsum.org/sigsum-go

// We don't want to depend on golang version later than is available
// in debian's stable or backports repos.
go 1.24.0

require (
	github.com/dchest/safefile v0.0.0-20151022103144-855e8d98f185
	github.com/golang/mock v1.6.0
	github.com/pborman/getopt/v2 v2.1.0
	golang.org/x/net v0.50.0
	golang.org/x/text v0.34.0
)

require (
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
)
