module sigsum.org/sigsum-go

// We don't want to depend on golang version later than is available
// in debian's stable or backports repos.
go 1.19

require (
	github.com/golang/mock v1.6.0
	github.com/pborman/getopt/v2 v2.1.0
	golang.org/x/net v0.5.0
	golang.org/x/text v0.6.0
)

require (
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/sys v0.4.0 // indirect
	golang.org/x/tools v0.1.12 // indirect
)
