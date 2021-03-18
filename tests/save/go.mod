module tardigarde-ci/tests

go 1.15

require (
	github.com/gruntwork-io/terratest v0.32.8
	github.com/stretchr/testify v1.6.1
	golang.org/x/net v0.0.0-20201021035429-f5854403a974 // indirect
	golang.org/x/sys v0.0.0-20210119212857-b64e53b001e4 // indirect
)

replace github.com/gruntwork-io/terratest v0.32.8 => github.com/ffernandezcast/terratest v0.28.6-0.20201201084725-13e8a4c156b8
