test:
	go test -v cap_test.go

scan:
	snyk test
	snyk monitor

.SILENT:
