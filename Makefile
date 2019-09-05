all:
	cd cmd/s3yarascanner ; go build -a -ldflags '-extldflags "-static"' 
