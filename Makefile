all: bin docker

bin: cmd/s3yarascanner/s3yarascanner
	cd cmd/s3yarascanner ; go build -tags static_all

docker:
	docker-compose build 