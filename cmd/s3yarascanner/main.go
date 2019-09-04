package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/zacharyestep/s3yarascanner/pkg/s3sync"
	"github.com/zacharyestep/s3yarascanner/pkg/yarascanner"
	"os"
)

func main() {
	log.Info("Starting s3 yara service")
	// The session the S3 Downloader will use
	bucket := os.Args[1]

	syncer, _ := s3sync.NewSyncer(bucket, "./binaries")
	scanner, _ := yarascanner.NewScanner("./binaries", "./rules", "./db/results.db")
	syncer.Start()
	scanner.Start()
}
