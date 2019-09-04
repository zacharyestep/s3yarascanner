package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/zacharyestep/s3yarascanner/pkg/s3sync"
	"github.com/zacharyestep/s3yarascanner/pkg/yarascanner"
	"github.com/hillu/go-yara"
	"os"
	"os/signal"
	"runtime"
)

func main() {
	defer yara.Finalize()
	log.Info("Starting s3 yara service")
	// The session the S3 Downloader will use
	bucket := os.Args[1]

	syncer, _ := s3sync.NewSyncer(bucket, "./binaries")
	scanner, _ := yarascanner.NewScanner("./binaries", "./rules", "./db/results.db")
	syncer.Start(runtime.NumCPU())
	scanner.Start(runtime.NumCPU())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	for { 
		select {
		case sig := <- c:
			log.Debugf("Handling sig %s",sig)
			syncer.Close()
			scanner.Close()
			return
		}
	}

}
