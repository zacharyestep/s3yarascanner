package main

import (
	"github.com/hillu/go-yara"
	log "github.com/sirupsen/logrus"
	"github.com/zacharyestep/s3yarascanner/pkg/s3sync"
	"github.com/zacharyestep/s3yarascanner/pkg/yarascanner"
	"os"
	"os/signal"
	"runtime"
)

func main() {
	defer yara.Finalize()
	log.Info("Starting s3 yara service")
	/*
	
	*/
	bucket := os.Getenv("BINARYSOURCEBUCKET")
	if len(bucket) == 0 {
		bucket = os.Args[1]
	}

	binaryDir := os.Getenv("BINARYDIR")
	if len(binaryDir) == 0 {
		binaryDir = os.Args[2]
	}

	rulesDir := os.Getenv("RULESDIR")
	if len(rulesDir) == 0 {
		rulesDir = os.Args[3]
	}

	db := os.Getenv("SQLITEDB")
	if len(db) == 0 {
		db = os.Args[4]
	}

	endpointurl := os.Getenv("ENDPOINTURL")
	awsregion := os.Getenv("AWS_REGION")
	awsaccessid := os.Getenv("AWS_ACCESS_KEY")
	awsaccesskey := os.Getenv("AWS_SECRET_KEY")

	var disablessl = false
	disablesslraw := os.Getenv("DISABLESSL")
	if len(disablesslraw) > 0  {
		disablessl = true
	}
	var s3forcepathstyle = false
	s3forcepathstyleraw := os.Getenv("S3FORCEPATHSTYLE")
	if len(s3forcepathstyleraw) > 0 {
		s3forcepathstyle = true
	}
	syncer, _ := s3sync.NewSyncer(bucket, binaryDir, endpointurl, awsregion,awsaccessid,awsaccesskey,disablessl,s3forcepathstyle)
	scanner, _ := yarascanner.NewScanner(binaryDir, rulesDir, db)
	syncer.Start(runtime.NumCPU())
	scanner.Start(runtime.NumCPU())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	for {
		select {
		case sig := <-c:
			log.Debugf("Handling sig %s", sig)
			syncer.Close()
			scanner.Close()
			log.Infof("Yara scanner exiting OK")
			return
		}
	}

}
