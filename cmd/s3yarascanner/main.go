package main

import (
	"github.com/hillu/go-yara"
	log "github.com/sirupsen/logrus"
	"github.com/zacharyestep/s3yarascanner/pkg/s3sync"
	"github.com/zacharyestep/s3yarascanner/pkg/yarascanner"
	"github.com/zacharyestep/s3yarascanner/pkg/feed"
	"github.com/zacharyestep/s3yarascanner/pkg/models"
	"os"
	"os/signal"
	"runtime"
	"net/http"
	"net/url"
	"github.com/jinzhu/gorm"
	//sqlitedilact for gorm
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"time"
)

func configureLogging() {
	loglevel := os.Getenv("LOGLEVEL")
	loglevels := map[string]log.Level{"debug": log.DebugLevel, "info": log.InfoLevel, "error": log.ErrorLevel, "warn": log.WarnLevel, "trace": log.TraceLevel}
	chosenLevel := log.InfoLevel
	if len(loglevel) > 0 {
		reallevel, ok := loglevels[loglevel]
		if ok {
			chosenLevel = reallevel
		} 
	} 
	log.SetLevel(chosenLevel)
	log.Infof("Log level is %s",chosenLevel)
}

func main() {
	//yara library's global cleanup routine defer'd to trigger at exit
	defer yara.Finalize()

	log.Info("Starting s3 yara service")
	//configure the running log-level
	configureLogging()

	/*
		scanner is configured via ENVVARS (for docker ease of use)
		and optional CLI parameters for the bucket, binary directory, rules directory, binary-database path/+name

		This will try to pick up the .aws/config file by default for connectivity to AWS,
		AWS_ACCESS_KEY and AWS_SECRET_KEY can be used instead, along with ENDPOINTURL, DISABLESSL,S3FORCEPATHSTYLE
		AWS_REGION is also supported, defaulting to 'us-east-1'

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

	//AWS related config options
	endpointurl := os.Getenv("ENDPOINTURL")
	awsregion := os.Getenv("AWS_REGION")
	awsaccessid := os.Getenv("AWS_ACCESS_KEY")
	awsaccesskey := os.Getenv("AWS_SECRET_KEY")

	var disablessl = false
	disablesslraw := os.Getenv("DISABLESSL")
	if len(disablesslraw) > 0 {
		disablessl = true
	}
	var s3forcepathstyle = false
	s3forcepathstyleraw := os.Getenv("S3FORCEPATHSTYLE")
	if len(s3forcepathstyleraw) > 0 {
		s3forcepathstyle = true
	}

	//options for feed server
	feedServerURLStr := os.Getenv("FEEDSERVERURL")
	if len(feedServerURLStr) == 0 { 
		feedServerURLStr = "http://127.0.0.1:31452"
	}

	feedServerHostURL,err  := url.Parse(feedServerURLStr)
	if err != nil {
		log.Fatalf("Error parsing server url %s - %v",feedServerURLStr,err)
	}

	feedServerHost := feedServerHostURL.Hostname() + ":" + feedServerHostURL.Port()

	feedServerTemplateFile := os.Getenv("FEEDSERVERTEMPLATEFILE")
	if len(feedServerTemplateFile) == 0 {
		feedServerTemplateFile = "./feed.tmpl"
	}

	dbGorm,err := gorm.Open("sqlite3",db)

	if err != nil  {
		log.Fatalf("%s %v",db,err)
	}

	dbGorm.AutoMigrate(&models.Binary{},&models.Rule{},&models.Result{})

	syncer, err:= s3sync.NewSyncer(bucket, binaryDir, endpointurl, awsregion, awsaccessid, awsaccesskey, disablessl, s3forcepathstyle)

	if err != nil {
		log.Fatalf("Error in syncer construction %v",err)
	}

	scanner, err := yarascanner.NewScanner(binaryDir, rulesDir, dbGorm)

	if err != nil { 
		log.Fatalf("Error in scanner construction %v",err)
	}

	syncer.Start(runtime.NumCPU())
	scanner.Start(runtime.NumCPU())

	feedrouter,err := feed.NewServerTmplFile(feedServerTemplateFile,dbGorm)
	feedrouter.Routes()
	if err != nil {
		log.Fatalf("Error setting up Feed Server %s %v",feedServerTemplateFile,err)
	}
	srv := &http.Server{
        Handler:      feedrouter.Router,
        Addr:         feedServerHost,
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
	}
	
	//Todo - HANDLE SHUTTING THIS DOWN
	go func() { 
		log.Fatalf("Error Serving feed %v",srv.ListenAndServe())
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	for {
		select {
		case sig := <-c:
			log.Debugf("Handling sig %s", sig)
			syncer.Close()
			scanner.Close()
			log.Debugf("Yara scanner main exiting OK")
			return
		}
	}

}
