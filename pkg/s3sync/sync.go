package s3sync

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

//Syncer struct
type Syncer struct {
	S3SVC        *s3.S3
	SourceBucket string
	DestDir      string
	toRemove     chan string
	toCopy       chan string
	downloader   *s3manager.Downloader
	ignoreFiles  map[string]bool
	ticker       *time.Ticker
	started      bool
}

//CopyWorker - go routine worker for doing copies from s3 to fs
func CopyWorker(source <-chan string, destpath string, downloader *s3manager.Downloader, bucket string, ignoreFiles map[string]bool) {
	//func (d Downloader) Download(w io.WriterAt, input *s3.GetObjectInput, options ...func(*Downloader)) (n int64, err error)
	for filename := range source {
		ignore, ok := ignoreFiles[filename]
		if !ok || (ok && !ignore) {
			outfile, err := os.Open(filepath.Join(destpath, filename))
			if err != nil {
				log.Fatal(err)
			} else {
				defer outfile.Close()
				_, err = downloader.Download(outfile,
					&s3.GetObjectInput{
						Bucket: aws.String(bucket),
						Key:    aws.String(filename),
					})
				if err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}

//DirectoryContentsWorker uses the local file system and retrives files that are already on disk
func DirectoryContentsWorker(destdir string, ignoreFiles map[string]bool) {
	files, err := ioutil.ReadDir(destdir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		log.Infof(file.Name())
		ignoreFiles[file.Name()] = true
	}
}

//S3ListWorker periodically checks the contents of the bucket and queues new files for download
func S3ListWorker(ticker <-chan time.Time, toCopy chan<- string, SourceBucket string, s3svc *s3.S3, ignoredFiles map[string]bool) {
	for range ticker {
		resp, err := s3svc.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(SourceBucket)})

		if err != nil {
			log.Fatalf("Unable to list items in bucket %q, %v", SourceBucket, err)
		}

		for _, item := range resp.Contents {
			name := *item.Key
			if _, ok := ignoredFiles[name]; !ok {
				//log.Debugf("Name: ", name)
				toCopy <- name
			}
		}
	}
}

//Close - shuts down the syncer correctly (ie, close the toCopy channel)
func (syncer *Syncer) Close() {
	close(syncer.toCopy)
}

//Start - starts the sync
func (syncer *Syncer) Start(workerNum int) {
	if !syncer.started {
		for i := 0 ; i < workerNum ; i ++ {
			go CopyWorker(syncer.toCopy, syncer.DestDir, syncer.downloader, syncer.SourceBucket, syncer.ignoreFiles)
			go S3ListWorker(syncer.ticker.C, syncer.toCopy, syncer.SourceBucket, syncer.S3SVC, syncer.ignoreFiles)
			go DirectoryContentsWorker(syncer.DestDir, syncer.ignoreFiles)
		}
		syncer.started = true
	} else { 
		log.Debugf("Syncer already started...")
	}
}

//NewSyncer returns a Syncer or an error if construction fails
func NewSyncer(srcBkt, destDir string) (syncer Syncer, err error) {
	sess := session.Must(session.NewSession())
	// The S3 client the S3 Downloader will use
	ticker := time.NewTicker(7 * time.Second)
	syncer = Syncer{SourceBucket: srcBkt, DestDir: destDir, S3SVC: s3.New(sess), ignoreFiles: make(map[string]bool), toCopy: make(chan string, 10000), ticker: ticker, started: false}
	// Create a downloader with the s3 client and default options
	syncer.downloader = s3manager.NewDownloaderWithClient(syncer.S3SVC)

	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		log.Debugf("!Destination directory for syncer does not exist!")
		return syncer, err
	}

	return syncer, nil
}
