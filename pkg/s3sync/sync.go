package s3sync

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"
)

//Syncer struct
type Syncer struct {
	S3SVC        *s3.S3
	SourceBucket string
	DestDir      string
	toCopy       chan string
	downloader   *s3manager.Downloader
	ignoreFiles  map[string]bool
	s3ticker     *time.Ticker
	fsticker     *time.Ticker
	started      bool
	workerexits  []chan bool
	workersdone  *sync.WaitGroup
}

//CopyWorker - go routine worker for doing copies from s3 to fs
func CopyWorker(source <-chan string, destpath string, downloader *s3manager.Downloader, bucket string, ignoreFiles map[string]bool, wg *sync.WaitGroup) {
	//func (d Downloader) Download(w io.WriterAt, input *s3.GetObjectInput, options ...func(*Downloader)) (n int64, err error)
	wg.Add(1)
	defer log.Debugf("Copy worker returning")
	defer wg.Done()
	for filename := range source {
		ignore, ok := ignoreFiles[filename]
		if !ok || (ok && !ignore) {
			outfile, err := os.OpenFile(filepath.Join(destpath, filename), os.O_WRONLY|os.O_CREATE, 0755)
			if err != nil {
				log.Fatalf("Copy worker %v", err)
			} else {
				defer outfile.Close()
				_, err = downloader.Download(outfile,
					&s3.GetObjectInput{
						Bucket: aws.String(bucket),
						Key:    aws.String(filename),
					})
				if err != nil {
					log.Fatalf("Copy worker %v", err)
				}
				log.Infof("Copy worker copied %s!", filename)
			}
		}
	}
}

//DirectoryContentsWorker uses the local file system and retrives files that are already on disk
func DirectoryContentsWorker(ticker <-chan time.Time, destdir string, ignoreFiles map[string]bool, done <-chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	defer log.Debugf("Directory worker returning")
	defer wg.Done()
	for {
		select {
		case <-ticker:
			files, err := ioutil.ReadDir(destdir)
			if err != nil {
				log.Fatalf("DW %v", err)
			}
			for _, file := range files {
				//log.Infof(file.Name())
				ignoreFiles[file.Name()] = true
			}
		case <-done:
			return
		}
	}
}

//S3ListWorker periodically checks the contents of the bucket and queues new files for download
func S3ListWorker(ticker <-chan time.Time, toCopy chan<- string, SourceBucket string, s3svc *s3.S3, ignoredFiles map[string]bool, done <-chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	defer log.Debugf("S3List worker returning")
	defer wg.Done()
	for {
		select {
		case <-ticker:
			resp, err := s3svc.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(SourceBucket)})

			if err != nil {
				log.Fatalf("S3Worker Unable to list items in bucket %q, %v", SourceBucket, err)
			}

			for _, item := range resp.Contents {
				name := *item.Key
				if _, ok := ignoredFiles[name]; !ok {
					//log.Debugf("Name: ", name)
					toCopy <- name
				}
			}
		case <-done:
			return
		}
	}
}

//Close - shuts down the syncer correctly (ie, close the toCopy channel)
func (syncer *Syncer) Close() {
	close(syncer.toCopy)
	syncer.s3ticker.Stop()
	syncer.fsticker.Stop()
	for _, workercontrol := range syncer.workerexits {
		workercontrol <- true
	}
	syncer.workersdone.Wait()
	log.Debugf("Syncer - all workers done -")
}

//Start - starts the sync
func (syncer *Syncer) Start(workerNum int) {
	if !syncer.started {
		for i := 0; i < workerNum; i++ {
			go CopyWorker(syncer.toCopy, syncer.DestDir, syncer.downloader, syncer.SourceBucket, syncer.ignoreFiles, syncer.workersdone)
		}
		syncer.workerexits = make([]chan bool, 2)
		syncer.workerexits[0] = make(chan bool, 1)
		syncer.workerexits[1] = make(chan bool, 1)
		go S3ListWorker(syncer.s3ticker.C, syncer.toCopy, syncer.SourceBucket, syncer.S3SVC, syncer.ignoreFiles, syncer.workerexits[0], syncer.workersdone)
		go DirectoryContentsWorker(syncer.fsticker.C, syncer.DestDir, syncer.ignoreFiles, syncer.workerexits[1], syncer.workersdone)
		syncer.started = true
		log.Infof("Sync started ok")
	} else {
		log.Debugf("Syncer already started...")
	}
}

//NewSyncer returns a Syncer or an error if construction fails
func NewSyncer(srcBkt, destDir, endpointURL, awsregion, awsaccessid, awsaccesskey string, disableSSL, s3ForcePathStyle bool) (syncer *Syncer, err error) {

	awsCfg := aws.Config{}

	if endpointURL != "" && len(endpointURL) > 0 {
		awsCfg.Endpoint = aws.String(endpointURL)
	}

	if awsregion != "" && len(awsregion) > 0 {
		awsCfg.Region = aws.String(awsregion)
	} else {
		awsCfg.Region = aws.String("us-east-1")
	}

	if len(awsaccessid) > 0 && len(awsaccesskey) > 0 {
		awsCfg.Credentials = credentials.NewStaticCredentials(awsaccessid, awsaccesskey, "")
	}

	awsCfg.S3ForcePathStyle = aws.Bool(s3ForcePathStyle)
	awsCfg.DisableSSL = aws.Bool(disableSSL)

	sess := session.Must(session.NewSession(&awsCfg))

	// The S3 client the S3 Downloader will use
	s3ticker := time.NewTicker(1 * time.Second)
	fsticker := time.NewTicker(1 * time.Second)

	syncer = &Syncer{SourceBucket: srcBkt, DestDir: destDir, S3SVC: s3.New(sess), ignoreFiles: make(map[string]bool), toCopy: make(chan string, 10000), s3ticker: s3ticker, fsticker: fsticker, started: false, workersdone: &sync.WaitGroup{}, workerexits: make([]chan bool, 0)}
	// Create a downloader with the s3 client and default options
	syncer.downloader = s3manager.NewDownloaderWithClient(syncer.S3SVC)

	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		log.Debugf("!Destination directory for syncer does not exist!")
		return syncer, err
	}

	return syncer, nil
}
