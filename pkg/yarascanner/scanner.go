package yarascanner

import (
	"github.com/fsnotify/fsnotify"
	"github.com/hillu/go-yara"
	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
	"github.com/zacharyestep/s3yarascanner/pkg/models"
	"io/ioutil"
	"os"
	"path/filepath"
	//sqlitedilact for gorm
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"time"
	"sync"
)

//Scanner type monitors a rule directory, a bin directory, and timely scans binaries and records the results in the configured DB
type Scanner struct {
	RuleDir      string
	BinDir       string
	resultsDB    *gorm.DB
	Compiler     *yara.Compiler
	Rules        *yara.Rules
	watcherBins  *fsnotify.Watcher
	watcherRules *fsnotify.Watcher
	resultsChan  chan BinaryMatches
	started      bool
	workerwaitgroup *sync.WaitGroup
}

//NewScanner returns a new scanner, or an error if construction fails
func NewScanner(ruleDir, binDir string, db * gorm.DB) (*Scanner, error) {
	compiler, err := yara.NewCompiler()
	watcherBins, err := fsnotify.NewWatcher()
	err = watcherBins.Add(binDir)
	if err != nil {
		return nil, err
	}
	watcherRules, err := fsnotify.NewWatcher()
	err = watcherRules.Add(ruleDir)
	if err != nil {
		return nil, err
	}
	return &Scanner{RuleDir: ruleDir, BinDir: binDir, Compiler: compiler, resultsDB: db, watcherRules: watcherRules, watcherBins: watcherBins, resultsChan: make(chan BinaryMatches, 1000), started: false}, nil
}

//Start startup routine launches workers
func (scanr *Scanner) Start(workerNum int) {
	scanr.LoadBins()
	scanr.LoadRules()
	if !scanr.started {
		for i := 0; i < workerNum; i++ {
			go ScanningWorker(scanr.BinDir, scanr.watcherBins.Events, scanr.resultsChan, scanr.Rules,scanr.workerwaitgroup)
		}
		go ResultDBWorker(scanr.resultsDB, scanr.resultsChan,scanr.workerwaitgroup)
		scanr.started = true
	} else {
		log.Debugf("Scanner already started...")
	}
}

//Close requisite close
func (scanr *Scanner) Close() {
	close(scanr.resultsChan)
	scanr.resultsDB.Close()
	scanr.watcherRules.Close()
	scanr.watcherBins.Close()
	scanr.workerwaitgroup.Wait()
}

//LoadBins loads bins from disk into the db
func (scanr *Scanner) LoadBins() {
	bins, err := ioutil.ReadDir(scanr.BinDir)
	if err != nil {
		log.Fatalf("Error loading binary dir %s %v", scanr.BinDir, err)
	}
	for _, bin := range bins {
		log.Debugf(bin.Name())
		scanr.resultsDB.Create(&models.Binary{Hash: bin.Name(), Created: time.Now()})
	}
}

//LoadRules load a directory of yara rules and generates a ruleset for yara
func (scanr *Scanner) LoadRules() {
	files, err := ioutil.ReadDir(scanr.RuleDir)
	if err != nil {
		log.Fatalf("Error loadind rule %v", err)
	}
	for _, file := range files {
		//log.Debugf(file.Name())
		file, _ := os.Open(filepath.Join(scanr.RuleDir, file.Name()))
		scanr.Compiler.AddFile(file, file.Name())
	}
	scanr.Rules, _ = scanr.Compiler.GetRules()
}

//BinaryMatches pairs a Binary-Hash/filename with set of results from yarascans - [] yara.MatchRule
type BinaryMatches struct {
	Matches  []yara.MatchRule
	FileHash string
}

//ScanningWorker go routine worker that knows how to scan files by name using a configured ruleset
func ScanningWorker(binDir string, toScan <-chan fsnotify.Event, scanResults chan<- BinaryMatches, ruleset *yara.Rules, wg * sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	for binFileEvent := range toScan {
		matches, err := ruleset.ScanFile(filepath.Join(binDir, binFileEvent.Name), 0, 30*time.Second)
		if err != nil {
			log.Debugf("Error scanning %s %v", binFileEvent.Name, err)
		} else {
			log.Infof("Scanned %s succesfully...%d results", binFileEvent.Name, len(matches))
			scanResults <- BinaryMatches{Matches: matches, FileHash: filepath.Base(binFileEvent.Name)}
		}
	}
	log.Debugf("Scanning worker exiting...")
}

//ResultDBWorker enters Results into the DB
func ResultDBWorker(db *gorm.DB, scanResults <-chan BinaryMatches, wg *sync.WaitGroup) {
	/*type MatchRule struct {
		Rule      string
		Namespace string
		Tags      []string
		Meta      map[string]interface{}
		Strings   []MatchString
	}*/
	wg.Add(1)
	defer wg.Done()
	for matches := range scanResults {
		for _, match := range matches.Matches {
			db.Create(models.Result{BinaryHash: matches.FileHash, Rule: match.Rule, Score: match.Meta["Score"].(int), Namespace: match.Namespace})
		}
	}
	log.Debugf("DB Worker exiting")
}
