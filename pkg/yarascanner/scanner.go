package yarascanner

import (
	"github.com/hillu/go-yara"
	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
	"github.com/zacharyestep/s3yarascanner/pkg/models"
	"io/ioutil"
	"os"
	"path/filepath"
	//sqlitedilact for gorm
	"github.com/fsnotify/fsnotify"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"time"
)

//Scanner type monitors a rule directory, a bin directory, and timely scans binaries and records the results in the configured DB
type Scanner struct {
	RuleDir      string
	BinDir       string
	ResultsDB    string
	resultsDB    *gorm.DB
	Compiler     *yara.Compiler
	Rules        *yara.Rules
	watcherBins  *fsnotify.Watcher
	watcherRules *fsnotify.Watcher
	resultsChan  chan BinaryMatches
}

//NewScanner returns a new scanner, or an error if construction fails
func NewScanner(ruleDir, binDir, db string) (Scanner, error) {
	compiler, err := yara.NewCompiler()
	gormdb, err := gorm.Open("sqlite3", db)
	if err != nil {
		return Scanner{}, err
	}
	watcherBins, err := fsnotify.NewWatcher()
	err = watcherBins.Add(binDir)
	if err != nil {
		return Scanner{}, err
	}
	watcherRules, err := fsnotify.NewWatcher()
	err = watcherRules.Add(ruleDir)
	if err != nil {
		return Scanner{}, err
	}
	return Scanner{RuleDir: ruleDir, BinDir: binDir, ResultsDB: db, Compiler: compiler, resultsDB: gormdb, watcherRules: watcherRules, watcherBins: watcherBins, resultsChan: make(chan BinaryMatches, 1000)}, nil
}

//Start startup routine launches workers
func (scanr *Scanner) Start() {
	go ScanningWorker(scanr.BinDir, scanr.watcherBins.Events, scanr.resultsChan, scanr.Rules)
	go ResultDBWorker(scanr.resultsDB,scanr.resultsChan)
}

//Close requisite close function
func (scanr *Scanner) Close() {
	scanr.resultsDB.Close()
	scanr.watcherRules.Close()
	scanr.watcherBins.Close()
	yara.Finalize()
}

//LoadBins loads bins from disk into the db
func (scanr *Scanner) LoadBins() {
	bins, err := ioutil.ReadDir(scanr.BinDir)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	for _, file := range files {
		log.Debugf(file.Name())
		file, _ := os.Open(filepath.Join(scanr.RuleDir, file.Name()))
		scanr.Compiler.AddFile(file, "")
	}
	scanr.Rules, _ = scanr.Compiler.GetRules()
}

//BinaryMatches pairs a Binary-Hash/filename with set of results from yarascans - [] yara.MatchRule
type BinaryMatches struct {
	Matches  []yara.MatchRule
	FileHash string
}

//ScanningWorker go routine worker that knows how to scan files by name using a configured ruleset
func ScanningWorker(binDir string, toScan <-chan fsnotify.Event, scanResults chan<- BinaryMatches, ruleset *yara.Rules) {
	for binFileEvent := range toScan {
		matches, err := ruleset.ScanFile(filepath.Join(binDir, binFileEvent.Name), 0, 30*time.Second)
		if err != nil {
			log.Debugf("Error scanning %s %v", binFileEvent.Name, err)
		} else {
			scanResults <- BinaryMatches{Matches: matches, FileHash: filepath.Base(binFileEvent.Name)}
		}
	}
}

//ResultDBWorker enters Results into the DB
func ResultDBWorker(db * gorm.DB, scanResults <-chan BinaryMatches) {
	/*type MatchRule struct {
		Rule      string
		Namespace string
		Tags      []string
		Meta      map[string]interface{}
		Strings   []MatchString
	}*/
	for matches := range scanResults {
		for _, match := range matches.Matches {
			db.Create(models.Result{BinaryHash: matches.FileHash, Rule: match.Rule, Score: match.Meta["Score"].(int), Namespace: match.Namespace})
		}
	}
}