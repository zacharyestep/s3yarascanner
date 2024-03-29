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
	"fmt"
)

//Scanner type monitors a rule directory, a bin directory, and timely scans binaries and records the results in the configured DB
type Scanner struct {
	RuleDir      string
	BinDir       string
	resultsDB    *gorm.DB
	RulesetProvider *WatchedRulesetProvider
	watcherBins  *fsnotify.Watcher
	watcherRules *fsnotify.Watcher
	resultsChan  chan BinaryMatches
	started      bool
	workerwaitgroup *sync.WaitGroup
	ScanningChan chan fsnotify.Event
}
//NewScannerDBString returns a scanner, or error if construction fails 
func NewScannerDBString(binDir,ruleDir,db string) (*Scanner, error) { 
	gdb, err := gorm.Open("sqlite3",db)
	if err != nil  { 
		return nil, err
	}
	return NewScanner(binDir,ruleDir,gdb)
}

//NewScanner returns a new scanner, or an error if construction fails
func NewScanner(binDir,ruleDir string, db * gorm.DB) (*Scanner, error) {
	log.Debugf("NewScanner %s %s",ruleDir,binDir)
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
	wrp, err := NewWatchedRulesetProvider(ruleDir,db,watcherRules.Events)
	if err != nil {
		log.Debugf("Error watcher contstruction %v",err)
		return nil, err
	}
	resultschan := make(chan BinaryMatches, 1000)
	scanningChan := make(chan fsnotify.Event, 10000)
	return &Scanner{ScanningChan : scanningChan,RulesetProvider: wrp,workerwaitgroup: &sync.WaitGroup{},RuleDir: ruleDir, BinDir: binDir, resultsDB: db, watcherRules: watcherRules, watcherBins: watcherBins, resultsChan: resultschan, started: false}, nil
}

//RulesetProvider is any source of yara rules providing a GetRules function
type RulesetProvider interface {
	LoadRules()	(error)
	GetRules() (* yara.Rules, error)
	Go(wg * sync.WaitGroup) 
	Stop()
}

//BinaryRescanRuleWatcher Uses rule notifications to query the DB, and send a list of binary-hash-names to be scanned-again with the new ruleset (ie , all of the bins)
func BinaryRescanRuleWatcher(bindb * gorm.DB, ruleChanged <-chan fsnotify.Event, tobeScanned chan<- fsnotify.Event, wg * sync.WaitGroup) {
	wg.Add(1)
	defer log.Debug("BinaryRescanRuleWatcher exiting...")
	defer wg.Done()
	for range ruleChanged { 
		bins := make([] models.Binary,0)
		bindb.Find(bins)
		for _, bin := range bins {
			tobeScanned <- fsnotify.Event{Name: bin.Hash}
		}
	}
}

//WatchedRulesetProvider is a RulesetProvider that updates the rules when they change
type WatchedRulesetProvider struct { 
	Compiler * yara.Compiler
	IncomingRulesChan chan fsnotify.Event
	OutgoingRulesChan chan fsnotify.Event
	RuleDB * gorm.DB
	sync.RWMutex
	rules * yara.Rules
	RuleDir string
}

//Stop closes output channel
func (wrp * WatchedRulesetProvider) Stop() { 
	close(wrp.OutgoingRulesChan)
}

//NewWatchedRulesetProvider factory method constructing a working RulesetProvider
func NewWatchedRulesetProvider(ruleDir string, ruleDb * gorm.DB, rulesUpdateChan chan fsnotify.Event) (* WatchedRulesetProvider , error) {
	log.Debugf("NewWatchedRulesetProvider %s", ruleDir)
	if _, err := os.Stat(ruleDir); os.IsNotExist(err) {
		log.Debugf("Error is rule dir not exist")
		return nil, err
	}
	
	if ruleDb == nil { 
		return nil, fmt.Errorf("rules db may not be nil")
	}
	compiler,err := yara.NewCompiler()
	if err != nil { 
		
		return nil , fmt.Errorf("YC error %v ",err)
	}
	wrp := WatchedRulesetProvider{Compiler: compiler, RuleDir: ruleDir, RuleDB: ruleDb , IncomingRulesChan: rulesUpdateChan, OutgoingRulesChan: make(chan fsnotify.Event,1000)}
	//err = wrp.LoadRules()
	return &wrp,err
}

//Go -- run in a goroutine and update rules 
func (wrp * WatchedRulesetProvider) Go(wg * sync.WaitGroup) {
	wg.Add(1)
	defer log.Debug("WatchedRuleSetProvider -> Go exiting")
	defer wg.Done()
	for ruleEvent := range wrp.IncomingRulesChan { 
		log.Debugf("WRP providing outgoing rule event")
		wrp.OutgoingRulesChan <- ruleEvent
		wrp.Lock()
		defer wrp.Unlock()
		err := wrp.loadRule(wrp.RuleDir,ruleEvent.Name)
		if err != nil {
			log.Fatalf("Error loading rule %s %s", ruleEvent.Name, err)
		}
		rules, err:= wrp.Compiler.GetRules()
		if err != nil { 
			log.Fatalf("Error loading rule %s %v", ruleEvent.Name, err)
		} else { 
			wrp.rules = rules
		}
	}
}

//GetRules returns the current rules from the underlying provider
func (wrp * WatchedRulesetProvider) GetRules() (rules * yara.Rules, err error) {
	wrp.Lock()
	defer wrp.Unlock()
	return wrp.rules, nil
}

func (wrp * WatchedRulesetProvider ) loadRule(dir,fileName string) error { 
	file, err := os.Open(filepath.Join(dir,fileName))
	if err != nil  {
		return err
	}
	err = wrp.Compiler.AddFile(file, fileName)
	if err != nil { 
		return err
	}
	wrp.RuleDB.Create(&models.Rule{Name:fileName})
	return nil
}

//LoadRules load a directory of yara rules and generates a ruleset for yara
func (wrp * WatchedRulesetProvider) LoadRules() error {
	wrp.Lock()
	defer wrp.Unlock()
	files, err := ioutil.ReadDir(wrp.RuleDir)
	if err != nil {
		log.Fatalf("Error loadind rule %v", err)
	}
	for _, file := range files {
		err := wrp.loadRule(wrp.RuleDir,file.Name())
		if err != nil {
			log.Errorf("Errro loading rule %s %v",file.Name(),err)
			return err 
		}
	}
	newrules, err := wrp.Compiler.GetRules()
	if err == nil {
		wrp.rules = newrules
		return nil
	} else {
		return err
	}
}

//GetRules returns the rules from the underlying provider, or an error if that fails
func (scanr * Scanner) GetRules() (*yara.Rules, error) { 
	return scanr.RulesetProvider.GetRules()
}


//PipeWorker joins two channels (the file events, and the artifical channel hosted by the scanner, is the usage below)
func PipeWorker(dest chan<- fsnotify.Event, source <-chan fsnotify.Event, wg * sync.WaitGroup) {
	wg.Add(1)
	defer log.Debugf("Pipeworker exiting...")
	defer wg.Done()
	for msg := range source { 
		log.Debugf("Pipeworker piping...")
		dest <- msg
	}
}


//Start startup routine launches workers
func (scanr *Scanner) Start(workerNum int) {
	scanr.LoadBins()
	err := scanr.RulesetProvider.LoadRules()
	if err != nil { 
		log.Fatalf("Error starting scanner - %v",err)
	}
	go BinaryRescanRuleWatcher(scanr.resultsDB,scanr.RulesetProvider.OutgoingRulesChan, scanr.ScanningChan, scanr.workerwaitgroup)
	if !scanr.started {
		for i := 0; i < workerNum; i++ {
			go ScanningWorker(scanr.BinDir, scanr.ScanningChan, scanr.resultsChan, scanr.RulesetProvider,scanr.workerwaitgroup)
		}
		//Pipeworker sends fsnotify events from the watcher to the 'ScanningChan' that yara-scanning workers will monitor
		//This allows other sources of bin-events, like when a binary needs to be rescanned
		go PipeWorker(scanr.ScanningChan,scanr.watcherBins.Events, scanr.workerwaitgroup)
		go ResultDBWorker(scanr.resultsDB, scanr.resultsChan, scanr.workerwaitgroup)
		go scanr.RulesetProvider.Go(scanr.workerwaitgroup)
		scanr.started = true
	} else {
		log.Debugf("Scanner already started...")
	}
}

//Close requisite close
func (scanr *Scanner) Close() {

	close(scanr.resultsChan)
	close(scanr.ScanningChan)
	//scanr.resultsDB.Close()

	scanr.watcherRules.Close()
	scanr.watcherBins.Close()

	scanr.RulesetProvider.Stop() 

	scanr.workerwaitgroup.Wait()

	log.Debugf("Scanner - all workers done -")
}

//LoadBins loads bins from disk into the db
func (scanr * Scanner) LoadBins() {
	bins, err := ioutil.ReadDir(scanr.BinDir)
	if err != nil {
		log.Fatalf("Error loading binary dir %s %v", scanr.BinDir, err)
	}
	for _, bin := range bins {
		log.Debugf("Loaded bin - %s",bin.Name())
		scanr.resultsDB.Create(&models.Binary{Hash: bin.Name()})
		scanr.ScanningChan <- fsnotify.Event{Name: bin.Name()}
	}
}

//BinaryMatches pairs a Binary-Hash/filename with set of results from yarascans - [] yara.MatchRule
type BinaryMatches struct {
	Matches  []yara.MatchRule
	FileHash string
}

//ScanningWorker go routine worker that knows how to scan files by name using a configured ruleset
func ScanningWorker(binDir string, toScan <-chan fsnotify.Event, scanResults chan<- BinaryMatches, rulesetProvider * WatchedRulesetProvider, wg * sync.WaitGroup) {
	wg.Add(1)
	defer log.Debugf("scanning worker exiting")
	defer wg.Done()
	for binFileEvent := range toScan {
		log.Debugf("Scanning worker going to scan %s", binFileEvent.Name)
		ruleset,err := rulesetProvider.GetRules()
		if err != nil {
			log.Fatalf("Error scanning - %v",err)
		}
		if ruleset == nil { 
			log.Fatalf("Got no rules from provider")
		}
		matches, err := ruleset.ScanFile(filepath.Join(binDir, binFileEvent.Name), yara.ScanFlagsFastMode, 5*time.Second)
		if err != nil {
			log.Debugf("Error scanning %s %v", binFileEvent.Name, err)
		} else {
			log.Infof("Scanned %s succesfully...%d results", binFileEvent.Name, len(matches))
			scanResults <- BinaryMatches{Matches: matches, FileHash: filepath.Base(binFileEvent.Name)}
		}
	}
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
	defer log.Debugf("DB Worker exiting")
	defer wg.Done()

	for matches := range scanResults {
		log.Debugf("Results worker procesing result set %v",matches)
		for _, match := range matches.Matches {
			log.Debugf("Match is : %s %s %d %s ",matches.FileHash,match.Rule,int(match.Meta["score"].(int32)), match.Namespace)
			intscore := int(match.Meta["score"].(int32))
			//db.Create(&models.Result{Score: intscore, BinaryHash: matches.FileHash})
			db.Create(&models.Result{BinaryHash: matches.FileHash, RuleName: match.Rule, Score: intscore, Namespace: match.Namespace})
		}
		log.Debugf("Results worker done processing results for ... %s", matches.FileHash)
	}
 
}
