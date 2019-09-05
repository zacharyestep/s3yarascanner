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
	RulesetProvider RulesetProvider
	watcherBins  *fsnotify.Watcher
	watcherRules *fsnotify.Watcher
	resultsChan  chan BinaryMatches
	started      bool
	workerwaitgroup *sync.WaitGroup
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
	return &Scanner{RulesetProvider: wrp,workerwaitgroup: &sync.WaitGroup{},RuleDir: ruleDir, BinDir: binDir, resultsDB: db, watcherRules: watcherRules, watcherBins: watcherBins, resultsChan: make(chan BinaryMatches, 1000), started: false}, nil
}

//RulesetProvider is any source of yara rules providing a GetRules function
type RulesetProvider interface {
	LoadRules()	(error)
	GetRules() (* yara.Rules, error)
	Go(wg * sync.WaitGroup) 
}

//WatchedRulesetProvider is a RulesetProvider that updates the rules when a 
type WatchedRulesetProvider struct { 
	Compiler * yara.Compiler
	RulesChan <-chan fsnotify.Event
	RuleDB * gorm.DB
	sync.RWMutex
	rules * yara.Rules
	RuleDir string
}

//NewWatchedRulesetProvider factory method constructing a working RulesetProvider
func NewWatchedRulesetProvider(ruleDir string, ruleDb * gorm.DB, rulesUpdateChan <-chan fsnotify.Event) (* WatchedRulesetProvider , error) {
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
	wrp := WatchedRulesetProvider{Compiler: compiler, RuleDir: ruleDir, RuleDB: ruleDb , RulesChan: rulesUpdateChan}
	err = wrp.LoadRules()
	log.Debugf("Load rules returned %v errorcode",err)
	return &wrp,err
}

//Go -- run in a goroutine and update rules 
func (wrp * WatchedRulesetProvider) Go(wg * sync.WaitGroup) {
	wg.Add(1)
	defer log.Debug("WatchedRuleSetProvider -> Go exiting")
	defer wg.Done()
	for ruleEvent := range wrp.RulesChan { 
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
	wrp.RLock()
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
	return nil
}

//GetRules returns the rules from the underlying provider, or an error if that fails
func (scanr * Scanner) GetRules() (*yara.Rules, error) { 
	return scanr.RulesetProvider.GetRules()
}


//Start startup routine launches workers
func (scanr *Scanner) Start(workerNum int) {
	scanr.LoadBins()
	err := scanr.RulesetProvider.LoadRules()
	if err != nil { 
		log.Fatalf("Error starting scanner - %v",err)
	}
	if !scanr.started {
		for i := 0; i < workerNum; i++ {
			go ScanningWorker(scanr.BinDir, scanr.watcherBins.Events, scanr.resultsChan, scanr.RulesetProvider,scanr.workerwaitgroup)
		}
		go ResultDBWorker(scanr.resultsDB, scanr.resultsChan,scanr.workerwaitgroup)
		go scanr.RulesetProvider.Go(scanr.workerwaitgroup)
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
	log.Debugf("Scanner - all workers done -")
}

//LoadBins loads bins from disk into the db
func (scanr * Scanner) LoadBins() {
	bins, err := ioutil.ReadDir(scanr.BinDir)
	if err != nil {
		log.Fatalf("Error loading binary dir %s %v", scanr.BinDir, err)
	}
	for _, bin := range bins {
		log.Debugf(bin.Name())
		scanr.resultsDB.Create(&models.Binary{Hash: bin.Name()})
	}
}



//BinaryMatches pairs a Binary-Hash/filename with set of results from yarascans - [] yara.MatchRule
type BinaryMatches struct {
	Matches  []yara.MatchRule
	FileHash string
}

//ScanningWorker go routine worker that knows how to scan files by name using a configured ruleset
func ScanningWorker(binDir string, toScan <-chan fsnotify.Event, scanResults chan<- BinaryMatches, rulesetProvider RulesetProvider, wg * sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	for binFileEvent := range toScan {
		ruleset,err := rulesetProvider.GetRules()
		if err != nil {
			log.Fatalf("Error scanning - %v",err)
		}
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
			db.Create(models.Result{BinaryHash: matches.FileHash, RuleName: match.Rule, Score: match.Meta["Score"].(int), Namespace: match.Namespace})
		}
	}
	log.Debugf("DB Worker exiting")
}
