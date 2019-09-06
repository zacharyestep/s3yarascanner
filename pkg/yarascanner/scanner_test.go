package yarascanner

import (
	log "github.com/sirupsen/logrus"
	"testing"
	"github.com/jinzhu/gorm"
	//sqlitedilact for gorm
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/zacharyestep/s3yarascanner/pkg/models"
	"os"
	"time"
)


//Test the scanners function
func TestScanner(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	//func NewScanner(binDir,ruleDir string, db * gorm.DB) (*Scanner, error) {
	log.Debugf("starting test")
	os.Remove("test/results.db")
	gdb,err := gorm.Open("sqlite3","test/results.db")	
	if err != nil { 
		t.Fatalf("Error opening db for tests ... %s %v","test/results.db",err)
	}

	gdb.AutoMigrate(&models.Binary{},&models.Rule{},&models.Result{})

	scanner, err := NewScanner("test/bins","test/rules",gdb)
	if err != nil { 
		t.Fatalf("%v",err)
	}

	scanner.Start(1)
	time.Sleep(3 * time.Second)

	resultscans := make([] models.Result,0)
	gdb.Find(&resultscans)
	expected := 1
	actual := len(resultscans)

	if actual != expected { 
		t.Errorf("ERROR FROM DB! actual results - %d != expected results - %d",actual, expected)
	}

	scanner.Close()
	gdb.Close()
}