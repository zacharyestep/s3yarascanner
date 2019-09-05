package models

import (
	"github.com/jinzhu/gorm"
	"time"
)

//Result - Result of scanning a binary with yara ruleset
type Result struct {
	gorm.Model
	BinaryHash	string
	Score	int
	RuleName string 
	Namespace string
	ID	int64
	Created time.Time
}