package models

import (
		"github.com/jinzhu/gorm"
		"time"
	)

//Binary a binary that will be considered for scanning
type Binary struct {
	gorm.Model
	Hash string `gorm: "primary_key"`
	LastScanedAt time.Time
}
