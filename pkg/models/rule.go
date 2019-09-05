package models

import (
		"github.com/jinzhu/gorm"
)

//Rule is a yara rule that will be used for scanning
type Rule struct {
	gorm.Model
	Name string `gorm: "primary_key"`
}