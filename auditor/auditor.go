package auditor

import (
	"crypto/ecdh"
	"fmt"
	"os"
)

type Auditor struct {
	FileName string
	curve    ecdh.Curve
}

// NewAuditor creates a new Auditor instance
func NewAuditor(fileName string, c ecdh.Curve) *Auditor {
	return &Auditor{FileName: fileName, curve: c}
}

func (a *Auditor) InitializeDatabase() error {
	// Check if the file already exists.
	_, err := os.Stat(a.FileName)

	if err == nil {
		// File exists, clear its contents
		err = os.Truncate(a.FileName, 0)
		if err != nil {
			return err
		}
		fmt.Printf("Cleared contents of %s\n", a.FileName)
	} else if os.IsNotExist(err) {
		// File doesn't exist, create it.
		file, err := os.Create(a.FileName)
		if err != nil {
			return err
		}
		defer file.Close()
		fmt.Printf("Created %s\n", a.FileName)
	} else {
		return err
	}

	return nil
}
