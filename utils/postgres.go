package utils

import (
	"fmt"
)

var PGConnection = fmt.Sprintf(
	"host=%s user=%s password=%s dbname=%s port=%d",
	"localhost", "postgres", "postgres", "postgres", 5432,
)
