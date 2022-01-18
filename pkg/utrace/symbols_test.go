package utrace

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListSymbols(t *testing.T) {
	pid := os.Getpid()
	symbols, err := ListSymbolsFromPID(pid)
	require.NoError(t, err)
	fmt.Println("map:", symbols)
}
