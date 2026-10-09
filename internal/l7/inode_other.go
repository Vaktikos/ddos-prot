//go:build !unix

package l7

import "os"

func inode(os.FileInfo) uint64 { return 0 }
