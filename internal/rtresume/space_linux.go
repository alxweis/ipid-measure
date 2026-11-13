//go:build linux

package rtresume

import (
	"fmt"
	"math"
	"syscall"
)

// Disk admission preserves the old source alongside the complete new result.
// The estimate includes 25% headroom and 8 GiB reserved for other VM writes.
func CheckSpace(directory string, p *Plan) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(directory, &st); err != nil {
		return err
	}
	needed := math.Ceil(float64(p.SourceEvidence.Size)/float64(p.Saved)*float64(p.Total)*1.25) + (8 << 30)
	available := float64(st.Bavail) * float64(st.Bsize)
	if available < needed {
		return fmt.Errorf("insufficient space for preserved original plus resumed output: %.1f GiB available, require %.1f GiB; enlarge the disk, do not delete the original", available/(1<<30), needed/(1<<30))
	}
	return nil
}
