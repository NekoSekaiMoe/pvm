package cow

// BackingOf returns the SYMLINK-RESOLVED absolute backing path recorded in
// the qcow2 header at path, or "" when the image is standalone (no backing
// file). Non-qcow2 (raw) inputs are standalone by definition and return "".
//
// The whole backing chain is opened (and containment-validated) exactly like
// any guest open, so a missing or disallowed hop surfaces as an error
// rather than a silently truncated chain. Callers guarding destructive
// operations treat that error as "cannot prove the chain safe" and fail
// closed — mirroring the engine's ErrRefScan semantics.
func BackingOf(path string) (string, error) {
	img, err := openGuestImage(path)
	if err != nil {
		return "", err
	}
	defer img.Close()
	qi, ok := img.(*qcow2Image)
	if !ok || qi.backing == nil {
		return "", nil
	}
	return qi.backingAbs, nil
}
