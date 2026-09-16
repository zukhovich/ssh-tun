package cli

func needsElevation(tunMode bool) bool { return tunMode && !isElevated() }
