package tui

type ReplayState struct {
	Enabled      bool
	CurrentIndex uint64
	TotalEvents  uint64
	Playing      bool
}
