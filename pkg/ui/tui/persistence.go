package tui

import (
	"encoding/json"
	"os"
)

type UIStateFile struct {
	Version int     `json:"version"`
	State   UIState `json:"state"`
}

const CurrentUIStateVersion = 1

func SaveUIState(path string, state UIState) error {
	fileState := UIStateFile{
		Version: CurrentUIStateVersion,
		State:   state,
	}
	
	data, err := json.MarshalIndent(fileState, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(path, data, 0644)
}

func LoadUIState(path string) (UIState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return UIState{}, err
	}
	
	var fileState UIStateFile
	if err := json.Unmarshal(data, &fileState); err != nil {
		return UIState{}, err
	}
	
	// Future migration logic goes here based on fileState.Version
	// if fileState.Version == 1 { ... }
	
	return fileState.State, nil
}
