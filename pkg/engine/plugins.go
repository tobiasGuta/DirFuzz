package engine

import (
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

// PluginMatcher wraps a Lua script that matches responses
type PluginMatcher struct {
	vm   *lua.LState
	file string
}

// PluginMutator wraps a Lua script that mutates payloads
type PluginMutator struct {
	vm   *lua.LState
	file string
}

// NewPluginMatcher creates a new Lua-based matcher
func NewPluginMatcher(scriptPath string) (*PluginMatcher, error) {
	L := lua.NewState()

	if err := L.DoFile(scriptPath); err != nil {
		L.Close()
		return nil, fmt.Errorf("failed to load plugin: %w", err)
	}

	// Verify the match function exists
	matchFunc := L.GetGlobal("match")
	if matchFunc == lua.LNil {
		L.Close()
		return nil, fmt.Errorf("plugin must define a 'match' function")
	}

	return &PluginMatcher{vm: L, file: scriptPath}, nil
}

// Match executes the Lua match function
func (pm *PluginMatcher) Match(statusCode, size, words, lines int, body, contentType string) bool {
	matchFunc := pm.vm.GetGlobal("match")
	if matchFunc == lua.LNil {
		return false
	}

	// Create response table
	respTable := pm.vm.NewTable()
	pm.vm.SetField(respTable, "status_code", lua.LNumber(statusCode))
	pm.vm.SetField(respTable, "size", lua.LNumber(size))
	pm.vm.SetField(respTable, "words", lua.LNumber(words))
	pm.vm.SetField(respTable, "lines", lua.LNumber(lines))
	pm.vm.SetField(respTable, "body", lua.LString(body))
	pm.vm.SetField(respTable, "content_type", lua.LString(contentType))

	// Call match function
	if err := pm.vm.CallByParam(lua.P{
		Fn:      matchFunc,
		NRet:    1,
		Protect: true,
	}, respTable); err != nil {
		return false
	}

	// Get result
	result := pm.vm.Get(-1)
	pm.vm.Pop(1)

	return lua.LVAsBool(result)
}

// Close cleans up the Lua state
func (pm *PluginMatcher) Close() {
	if pm.vm != nil {
		pm.vm.Close()
	}
}

// NewPluginMutator creates a new Lua-based mutator
func NewPluginMutator(scriptPath string) (*PluginMutator, error) {
	L := lua.NewState()

	if err := L.DoFile(scriptPath); err != nil {
		L.Close()
		return nil, fmt.Errorf("failed to load plugin: %w", err)
	}

	// Verify the mutate function exists
	mutateFunc := L.GetGlobal("mutate")
	if mutateFunc == lua.LNil {
		L.Close()
		return nil, fmt.Errorf("plugin must define a 'mutate' function")
	}

	return &PluginMutator{vm: L, file: scriptPath}, nil
}

// Mutate executes the Lua mutate function
func (pm *PluginMutator) Mutate(original string) []string {
	mutateFunc := pm.vm.GetGlobal("mutate")
	if mutateFunc == lua.LNil {
		return []string{original}
	}

	// Call mutate function
	if err := pm.vm.CallByParam(lua.P{
		Fn:      mutateFunc,
		NRet:    1,
		Protect: true,
	}, lua.LString(original)); err != nil {
		return []string{original}
	}

	// Get result (should be a table/array)
	result := pm.vm.Get(-1)
	pm.vm.Pop(1)

	if table, ok := result.(*lua.LTable); ok {
		var variants []string
		table.ForEach(func(_ lua.LValue, val lua.LValue) {
			if str, ok := val.(lua.LString); ok {
				variants = append(variants, string(str))
			}
		})
		return variants
	}

	return []string{original}
}

// Close cleans up the Lua state
func (pm *PluginMutator) Close() {
	if pm.vm != nil {
		pm.vm.Close()
	}
}
