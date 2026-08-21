package engineadapter

import (
	"context"
	"io"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestToArgumentsShapes(t *testing.T) {
	m, err := toArguments(nil)
	require.NoError(t, err)
	require.Empty(t, m)

	passthrough := map[string]any{"a": 1}
	m, err = toArguments(passthrough)
	require.NoError(t, err)
	require.Equal(t, passthrough, m)

	m, err = toArguments(struct {
		A string `json:"a"`
	}{A: "x"})
	require.NoError(t, err)
	require.Equal(t, "x", m["a"])

	_, err = toArguments(make(chan int))
	require.Error(t, err, "an unmarshallable value cannot become arguments")

	_, err = toArguments([]int{1})
	require.Error(t, err, "a non-object cannot become arguments")
}

func TestFirstTextFindsTheMessage(t *testing.T) {
	require.Equal(t, "boom", firstText(&mcp.CallToolResult{Content: []mcp.Content{
		&mcp.ImageContent{},
		&mcp.TextContent{Text: "boom"},
	}}))
	require.Equal(t, "engine reported an error with no message",
		firstText(&mcp.CallToolResult{}))
}

func TestNewMCPCallerDefaultsItsStderr(t *testing.T) {
	c := NewMCPCaller(t.TempDir(), "v0", nil)
	require.Equal(t, io.Discard, c.stderr)
}

func TestCallReportsAnUnresolvableEngine(t *testing.T) {
	c := NewMCPCaller(t.TempDir(), "v0", nil)
	err := c.Call(context.Background(), "nonsense://x", "declare", nil, nil)
	require.Error(t, err)
}

func TestCallReportsAnEngineThatCannotStart(t *testing.T) {
	c := NewMCPCaller(t.TempDir(), "v0", nil)
	err := c.Call(context.Background(), "alias://missing", "declare", nil, nil)
	require.Error(t, err)
}
