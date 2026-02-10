package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/bdubs00/constellation/internal/audit"
	"github.com/bdubs00/constellation/internal/config"
	"github.com/bdubs00/constellation/internal/policy"
)

// Proxy brokers JSON-RPC messages between an MCP client and server,
// evaluating tool calls against a policy engine.
type Proxy struct {
	engine       *policy.Engine
	logger       *audit.Logger
	serverName   string
	dryRun       bool
	serverStdin  io.Writer
	serverStdout io.Reader
	clientReader io.Reader
	clientWriter io.Writer
}

// Run starts the proxy. It spawns the MCP server as a child process and
// brokers messages between the client (our stdin/stdout) and the server.
func Run(serverName string, srv config.Server, engine *policy.Engine, logger *audit.Logger, dryRun bool, extraEnv map[string]string) error {
	logger.LogStartup(serverName, "")

	cmd := exec.Command(srv.Command, srv.Args...)
	cmd.Stderr = os.Stderr

	// Inject secrets as env vars
	cmd.Env = os.Environ()
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating server stdin pipe: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating server stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting server %q: %w", srv.Command, err)
	}

	p := &Proxy{
		engine:       engine,
		logger:       logger,
		serverName:   serverName,
		dryRun:       dryRun,
		serverStdin:  serverIn,
		serverStdout: serverOut,
		clientReader: os.Stdin,
		clientWriter: os.Stdout,
	}

	// Proxy server responses back to client
	go p.relayServerToClient()

	// Read client messages and evaluate them
	p.relayClientToServer()

	logger.LogShutdown(serverName)
	return cmd.Wait()
}

// relayClientToServer reads from the client, evaluates tool calls, and forwards.
func (p *Proxy) relayClientToServer() {
	scanner := bufio.NewScanner(p.clientReader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		p.handleClientMessage(scanner.Bytes())
	}
}

// handleClientMessage processes a single message from the client.
func (p *Proxy) handleClientMessage(data []byte) {
	msg, err := ParseMessage(data)
	if err != nil {
		log.Printf("failed to parse client message: %v", err)
		p.forward(data)
		return
	}

	if msg.Method == "tools/call" {
		p.handleToolCall(msg, data)
		return
	}

	// All other messages pass through
	p.forward(data)
}

// handleToolCall evaluates a tool call against the policy engine.
func (p *Proxy) handleToolCall(msg *Message, raw []byte) {
	tc, err := msg.AsToolCall()
	if err != nil {
		log.Printf("failed to parse tool call: %v", err)
		p.forward(raw)
		return
	}

	start := time.Now()
	decision := p.engine.Evaluate(tc.Name, tc.Arguments)
	durationMs := time.Since(start).Milliseconds()

	decisionStr := "deny"
	if decision.Allow {
		decisionStr = "allow"
	}

	p.logger.LogToolCall(audit.ToolCallEvent{
		Server:     p.serverName,
		Tool:       tc.Name,
		Arguments:  tc.Arguments,
		Decision:   decisionStr,
		Rule:       decision.MatchedRule,
		Reason:     decision.Reason,
		DurationMs: durationMs,
	})

	if decision.Allow || p.dryRun {
		p.forward(raw)
		return
	}

	// Denied — send error response back to client
	errResp := BuildErrorResponse(msg.ID, -32600, "tool call denied by policy: "+decision.Reason)
	errResp = append(errResp, '\n')
	p.clientWriter.Write(errResp)
}

// relayServerToClient reads from the server and forwards to the client,
// filtering tools/list responses to hide unauthorized tools.
func (p *Proxy) relayServerToClient() {
	scanner := bufio.NewScanner(p.serverStdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		data := scanner.Bytes()

		msg, err := ParseMessage(data)
		if err != nil {
			p.clientWriter.Write(append(data, '\n'))
			continue
		}

		// Filter tools/list responses
		if msg.IsResponse() && msg.Result != nil {
			if filtered, err := p.maybeFilterToolList(msg); err == nil && filtered != nil {
				p.clientWriter.Write(append(filtered, '\n'))
				continue
			}
		}

		p.clientWriter.Write(append(data, '\n'))
	}
}

// maybeFilterToolList checks if a response looks like a tools/list response
// and filters it. Returns nil if it's not a tools/list response.
func (p *Proxy) maybeFilterToolList(msg *Message) ([]byte, error) {
	tools, err := msg.AsToolList()
	if err != nil || len(tools) == 0 {
		return nil, err
	}

	allowed := p.engine.AllowedTools()
	if len(allowed) == 0 {
		return nil, nil
	}

	return FilterToolListResponse(msg.Raw, allowed)
}

// forward sends data to the server's stdin.
func (p *Proxy) forward(data []byte) {
	p.serverStdin.Write(append(data, '\n'))
}
