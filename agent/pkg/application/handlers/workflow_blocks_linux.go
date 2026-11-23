//go:build linux

package handlers

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// firstCapture returns the first regex capture group of the first match, or
// the whole match when the pattern has no groups. Empty when no match.
func firstCapture(pattern, content string) (string, bool, error) {
	if pattern == "" {
		return "", false, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", false, fmt.Errorf("invalid pattern: %w", err)
	}
	m := re.FindStringSubmatch(content)
	if m == nil {
		return "", false, nil
	}
	if len(m) > 1 {
		return m[1], true, nil
	}
	return m[0], true, nil
}

// handleReadFile reads a text file and returns its content (and an optional
// regex capture) as command result outputs.
func (h *CommandHandler) handleReadFile(commandID string, cmd *proto.ReadFileCommand) error {
	h.logger.Info("read file command received", "command_id", commandID, "path", cmd.Path)
	h.reportCommandStatus(commandID, "in_progress", 0, fmt.Sprintf("Reading %s", cmd.Path))

	// Resolve and check the path the same way write and delete do. This read had
	// no protected-path enforcement on the agent at all: readFileBounded's
	// O_NOFOLLOW refuses a symlinked FINAL component, but a symlinked PARENT
	// walked straight through it, so /etc/orchestrator -> somewhere would have
	// handed back the adoption file's impersonation token. The backend's path
	// policy was the only thing in the way, and the agent must not depend on its
	// caller for that.
	path, err := h.resolveForFileRead(cmd.Path, h.adoptionFilePath)
	if err != nil {
		h.reportCommandStatus(commandID, "failed", 0, err.Error())
		return err
	}

	// Bounded, symlink-safe, regular-files-only. An unbounded os.ReadFile here
	// could block on a FIFO, allocate all of memory on /proc/kcore, or return
	// non-UTF-8 bytes that fail the proto marshal and tear down this node's
	// command stream — the failure lands on the connection, not the command.
	content, meta, err := readFileBounded(path, int64(cmd.MaxBytes))
	if err != nil {
		errMsg := fmt.Sprintf("failed to read file: %v", err)
		h.reportCommandStatus(commandID, "failed", 0, errMsg)
		return fmt.Errorf("%s", errMsg)
	}
	result := map[string]string{"content": content}
	for k, v := range meta {
		result[k] = v
	}
	if meta["truncated"] == "true" || meta["binary"] == "true" {
		// Reported as a FAILURE, not a success with empty content: a playbook
		// doing read_file -> write_file would otherwise copy an empty file
		// somewhere and stay green. The metadata still travels so the caller
		// can say which limit was hit.
		why := "is larger than the read limit"
		if meta["binary"] == "true" {
			why = "is not valid UTF-8 text"
		}
		h.reportCommandResult(commandID, "failed", fmt.Sprintf("%s %s", cmd.Path, why), result)
		return fmt.Errorf("%s %s", cmd.Path, why)
	}
	if cmd.Pattern != "" {
		match, ok, err := firstCapture(cmd.Pattern, content)
		if err != nil {
			h.reportCommandStatus(commandID, "failed", 0, err.Error())
			return err
		}
		if ok {
			result["match"] = match
		}
	}
	h.reportCommandResult(commandID, "success", fmt.Sprintf("Read %s (%d bytes)", cmd.Path, len(content)), result)
	return nil
}

// handleWaitForFile polls a file until its content matches the regex or the
// timeout elapses. The first capture group is returned as the "match" output.
func (h *CommandHandler) handleWaitForFile(commandID string, cmd *proto.WaitForFileCommand) error {
	// Bounded for the reason reboot/shutdown delays are (command_delay.go): both
	// run on the agent's single command goroutine, so an unbounded value parks
	// this node's command handling — and a parked handler also blocks terminal
	// frames, because dispatch is inline on the read loop. The platform clamps
	// too; this is the agent's own bound, since a command can arrive from an
	// older backend or a platform that is not this repository's.
	timeout := time.Duration(clamp32(cmd.TimeoutSeconds, 1, maxBlockTimeoutSeconds, 600)) * time.Second
	interval := time.Duration(clamp32(cmd.IntervalSeconds, 1, maxBlockTimeoutSeconds, 10)) * time.Second
	// An interval longer than the timeout means the loop sleeps past its own
	// deadline: the check below only runs BETWEEN polls, so the command would
	// outlive the timeout it was given by the length of one sleep.
	if interval > timeout {
		interval = timeout
	}
	h.logger.Info("wait for file command received", "command_id", commandID, "path", cmd.Path, "timeout", timeout)

	// Same read policy as read_file, and for the same reason. This was the one
	// file handler that called readFileBounded directly, so nothing checked the
	// refuse-list, the /proc|/sys|/dev|/run prefixes, or the adoption file —
	// while the block returns the first regex capture group, which is all an
	// exfiltration needs: path=<adoption file>, pattern="unique_token":"([^"]+)"
	// hands back the credential that impersonates this node. The privileged-block
	// comment in the backend's authz mapping names this threat for read_file AND
	// wait_for_file, which is what makes the omission an oversight rather than a
	// decision.
	path, err := h.resolveForFileRead(cmd.Path, h.adoptionFilePath)
	if err != nil {
		h.reportCommandResult(commandID, "failed", err.Error(), nil)
		return err
	}

	h.reportCommandStatus(commandID, "in_progress", 0, fmt.Sprintf("Waiting for %s to match", cmd.Path))

	deadline := time.Now().Add(timeout)
	for {
		// Re-resolve on every poll. When the parent did not exist at dispatch
		// the first resolve could only hand back the cleaned string, symlinks
		// and all, and the anchored read refuses any symlink component
		// — so a file under /var/log on the Buildroot bootstrap
		// (/var/log -> ../tmp) whose directory a script creates later would
		// never match. A policy refusal stays a refusal; anything else keeps
		// the previous path.
		if p, rerr := h.resolveForFileRead(cmd.Path, h.adoptionFilePath); rerr == nil {
			path = p
		} else {
			h.reportCommandStatus(commandID, "failed", 0, rerr.Error())
			return rerr
		}
		// Bounded like read_file: the deadline below is only checked between
		// polls, so a blocking read here would never time out and would hold
		// the agent's only command goroutine forever.
		if data, _, err := readFileBounded(path, DefaultReadMaxBytes); err == nil {
			match, ok, err := firstCapture(cmd.Pattern, data)
			if err != nil {
				h.reportCommandStatus(commandID, "failed", 0, err.Error())
				return err
			}
			if ok {
				h.reportCommandResult(commandID, "success", "Match found", map[string]string{"match": match})
				return nil
			}
		}
		if time.Now().After(deadline) {
			errMsg := fmt.Sprintf("timed out after %s waiting for %s to match", timeout, cmd.Path)
			h.reportCommandStatus(commandID, "failed", 0, errMsg)
			return fmt.Errorf("%s", errMsg)
		}
		// Never sleep past the deadline: time.Sleep is not cancellable, so a
		// long interval would hold the goroutine well after the command has
		// logically failed.
		sleep := interval
		if remaining := time.Until(deadline); remaining < sleep {
			sleep = remaining
		}
		if sleep > 0 {
			time.Sleep(sleep)
		}
	}
}

// handleRunScript runs a shell script and returns exit_code/stdout/stderr.
func (h *CommandHandler) handleRunScript(commandID string, cmd *proto.RunScriptCommand) error {
	// Bounded like wait_for_file above: this one is cancellable (context), but
	// an unbounded value still holds the single command goroutine for as long
	// as the caller asked.
	timeout := time.Duration(clamp32(cmd.TimeoutSeconds, 1, maxBlockTimeoutSeconds, 300)) * time.Second
	h.logger.Info("run script command received", "command_id", commandID, "timeout", timeout)
	h.reportCommandStatus(commandID, "in_progress", 0, "Running script")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Never `sh -c <script>`: the body carries resolved secrets, and argv is
	// readable by every local account (newScriptCommand).
	command, cleanupScript, err := newScriptCommand(ctx, cmd.Script)
	if err != nil {
		h.reportCommandResult(commandID, "failed", err.Error(), nil)
		return err
	}
	defer cleanupScript()
	// Bounded, not a strings.Builder: the result travels in one gRPC frame on
	// the node's stream, and an oversized frame kills the CONNECTION rather
	// than the command. See MaxResultOutputBytes for what that cost.
	stdout, stderr := newBoundedBuffer(), newBoundedBuffer()
	command.Stdout = stdout
	command.Stderr = stderr
	// Because Stdout/Stderr are not *os.File, exec gives the child OS pipes and
	// Run waits for them to reach EOF. A cancel kills the script's process
	// group (newScriptCommand), but a script that ends normally after forking
	// a daemon — `something &`, anything that daemonises or leaves the group —
	// leaves a process holding the write end, and Run would block forever. This runs on the agent's single command
	// goroutine, so that one script wedges every later command on the node.
	// WaitDelay stops waiting for the pipes shortly after the context ends;
	// output produced up to that point is still reported.
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()

	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		switch {
		case errors.As(runErr, &exitErr):
			exitCode = exitErr.ExitCode()
		case errors.Is(runErr, exec.ErrWaitDelay) && command.ProcessState != nil:
			// WaitDelay fired, which is NOT a script failure: the script exited
			// and something it backgrounded is still holding the stdout pipe.
			// exec reports that as ErrWaitDelay, which is not an ExitError, so
			// the -1 fallback below marked every such run failed — a script
			// ending in `mydaemon &` returned "exited with code -1" after
			// exiting cleanly with 0, and unattended playbooks failed on it.
			// The real status is on ProcessState.
			exitCode = command.ProcessState.ExitCode()
		default:
			exitCode = -1
		}
	}
	result := map[string]string{
		"exit_code": fmt.Sprintf("%d", exitCode),
		"stdout":    stdout.String(),
		"stderr":    stderr.String(),
	}
	if ctx.Err() == context.DeadlineExceeded {
		h.reportCommandResult(commandID, "failed", "script timed out", result)
		return fmt.Errorf("script timed out after %s", timeout)
	}
	if exitCode != 0 {
		h.reportCommandResult(commandID, "failed", fmt.Sprintf("script exited with code %d", exitCode), result)
		return fmt.Errorf("script exited with code %d", exitCode)
	}
	h.reportCommandResult(commandID, "success", "Script completed", result)
	return nil
}
