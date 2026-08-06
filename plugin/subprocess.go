package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// runSubprocessCall is the ONE shared choke point every language plugin's run funnels through,
// and so the one place analyzer compute is metered.
// goPlugin/dotnetPlugin/javaPlugin/jsPlugin/pythonPlugin each
// have their own independent subprocess transport — there is no common struct or interface below
// LanguagePlugin they all satisfy that a single call site could meter once — so instrumenting the
// five `run` methods individually risked exactly the drift found in review (only goPlugin.run was
// metered; the other four ran dark). Factoring the record logic into this one helper means all
// five funnel through byte-identical instrumentation, and a future 6th language plugin gets
// metering for free just by calling this same function from its own run.
//
// It emits tegron.plugin.call.count + .duration exactly once per call, carrying cost_class=cogs,
// the REAL per-plugin language (the caller's own Language(), never a hard-coded constant),
// plugin.op, and — on failure — error.type.
func runSubprocessCall(ctx context.Context, bin, language string, metrics *pluginMetrics, req Request) (*Response, error) {
	start := time.Now()
	resp, err := execSubprocess(ctx, bin, req)

	attrs := []attribute.KeyValue{
		attribute.String(attrCostClass, costClassCOGS),
		attribute.String(attrLanguage, language),
		attribute.String(attrPluginOp, string(req.Op)),
	}
	if err != nil {
		attrs = append(attrs, attribute.String(attrErrorType, errorType(err)))
	}
	set := metric.WithAttributes(attrs...)
	metrics.callCount.Add(ctx, 1, set)
	metrics.callDuration.Record(ctx, time.Since(start).Seconds(), set)
	return resp, err
}

// execSubprocess performs one bounded subprocess exchange, shared by every language plugin's run:
// marshal req to a single newline-JSON line, exec.CommandContext the binary, write the line to
// stdin and close it, read one newline-delimited JSON line from stdout, Wait, unmarshal the
// Response, and verify the protocol version. Any non-empty Response.Error, non-zero exit, or
// transport failure is mapped to a wrapped Go error with ZERO retries (inv.4). On success it
// returns the decoded Response; declared partiality lives in the payload, not here (§4.3).
func execSubprocess(ctx context.Context, bin string, req Request) (*Response, error) {
	req.Protocol = ProtocolVersion

	reqLine, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("plugin: marshal %s request: %w", req.Op, err)
	}
	reqLine = append(reqLine, '\n')

	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = bytes.NewReader(reqLine)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	if stdout.Len() > 0 {
		line, _ := bufio.NewReader(&stdout).ReadBytes('\n')
		var resp Response
		if jsonErr := json.Unmarshal(bytes.TrimSpace(line), &resp); jsonErr == nil {
			if runErr != nil {
				return nil, fmt.Errorf("plugin: %s subprocess exited non-zero: %w (stderr: %s)", req.Op, runErr, stderr.String())
			}
			if resp.Protocol != ProtocolVersion {
				return nil, fmt.Errorf("plugin: %s response protocol %q != %q", req.Op, resp.Protocol, ProtocolVersion)
			}
			if resp.Error != "" {
				return nil, fmt.Errorf("plugin: %s failed: %s", req.Op, resp.Error)
			}
			return &resp, nil
		}
	}

	if runErr != nil {
		return nil, fmt.Errorf("plugin: %s subprocess failed: %w (stderr: %s)", req.Op, runErr, stderr.String())
	}
	return nil, fmt.Errorf("plugin: %s produced no decodable response (stderr: %s)", req.Op, stderr.String())
}
