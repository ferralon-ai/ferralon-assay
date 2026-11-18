package buildgraph

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// CompileRequest is one compile of a repository's main classes with its own build tool.
type CompileRequest struct {
	Dir        string
	Tool       string // ToolMaven or ToolGradle
	Conditions Conditions
	Env        []string // the job's environment; the process's when nil
	// Timeout bounds the tool run on top of ctx; zero leaves ctx alone.
	Timeout time.Duration
	// Exec runs the tool; nil runs the process. A test stands in for it.
	Exec func(ctx context.Context, dir string, env []string, exe string, args []string) ([]byte, error)
}

// Compile runs the repository's own Maven or Gradle to compile its main classes, with the wrapper
// when the repository has one, under the run conditions the graph was resolved with. A failure is
// a *Failure whose Log is the cause (compile errors first), never the head of the tool's output.
// The command is the invocation a user can repeat: the tool as found ("./mvnw", else "mvn") and its
// arguments, set whether or not the run succeeded.
func Compile(ctx context.Context, req CompileRequest) (command string, _ *Failure) {
	env := req.Env
	if env == nil {
		env = os.Environ()
	}
	env = environ(env, req.Conditions.Env)
	wrapper, onPath, args := compileInvocation(req.Tool, req.Conditions)
	exe, shown, isWrapper, err := findTool(req.Dir, wrapper, onPath, env)
	if err != nil {
		var f *Failure
		_ = errors.As(err, &f)
		return onPath + " " + strings.Join(args, " "), f
	}
	if req.Tool == ToolGradle && isWrapper {
		env, _ = gradleJDK(req.Dir, env, req.Conditions)
	}
	command = shown + " " + strings.Join(args, " ")
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	run := req.Exec
	if run == nil {
		run = runProcess
	}
	out, err := run(ctx, req.Dir, env, exe, args)
	if err == nil {
		return command, nil
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return command, &Failure{Kind: KindToolFailed, Detail: "compile", Log: "stopped at its time limit: " + compileCause(out)}
	case ctx.Err() != nil:
		return command, &Failure{Kind: KindToolFailed, Detail: "compile", Log: "canceled before it finished: " + compileCause(out)}
	}
	f := classify("compile", out)
	f.Log = compileCause(out)
	var ee *exec.ExitError
	if !errors.As(err, &ee) && len(bytes.TrimSpace(out)) == 0 {
		f.Log = err.Error()
	}
	return command, f
}

// CompileCommand is the command Compile runs for dir, as a user would type it: the repository's
// wrapper when it has an executable one, else the tool on PATH.
func CompileCommand(dir, tool string, c Conditions) string {
	wrapper, onPath, args := compileInvocation(tool, c)
	shown := onPath
	if _, s, isWrapper, err := findTool(dir, wrapper, onPath, nil); err == nil && isWrapper {
		shown = s
	}
	return shown + " " + strings.Join(args, " ")
}

func compileInvocation(tool string, c Conditions) (wrapper, onPath string, args []string) {
	if tool == ToolGradle {
		return "gradlew", "gradle", gradleCompileArgs(c)
	}
	return "mvnw", "mvn", append(mavenBase(c), "compile")
}

func gradleCompileArgs(c Conditions) []string {
	args := []string{"--console=plain"}
	keys := make([]string, 0, len(c.Properties))
	for k := range c.Properties {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-P"+k+"="+c.Properties[k])
	}
	return append(args, "classes")
}

func runProcess(ctx context.Context, dir string, env []string, exe string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.WaitDelay = 10 * time.Second
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.Bytes(), err
}

// compileCauseMax bounds the cause a failure carries; compileCause keeps its beginning and end.
const compileCauseMax = 2000

// compileCause is what explains a failed build in the tool's output. Maven's error lines (the
// compiler's findings first, the failed goal last, its help footer dropped) and Gradle's "What went
// wrong" section are the cause; any other output is cut to its tail.
func compileCause(out []byte) string {
	s := string(out)
	if i := strings.Index(s, "* What went wrong:"); i >= 0 {
		s = s[i+len("* What went wrong:"):]
		if j := strings.Index(s, "* Try:"); j >= 0 {
			s = s[:j]
		}
		return clip(strings.TrimSpace(s))
	}
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, "\r")
		rest, ok := strings.CutPrefix(l, "[ERROR]")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if rest == "" || strings.HasPrefix(rest, "-> [Help") || strings.HasPrefix(rest, "[Help") ||
			strings.HasPrefix(rest, "To see the full stack trace") || strings.HasPrefix(rest, "Re-run Maven") ||
			strings.HasPrefix(rest, "For more information") || strings.HasPrefix(rest, "After correcting") ||
			strings.HasPrefix(rest, "mvn <args>") {
			continue
		}
		keep = append(keep, rest)
	}
	if len(keep) > 0 {
		return clip(strings.Join(keep, "\n"))
	}
	if len(s) > compileCauseMax {
		s = s[len(s)-compileCauseMax:]
	}
	return strings.TrimSpace(s)
}

func clip(s string) string {
	if len(s) <= compileCauseMax {
		return s
	}
	h := compileCauseMax / 2
	return s[:h] + "\n...\n" + s[len(s)-h:]
}
