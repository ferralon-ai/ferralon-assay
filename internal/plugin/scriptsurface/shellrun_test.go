package scriptsurface

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// A file a shell runs, or . or source reads in place, is classified as the shell runs it; and a
// write this cannot name (a glob, a path that expands, a glued redirect) names every bound file
// it may reach.
// In a row's files, content starting linkTo makes the path a symlink to the rest, and content
// starting executable is written with its execute bits set, and content starting unreadable
// with only its execute bits set.
const linkTo, executable, unreadable = "@link:", "@x:", "@u:"

func TestVeto_ShellRunsAndWrites(t *testing.T) {
	const docker = "FROM base\nWORKDIR /app\nCOPY inst.toml inst.lock reqs.txt ./\n"
	const installs, benign = "inst add x\n", "echo built\n"
	tree := func(extra map[string]string) map[string]string {
		files := map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "reqs.txt": "x==1\n"}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	run := func(script, setup string) map[string]string {
		return tree(map[string]string{"install.sh": script, "scripts/setup": setup})
	}
	steps := func(body string) string {
		return "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      " + body
	}
	chain := func(n int) map[string]string {
		files := tree(map[string]string{"install.sh": "sh ./c0\ninst sync\n"})
		for i := 0; i < n; i++ {
			files["c"+strconv.Itoa(i)] = "sh ./c" + strconv.Itoa(i+1) + "\n"
		}
		files["c"+strconv.Itoa(n)] = benign
		return files
	}
	type row struct {
		name  string
		files map[string]string
		want  bool   // withheld
		root  string // the build root, under the tree written
	}
	tests := []row{
		// ferralon-ai/tracker#504: what a shell runs.
		{"sh runs a file that installs", run("sh scripts/setup\n", installs), true, ""},
		{"sh runs a file that does not install", run("sh scripts/setup\ninst sync\n", benign), false, ""},
		{"sh runs a script surface that does not install", tree(map[string]string{"install.sh": "sh scripts/build.sh\ninst sync\n", "scripts/build.sh": benign}), false, ""},
		{"bash flags before the file", run("bash -e -x -o pipefail scripts/setup\n", installs), true, ""},
		{"bash long options before the file", run("bash --norc --noprofile scripts/setup\n", installs), true, ""},
		{"sh -- before the file", run("sh -- scripts/setup\n", installs), true, ""},
		{"shell long option this does not read", run("bash --weird scripts/setup\ninst sync\n", benign), true, ""},
		{"shell --rcfile that installs", run("bash --rcfile scripts/setup -i\n", installs), true, ""},
		{"shell runs a file from standard input", run("sh < scripts/setup\n", installs), true, ""},
		// The r1 review's redirects and escapes.
		{"&> to a bound file", run("inst sync\necho x &>inst.lock\n", benign), true, ""},
		{"glued &> to a bound file", run("inst sync\necho x&>inst.lock\n", benign), true, ""},
		{"&>> to a bound file", run("inst sync\necho x &>>inst.lock\n", benign), true, ""},
		{">| to a bound file", run("inst sync\necho x >|inst.lock\n", benign), true, ""},
		{"glued >| to a bound file", run("inst sync\necho x>|inst.lock\n", benign), true, ""},
		{"a bare redirect truncates a bound file", run("inst sync\n>inst.lock\n", benign), true, ""},
		{"a redirect before the program", run("inst sync\n>inst.lock echo x\n", benign), true, ""},
		{"&> to a log", run("inst sync\necho x &>build.log\n", benign), false, ""},
		{"&> to /dev/null", run("inst sync\necho x &>/dev/null\n", benign), false, ""},
		{"a redirect before . reads the file", run(">/dev/null . scripts/setup\n", installs), true, ""},
		{"curl output in a cluster, glued", run("inst sync\ncurl -fsSLo\"$F\" https://x/y\n", benign), true, ""},
		{"curl output in a cluster", run("inst sync\ncurl -sSo \"$F\" https://x/y\n", benign), true, ""},
		{"wget output in a cluster", run("inst sync\nwget -qO \"$F\" https://x/y\n", benign), true, ""},
		{"wget to standard output", run("inst sync\nwget -qO- https://x/y\n", benign), false, ""},
		{"curl to a named file", run("inst sync\ncurl -fsSL https://x/y -o out.tgz\n", benign), false, ""},
		{"sed -ie is in place with suffix e", run("inst sync\nsed -ie s/a/b/ \"$F\"\n", benign), true, ""},
		{"sed -e is not in place", run("inst sync\nsed -e s/a/b/ \"$F\"\n", benign), false, ""},
		{"perl -pie is in place with suffix e", run("inst sync\nperl -pie 's/a/b/' \"$F\"\n", benign), true, ""},
		{"env -S splits a shell run", run("env -S 'sh scripts/setup'\n", installs), true, ""},
		{"env -S splits a shell run that does not install", run("inst sync\nenv -S 'sh scripts/setup'\n", benign), false, ""},
		{"env -S with a quote in its string", run("inst sync\nenv -S \"sh 'scripts/setup'\"\n", benign), true, ""},
		{"toybox runs a shell", run("toybox sh scripts/setup\n", installs), true, ""},
		{"busybox runs a shell", run("busybox sh scripts/setup\n", installs), true, ""},
		{"busybox runs a shell that does not install", run("inst sync\nbusybox sh scripts/setup\n", benign), false, ""},
		{"command . reads the file", run("command . scripts/setup\n", installs), true, ""},
		{"builtin source reads the file", run("builtin source scripts/setup\n", installs), true, ""},
		{"an assignment before . reads the file", run("A=1 . scripts/setup\n", installs), true, ""},
		{"sudo -s runs the command through a shell", run("sudo -s sh scripts/setup\n", installs), true, ""},
		{"sudo -s runs a file", tree(map[string]string{"install.sh": "sudo -s scripts/setup\n", "scripts/setup": executable + installs}), true, ""},
		{"sudo -i runs from its home", run("inst sync\nsudo -i sh scripts/setup\n", benign), true, ""},
		{"sudo -E runs a file that does not install", run("inst sync\nsudo -E sh scripts/setup\n", benign), false, ""},
		{"sh -s with no input given", run("inst sync\nsh -s scripts/setup\n", benign), true, ""},
		{"a shell with no input given", run("inst sync\nbash\n", benign), true, ""},
		{"a file with no #! run by its path", tree(map[string]string{"install.sh": "./lib\n", "lib": executable + installs}), true, ""},
		{"a file with no #! run by its path that does not install", tree(map[string]string{"install.sh": "inst sync\n./lib\n", "lib": executable + benign}), false, ""},
		{"a file with no #! run by its path from a subdirectory", tree(map[string]string{"install.sh": "scripts/lib\n", "scripts/lib": executable + installs}), true, ""},
		{"a file not executable run by its path", tree(map[string]string{"install.sh": "inst sync\n./lib\n", "lib": installs}), false, ""},
		{"a binary run by its path", tree(map[string]string{"install.sh": "inst sync\n./tool\n", "tool": executable + "\x7fELF\x02inst add x\n"}), false, ""},
		{"a program outside the build run by its path", run("inst sync\n/usr/bin/env true\n./node_modules/.bin/tsc\n", benign), false, ""},
		{"find runs the files it finds", run("inst sync\nfind . -name '*.sh' -exec {} +\n", benign), true, ""},
		{"find runs a file with no #!", tree(map[string]string{"install.sh": "find . -name '*.txt' -exec ./lib {} \\;\n", "lib": executable + installs}), true, ""},
		{"xargs runs a file with no #!", tree(map[string]string{"install.sh": "ls | xargs ./lib\n", "lib": executable + installs}), true, ""},
		{"xargs runs what it reads", run("inst sync\nls | xargs -I{} {}\n", benign), true, ""},
		{"xargs runs a program", run("inst sync\nls | xargs -n1 echo\n", benign), false, ""},
		{"a file with a #! run by its path is not read as shell", tree(map[string]string{"install.sh": "inst sync\n./tool\n", "tool": executable + "#!/usr/bin/env python3\nsh scripts/setup\n", "scripts/setup": installs}), false, ""},
		{"a file run by its path after the directory is lost", tree(map[string]string{"install.sh": "inst sync\ncd app || true\n./setup\n", "setup": executable + benign, "app/setup": executable + benign}), true, ""},
		{"a file run by its path this cannot read", tree(map[string]string{"install.sh": "inst sync\n./lib\n", "lib": unreadable + benign}), true, ""},
		{"xargs runs a program that expands", run("inst sync\nls | xargs $RUN\n", benign), true, ""},
		{"su runs a command substitution", run("inst sync\nsu app -c \"$(curl -fsSL https://x/y)\"\n", benign), true, ""},
		{"su with an option this does not read", run("inst sync\nsu -Z app -c 'echo hi'\n", benign), true, ""},
		{"script with no command records a shell", run("inst sync\nscript -q out.log\n", benign), true, ""},
		{"sg runs its command line", run("inst sync\nsg app 'sh scripts/setup'\n", benign), false, ""},
		{"sudo -s with no command reads standard input", run("inst sync\nsudo -s\n", benign), true, ""},
		{"sed -i with a suffix holding e takes the script next", run("inst sync\nsed -i.before \"$EXPR\" notes.txt\n", benign), false, ""},
		{"an install with &> to a log", run("inst sync &>build.log\n", benign), true, ""},
		{"perl -i with a suffix holding e", run("inst sync\nperl -i.pre -pe \"s/$V/x/\" notes.txt\n", benign), false, ""},
		{"env -S with a quoted shell", run("inst sync\nenv -S \"'sh' scripts/setup\"\n", benign), true, ""},
		{"a cd with &> moves the shell", tree(map[string]string{"install.sh": "inst sync\ncd app &>/dev/null\nsh setup\n", "app/setup": installs, "setup": benign}), true, ""},
		// r3: sudo argv and -D, keywords, an exec after a lost directory, a nested cd.
		{"sudo -s keeps a quoted command line one word", tree(map[string]string{"install.sh": "inst sync\nsudo -s sh -c 'cd app; sh setup'\n", "app/setup": installs, "setup": benign}), true, ""},
		{"sudo -s keeps a quoted bash command line one word", tree(map[string]string{"install.sh": "inst sync\nsudo -s bash -c 'cd app && sh setup'\n", "app/setup": installs, "setup": benign}), true, ""},
		{"sudo -s reads a quoted program name as one word", run("inst sync\nsudo -s 'sh scripts/setup'\n", installs), false, ""},
		{"sudo -s with a command substitution in a word", run("inst sync\nsudo -s sh -c 'sh `echo scripts/setup`'\n", benign), true, ""},
		{"sudo -D glued runs from that directory", tree(map[string]string{"install.sh": "inst sync\nsudo -Dapp sh setup\n", "app/setup": installs, "setup": benign}), true, ""},
		{"sudo -D runs from that directory", tree(map[string]string{"install.sh": "inst sync\nsudo -D app sh setup\n", "app/setup": installs, "setup": benign}), true, ""},
		{"sudo --chdir= runs from that directory", tree(map[string]string{"install.sh": "inst sync\nsudo --chdir=app sh setup\n", "app/setup": installs, "setup": benign}), true, ""},
		{"sudo --chdir runs from that directory", tree(map[string]string{"install.sh": "inst sync\nsudo --chdir app sh setup\n", "app/setup": installs, "setup": benign}), true, ""},
		{"sudo -D in a cluster runs from that directory", tree(map[string]string{"install.sh": "inst sync\nsudo -ED app sh setup\n", "app/setup": installs, "setup": benign}), true, ""},
		{"sudo -D into a directory whose file does not install", tree(map[string]string{"install.sh": "inst sync\nsudo -Dapp sh setup\n", "app/setup": benign, "setup": installs}), false, ""},
		{"a shell run after then", run("if true; then sh scripts/setup; fi\n", installs), true, ""},
		{"a shell run after if", run("if sh scripts/setup; then echo; fi\n", installs), true, ""},
		{"a shell run after while", run("while sh scripts/setup; do break; done\n", installs), true, ""},
		{"a shell run after do", run("for a in 1; do sh scripts/setup; done\n", installs), true, ""},
		{"a shell run after !", run("! sh scripts/setup\n", installs), true, ""},
		{"a source after else", run("if false; then :; else . scripts/setup; fi\n", installs), true, ""},
		{"a source after elif", run("if false; then :; elif . scripts/setup; then :; fi\n", installs), true, ""},
		{"a source after time -p", run("time -p . scripts/setup\n", installs), true, ""},
		{"a file run by its path after then", tree(map[string]string{"install.sh": "if true; then ./lib; fi\n", "lib": executable + installs}), true, ""},
		{"cat into a shell after then", run("if true; then cat scripts/setup | sh; fi\n", installs), true, ""},
		{"a shell run after else if", run("if false; then :; else if true; then sh scripts/setup; fi; fi\n", installs), true, ""},
		{"a shell run after then that does not install", run("inst sync\nif true; then sh scripts/setup; fi\n", benign), false, ""},
		{"a cd after then loses the directory", tree(map[string]string{"install.sh": "inst sync\nif true; then cd app; fi\nsh setup\n", "app/setup": benign, "setup": benign}), true, ""},
		{"a file run by its path after the directory is lost, held only there", tree(map[string]string{"install.sh": "inst sync\ncd app || true\n./setup\n", "app/setup": executable + benign}), true, ""},
		{"a file run by its path after a cd that expands", tree(map[string]string{"install.sh": "inst sync\ncd \"$X\"\n./setup\n", "app/setup": executable + benign}), true, ""},
		{"a file run by its path after the directory is lost, held nowhere", tree(map[string]string{"install.sh": "inst sync\ncd app || true\n./other\n", "app/setup": executable + benign}), false, ""},
		{"a file run by its path after the directory is lost, with a #!", tree(map[string]string{"install.sh": "inst sync\ncd app || true\n./setup\n", "app/setup": executable + "#!/usr/bin/env python3\nprint(1)\n"}), false, ""},
		{"sudo -s runs eval of a word that expands", run("inst sync\nsudo -s eval \"$CMD --yes\"\n", benign), true, ""},
		{"sudo --chdir= into a directory whose file does not install", tree(map[string]string{"install.sh": "inst sync\nsudo --chdir=app sh setup\n", "app/setup": benign, "setup": installs}), false, ""},
		{"sudo --chdir into a directory whose file does not install", tree(map[string]string{"install.sh": "inst sync\nsudo --chdir app sh setup\n", "app/setup": benign, "setup": installs}), false, ""},
		{"cat into a shell after then that does not install", run("inst sync\nif true; then cat scripts/setup | sh; fi\n", benign), false, ""},
		{"a file run by its path through a symlinked directory", tree(map[string]string{"install.sh": "inst sync\n./scripts/setup\n", "real/setup": executable + benign, "scripts": linkTo + "real"}), true, ""},
		{"a file run by a glob", tree(map[string]string{"install.sh": "inst sync\n./scripts/set*\n", "scripts/setup": executable + benign}), true, ""},
		{"a file run by a glob no build file matches", tree(map[string]string{"install.sh": "inst sync\n./scripts/run*\n", "scripts/setup": executable + benign}), false, ""},
		// r4.
		{"sudo -s drops an empty word", run("sudo -s '' sh scripts/setup\n", installs), true, ""},
		{"sudo -i drops an empty word", run("sudo -i '' sh scripts/setup\n", installs), true, ""},
		{"a Dockerfile runs a file under ~ by its path", tree(map[string]string{"Dockerfile": "FROM base\nWORKDIR /root\nCOPY . .\nRUN ~/setup\n", "setup": executable + installs}), true, ""},
		{"a file under ~ run by its path in a line that does not tokenise", tree(map[string]string{"install.sh": "inst sync\n( ~/tools/setup )\n", "app/setup": executable + benign}), true, ""},
		{"a shell run after until", run("until sh scripts/setup; do break; done\n", installs), true, ""},
		{"a symlink run by its path after the directory is lost", tree(map[string]string{"install.sh": "inst sync\ncd app || true\n./setup\n", "app/setup": linkTo + "../tools/run", "tools/run": executable + benign}), true, ""},
		{"an upper-case name run by its path after the directory is lost", tree(map[string]string{"install.sh": "inst sync\ncd app || true\n./Setup\n", "app/Setup": executable + benign}), true, ""},
		{"CircleCI: sourced from several directories, a cd in a file it sources loses the caller's directory", tree(map[string]string{
			".circleci/config.yml": "version: 2.1\njobs:\n  b:\n    docker:\n      - image: x\n    working_directory: app\n    steps:\n      - run: inst sync\n      - run: . ./lib; sh ./y\n",
			"lib":                  ". ./x\n", "app/lib": ". ./x\n", "x": "cd sub\n", "app/x": "cd sub\n", "y": benign, "app/y": benign, "sub/y": installs, "app/sub/y": installs}), true, ""},
		{"CircleCI: sourced from several directories, a cd that expands in a file it sources", tree(map[string]string{
			".circleci/config.yml": "version: 2.1\njobs:\n  b:\n    docker:\n      - image: x\n    working_directory: app\n    steps:\n      - run: inst sync\n      - run: . ./lib; sh ./y\n",
			"lib":                  ". ./x\n", "app/lib": ". ./x\n", "x": "cd \"$D\"\n", "app/x": "cd \"$D\"\n", "y": benign, "app/y": benign, "sub/y": installs, "app/sub/y": installs}), true, ""},
		{"CircleCI: sourced from several directories, a file it sources that does not cd", tree(map[string]string{
			".circleci/config.yml": "version: 2.1\njobs:\n  b:\n    docker:\n      - image: x\n    working_directory: app\n    steps:\n      - run: inst sync\n      - run: . ./lib; sh ./y\n",
			"lib":                  ". ./x\n", "app/lib": ". ./x\n", "x": benign, "app/x": benign, "y": benign, "app/y": benign, "sub/y": installs, "app/sub/y": installs}), false, ""},
		{"a source in a one-line case arm", run("case x in a) . scripts/setup;; esac\n", benign), true, ""},
		{"a source in a case arm on its own line", run("inst sync\ncase x in\na) . scripts/setup ;;\nesac\n", benign), true, ""},
		{"coproc runs a shell", run("coproc sh scripts/setup\n", installs), true, ""},
		{"coproc sources a file", run("coproc . scripts/setup\n", installs), true, ""},
		{"a cd in a coprocess does not move the shell", tree(map[string]string{"install.sh": "inst sync\ncoproc cd app\nsh setup\n", "app/setup": installs, "setup": benign}), false, ""},
		{"a program that expands ahead of a shell run", run("inst sync\n$P sh scripts/setup\n", benign), true, ""},
		{"a program that expands ahead of a source", run("inst sync\n${P} . scripts/setup\n", benign), true, ""},
		{"a program that expands with a last . as a path", run("inst sync\n$DOCKER build -t x .\n", benign), false, ""},
		{"a #! shell script run by its path reads files from the caller's directory", tree(map[string]string{"install.sh": "inst sync\nscripts/build\n", "scripts/build": executable + "#!/bin/sh\nsh setup\n", "setup": installs, "scripts/setup": benign}), true, ""},
		{"a #! shell script run by its path that does not install", tree(map[string]string{"install.sh": "inst sync\nscripts/build\n", "scripts/build": executable + "#!/bin/sh\nsh setup\n", "setup": benign, "scripts/setup": benign}), false, ""},
		{"sudo -D into a directory that expands", tree(map[string]string{"install.sh": "inst sync\nsudo -D \"$X\" sh setup\n", "setup": benign, "$X/setup": benign}), true, ""},
		{"a #! shell script run by its path after the directory is lost", tree(map[string]string{"install.sh": "inst sync\ncd app || true\n./build\n", "app/build": executable + "#!/bin/sh\nsh setup\n", "app/setup": benign}), true, ""},
		{"a file run by its path in a subshell", tree(map[string]string{"install.sh": "inst sync\n( cd app && ./setup )\n", "app/setup": executable + benign}), true, ""},
		{"sourced from several directories, a cd in a file it sources loses the caller's directory", tree(map[string]string{
			".github/workflows/ci.yml": steps("- run: inst sync\n      - run: . ./lib; sh ./y\n        working-directory: app\n"),
			"lib":                      ". ./x\n", "app/lib": ". ./x\n", "x": "cd sub\n", "app/x": "cd sub\n", "y": benign, "app/y": benign, "sub/y": installs, "app/sub/y": installs}), true, ""},
		{"sourced from several directories, a file it sources that does not cd", tree(map[string]string{
			".github/workflows/ci.yml": steps("- run: inst sync\n      - run: . ./lib; sh ./y\n        working-directory: app\n"),
			"lib":                      ". ./x\n", "app/lib": ". ./x\n", "x": benign, "app/x": benign, "y": benign, "app/y": benign, "sub/y": installs, "app/sub/y": installs}), false, ""},
		// Hazard gates.
		{"shell runs a file through a symlinked directory", tree(map[string]string{"install.sh": "sh scripts/setup\ninst sync\n", "real/setup": benign, "scripts": linkTo + "real"}), true, ""},
		{"Dockerfile runs a COPY'd file through a symlinked directory", tree(map[string]string{"Dockerfile": docker + "COPY scripts/setup ./\nRUN inst sync\nRUN sh /app/setup\n", "real/setup": benign, "scripts": linkTo + "real"}), true, ""},
		{"shell runs a file after the directory is lost", tree(map[string]string{"install.sh": "inst sync\ncd app || true\nsh setup\n", "app/setup": benign, "setup": benign}), true, ""},
		{"cat of two files piped into a shell", run("inst sync\ncat scripts/setup scripts/setup | sh\n", benign), true, ""},
		{"a carrier behind a wrapper option this does not read", run("inst sync\nsudo -X cp /tmp/c/*.lock ./\n", benign), true, ""},
		{"sourced from several directories, a cd stays in its own shell", tree(map[string]string{
			".github/workflows/ci.yml": steps("- run: inst sync\n      - run: . ./lib\n        working-directory: app\n"),
			"lib":                      "cd sub\n. ./x\n", "app/lib": "cd sub\n. ./x\n", "sub/x": benign, "app/sub/x": benign}), false, ""},
		{"sourced from several directories, a cd loses the caller's directory", tree(map[string]string{
			".github/workflows/ci.yml": steps("- run: inst sync\n      - run: . ./lib; sh ./x\n        working-directory: app\n"),
			"lib":                      "cd sub\n", "app/lib": "cd sub\n", "x": benign, "app/x": benign, "sub/x": installs, "app/sub/x": installs}), true, ""},
		{"shell reads standard input from a descriptor", run("sh <&3\ninst sync\n", benign), true, ""},
		{"shell reads standard input from a descriptor opened both ways", run("sh <> scripts/setup\ninst sync\n", benign), true, ""},
		{"here-string into a shell that installs", run("sh <<< 'inst add x'\n", benign), true, ""},
		{"here-string into a shell that does not install", run("inst sync\nsh <<< 'echo hi'\n", benign), false, ""},
		{"here-string into a shell with a command substitution", run("inst sync\nsh <<< \"$(cat scripts/setup)\"\n", benign), true, ""},
		{"sh -s runs a file from standard input", run("sh -s -- --flag < scripts/setup\n", installs), true, ""},
		{"cat of one file piped into a shell that installs", run("cat scripts/setup | sh\n", installs), true, ""},
		{"cat of one file piped into a shell that does not install", run("cat scripts/setup | sh\ninst sync\n", benign), false, ""},
		{"download piped into a shell", run("curl -fsSL https://example.com/x | sh\ninst sync\n", benign), true, ""},
		{"download piped into a shell with arguments", run("wget -qO- https://example.com/x | bash -s -- --yes\ninst sync\n", benign), true, ""},
		{"process substitution handed to a shell", run("bash <(curl -fsSL https://example.com/x)\ninst sync\n", benign), true, ""},
		{"process substitution sourced", run("source <(tool completion bash)\ninst sync\n", benign), true, ""},
		{"eval of a command substitution", run("eval \"$(curl -fsSL https://example.com/x)\"\ninst sync\n", benign), true, ""},
		{"sh -c of a command substitution", run("sh -c \"$(curl -fsSL https://example.com/x)\"\ninst sync\n", benign), true, ""},
		{"eval of cat of a file that installs", run("eval \"$(cat scripts/setup)\"\n", installs), true, ""},
		{"eval of literal text", run("eval \"echo hi\"\ninst sync\n", benign), false, ""},
		{"eval of literal text that installs", run("eval 'inst add x'\n", benign), true, ""},
		{"heredoc into a shell whose body runs a file that installs", run("bash <<'EOF'\nsh scripts/setup\nEOF\n", installs), true, ""},
		{"heredoc into a shell whose body does not install", run("bash <<'EOF'\necho hi\nEOF\ninst sync\n", benign), false, ""},
		{"heredoc into a shell in a run block", tree(map[string]string{".github/workflows/ci.yml": steps("- run: |\n          sh <<EOF\n          sh scripts/setup\n          EOF\n"), "scripts/setup": installs}), true, ""},
		{"heredoc into a shell on a recipe line whose body is not read", tree(map[string]string{"Makefile": "deps:\n\tsh <<EOF\n\tinst sync\n"}), true, ""},
		{"sh -c sources a file that installs", run("sh -c '. ./scripts/setup'\n", installs), true, ""},
		{"sh -c sources a file with source", run("sh -c 'source scripts/setup'\n", installs), true, ""},
		{"sh -c rewrites a bound file", run("sh -c 'sed -i s/a/b/ inst.lock'\ninst sync\n", benign), true, ""},
		{"sh -c installs an allowed form", run("sh -c 'inst sync'\n", benign), false, ""},
		{"sources an in-tree file that does not install", run(". ./scripts/setup\ninst sync\n", "export A=1\n"), false, ""},
		{"sources an in-tree file that runs a file that installs", tree(map[string]string{"install.sh": ". ./scripts/setup\n", "scripts/setup": "sh ./scripts/deep\n", "scripts/deep": installs}), true, ""},
		{"sources an in-tree file that sets an installer variable", run(". ./scripts/setup\ninst sync\n", "INST_INDEX=https://x\n"), true, ""},
		{"shell runs a directory", tree(map[string]string{"install.sh": "sh scripts\ninst sync\n", "scripts/x": benign}), true, ""},
		{"shell runs a file that is not there", tree(map[string]string{"install.sh": "sh scripts/missing\ninst sync\n"}), true, ""},
		{"shell runs a file outside the build root", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "app/install.sh": "sh ../outside\ninst sync\n", "outside": benign}, true, "app"},
		{"shell runs a file named by a variable", run("sh \"$F\"\ninst sync\n", benign), true, ""},
		{"shell runs an absolute path", run("sh /scripts/setup\ninst sync\n", benign), true, ""},
		{"shell runs a sample hook", tree(map[string]string{"install.sh": "sh .git/hooks/pre-commit.sample\ninst sync\n", ".git/hooks/pre-commit.sample": benign}), true, ""},
		{"shell runs a file past the size cap", run("sh scripts/setup\ninst sync\n", strings.Repeat("# x\n", maxRunBytes/4+1)), true, ""},
		{"shell runs a file just under the size cap", run("sh scripts/setup\ninst sync\n", strings.Repeat("# x\n", maxRunBytes/4)), false, ""},
		{"files that run each other", tree(map[string]string{"install.sh": "sh ./a\ninst sync\n", "a": "sh ./b\n", "b": "sh ./a\n"}), true, ""},
		{"shell runs nested past the bound", chain(5), true, ""},
		{"shell runs nested within the bound", chain(2), false, ""},
		{"shell run behind a wrapper option this does not read", run("env -C sub sh scripts/setup\ninst sync\n", benign), true, ""},
		{"shell run from xargs", run("xargs -n1 sh < list\ninst sync\n", benign), true, ""},
		{"shell run from find -exec", run("find . -name '*.sh' -exec sh {} \\;\ninst sync\n", benign), true, ""},
		{"shell told to run a file first through BASH_ENV", run("BASH_ENV=./scripts/setup bash -c true\ninst sync\n", benign), true, ""},
		{"command -v names a shell and runs nothing", run("command -v bash\ninst sync\n", benign), false, ""},
		{"a cd in a sourced file moves the shell that sourced it", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "install.sh": ". ./go\ninst sync\n", "go": "cd app\n"}, false, ""},
		{"a cd in a file a shell runs does not move the shell that ran it", map[string]string{"app/inst.toml": "[deps]\n", "app/inst.lock": "lock\n", "install.sh": "sh ./go\ninst sync\n", "go": "cd app\n"}, true, ""},
		{"Dockerfile runs a COPY'd file that installs", tree(map[string]string{"Dockerfile": docker + "COPY setup ./\nRUN sh setup\n", "setup": installs}), true, ""},
		{"Dockerfile runs a file no COPY put there", tree(map[string]string{"Dockerfile": docker + "RUN inst sync && sh /opt/setup.sh\n"}), true, ""},
		{"Dockerfile installs, then runs a COPY'd file that does not", tree(map[string]string{"Dockerfile": docker + "COPY setup ./\nRUN inst sync\nRUN sh /app/setup\n", "setup": benign}), false, ""},
		{"Dockerfile runs a COPY'd file that does not install, then installs", tree(map[string]string{"Dockerfile": docker + "COPY setup ./\nRUN sh /app/setup\nRUN inst sync\n", "setup": benign}), true, ""},
		{"Dockerfile heredoc script runs a file that installs", tree(map[string]string{"Dockerfile": docker + "COPY setup ./\nRUN <<EOF\nsh /app/setup\nEOF\n", "setup": installs}), true, ""},
		{"Dockerfile heredoc into a shell sources a file that installs", tree(map[string]string{"Dockerfile": docker + "COPY setup ./\nRUN bash <<EOF\n. /app/setup\nEOF\n", "setup": installs}), true, ""},
		{"Dockerfile installs, then a heredoc writes a file", tree(map[string]string{"Dockerfile": docker + "RUN inst sync\nRUN cat <<EOF > /app/run.sh\nsource /etc/profile\nEOF\n"}), false, ""},

		// ferralon-ai/tracker#505: writes this cannot name.
		{"glob over a bound file's name", run("inst sync\nsed -i s/a/b/ *.lock\n", benign), true, ""},
		{"glob in a brace list", run("inst sync\nrm -f {a,b}/*.l?ck\n", benign), true, ""},
		{"glob under a directory", run("inst sync\ncp cache/*.lock .\n", benign), true, ""},
		{"glob outside the build carried in", run("inst sync\ncp /tmp/cache/*.lock .\n", benign), true, ""},
		{"glob outside the build carried in, in a line that does not tokenise", run("inst sync\n(mv /tmp/cache/*.lock .)\n", benign), true, ""},
		{"glob inside the build by its absolute path", run("inst sync\nrm -f @root@/*.lock\n", benign), true, ""},
		{"glob in a line that does not tokenise", run("inst sync\n(cp cache/inst.* .)\n", benign), true, ""},
		{"redirect glued to its command", run("inst sync\necho x>inst.lock\n", benign), true, ""},
		{"append glued to its command", run("inst sync\necho x>>inst.lock\n", benign), true, ""},
		{"descriptor redirect glued to its command", run("inst sync\necho x 1>inst.lock\n", benign), true, ""},
		{"find by name runs a writer", run("inst sync\nfind . -name '*.lock' -exec sed -i s/a/b/ {} +\n", benign), true, ""},
		{"find with no name runs a writer", run("inst sync\nfind . -type f -exec sed -i s/a/b/ {} +\n", benign), true, ""},
		{"find with no name deletes", run("inst sync\nfind . -type f -mtime +30 -delete\n", benign), true, ""},
		{"find from . that writes nothing", run("inst sync\nfind . -type f -name '*.go' -print\n", benign), false, ""},
		{"find by name runs a writer on files no bound file matches", run("inst sync\nfind . -name '*.go' -exec sed -i s/a/b/ {} +\n", benign), false, ""},
		{"su runs a command line that sources a file that installs", run("su app -c '. scripts/setup'\n", installs), true, ""},
		{"su runs a command line that sources a file that does not install", run("inst sync\nsu app -c '. scripts/setup'\n", benign), false, ""},
		{"su runs a command line naming a file", tree(map[string]string{"install.sh": "su -c scripts/setup\n", "scripts/setup": executable + installs}), true, ""},
		{"su from a login runs from its home", run("inst sync\nsu -l app -c 'sh scripts/setup'\n", benign), true, ""},
		{"su with no command reads standard input", run("inst sync\necho 'echo hi' | su app\n", benign), true, ""},
		{"su with a shell this does not read", run("inst sync\nsu -s /usr/bin/python3 app -c 'print(1)'\n", benign), true, ""},
		{"sg runs its command line", run("sg docker 'sh scripts/setup'\n", installs), true, ""},
		{"runner given a command line that runs a shell", run("inst sync\nrunuser -u app -- script -qc 'sh scripts/setup'\n", benign), true, ""},
		{"runner given . as a path", run("inst sync\nflock . echo done\n", benign), false, ""},
		{"xargs runs a writer", run("inst sync\nls | xargs sed -i s/a/b/\n", benign), true, ""},
		{"writer given a path that expands", run("inst sync\nsed -i s/a/b/ \"$F\"\n", benign), true, ""},
		{"redirect to a path that expands", run("inst sync\necho x > \"$OUT\"\n", benign), true, ""},
		{"redirect to a path that expands, in a line that does not tokenise", run("inst sync\n(echo x) > \"$OUT\"\n", benign), true, ""},
		{"writer given a path that expands, nothing bound", run("sed -i s/a/b/ \"$F\"\necho x > \"$OUT\"\n", benign), false, ""},
		{"writer given a path that expands in a sample hook, nothing reaching it", tree(map[string]string{"install.sh": "inst sync\n", ".git/hooks/commit-msg.sample": "#!/bin/sh\nperl -i.bak -pe 's/x/y/' \"$1\"\n"}), false, ""},

		// Commands that write nothing a bound file could be.
		{"glob over other names", run("inst sync\nsed -i s/a/b/ src/*.js\n", benign), false, ""},
		{"glob outside the build not carried in", run("inst sync\nrm -rf /tmp/cache/*\n", benign), false, ""},
		{"glob outside the build in a make variable", tree(map[string]string{"Makefile": "PATHS := / /assets/*\nall:\n\tinst sync\n"}), false, ""},
		{"quoted glob", run("inst sync\ngsutil cp x \"gs://b/og/**\"\n", benign), false, ""},
		{"test bracket", run("inst sync\n[ -f x ] && echo y\n", benign), false, ""},
		{"redirect to /dev/null", run("inst sync\necho x > /dev/null\n", benign), false, ""},
		{"descriptor duplicated into a pipe", run("inst sync\nmake 2>&1 | tee build.log\n", benign), false, ""},
		{"append to the runner's output file", run("inst sync\necho x=1 >> $GITHUB_OUTPUT\n", benign), false, ""},
		{"append to the runner's output file in a line that does not tokenise", run("inst sync\necho \"v=$(date)\" >> \"$GITHUB_OUTPUT\"\n", benign), false, ""},
		{"tee to the runner's environment file", run("inst sync\necho A=1 | tee -a \"$GITHUB_ENV\"\n", benign), false, ""},
		{"redirect to the runner's environment file", run("inst sync\necho A=1 >> \"$GITHUB_ENV\"\n", benign), false, ""},
		{"Dockerfile clears the image root", tree(map[string]string{"Dockerfile": docker + "RUN inst sync && rm -rf /*\n"}), true, ""},
		{"Dockerfile glob under a directory a COPY fills", tree(map[string]string{"Dockerfile": docker + "COPY . /src/\nRUN inst sync && rm -f /src/sub/*.lock\n"}), true, ""},
		{"Dockerfile clears an absolute directory no COPY reaches", tree(map[string]string{"Dockerfile": docker + "RUN inst sync && rm -rf /var/lib/apt/lists/*\n"}), false, ""},
		{"Dockerfile glob over a directory a COPY reaches", tree(map[string]string{"Dockerfile": docker + "RUN inst sync\n", "fix.sh": "rm -f /app/*.lock\n", "Dockerfile.fix": docker + "RUN rm -f /app/*.lock\n"}), true, ""},
	}
	for _, sh := range []string{"bash", "dash", "zsh", "ksh", "ash", "mksh", "/bin/sh", "/usr/bin/env bash"} {
		tests = append(tests, row{sh + " runs a file that installs", run(sh+" scripts/setup\n", installs), true, ""})
	}
	for _, w := range []string{"env A=1", "env -i", "command", "command -p", "exec", "exec -a x", "nohup", "sudo -E", "sudo -u root", "time", "timeout 5", "timeout -s KILL 5", "nice -n 5", "A=1"} {
		tests = append(tests, row{w + " wraps a shell that runs a file that installs", run(w+" sh scripts/setup\n", installs), true, ""})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, tt.files)
			root := filepath.Join(dir, tt.root)
			for rel, content := range tt.files {
				p := filepath.Join(dir, rel)
				switch {
				case strings.HasPrefix(content, linkTo):
					if err := os.Remove(p); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(strings.TrimPrefix(content, linkTo), p); err != nil {
						t.Fatal(err)
					}
				case strings.HasPrefix(content, executable):
					if err := os.WriteFile(p, []byte(strings.TrimPrefix(content, executable)), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(p, 0o755); err != nil {
						t.Fatal(err)
					}
				case strings.HasPrefix(content, unreadable):
					if err := os.Chmod(p, 0o111); err != nil {
						t.Fatal(err)
					}
				case strings.Contains(content, "@root@"):
					if err := os.WriteFile(p, []byte(strings.ReplaceAll(content, "@root@", root)), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if got := withheld(root, testSpec); got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
		})
	}
}

// A concurrent runner's command that sources a file reads it as a shell would.
func TestVeto_ConcurrentSources(t *testing.T) {
	spec := testSpec
	spec.Token = func(w string) bool { return w == "inst" || w == "instw" || w == "conc" }
	spec.Concurrent = func(words []string) ([]string, bool) {
		if words[0] != "conc" {
			return nil, false
		}
		return words[1:], true
	}
	for _, tt := range []struct {
		name, setup string
		want        bool
	}{
		{"sources a file that installs", "inst add x\n", true},
		{"sources a file that does not install", "export A=1\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n",
				"install.sh": "conc \". ./setup\" \"inst sync\"\n", "setup": tt.setup})
			if got := withheld(root, spec); got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
		})
	}
}

// A Dockerfile RUN handing a COPY'd file that installs nothing to a shell binds what it bound
// before the file was read: the files bound are the same with the RUN as without it.
func TestVeto_DockerShellRunKeepsBinds(t *testing.T) {
	const head = "FROM base\nWORKDIR /app\nCOPY inst.toml inst.lock setup ./\nRUN inst sync\n"
	bound := func(dockerfile string) map[string]bool {
		root := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "setup": "cp inst.toml /tmp/x\necho built\n", "Dockerfile": dockerfile})
		v := New(root, testRead(root), testSpec)
		none := func(string, []byte) (string, bool) { return "", false }
		buildtree.Candidates(root, v.Classify(none), v.FullyRead)
		return v.bound
	}
	without := bound(head + "RUN inst run build\n")
	with := bound(head + "RUN sh /app/setup\nRUN inst run build\n")
	if !maps.Equal(with, without) {
		t.Fatalf("bound with RUN sh = %v, without = %v", with, without)
	}
	if len(without) == 0 {
		t.Fatal("nothing bound")
	}
}

// The redirect operator ends the word before it, as the shell reads x>f, and a descriptor
// duplication stays one word.
func TestShellSegments_Redirects(t *testing.T) {
	for _, tt := range []struct {
		in    string
		words []string
		redir []bool
	}{
		{"echo x>f", []string{"echo", "x", ">f"}, []bool{false, false, true}},
		{"echo x 2>&1", []string{"echo", "x", "2>&1"}, []bool{false, false, true}},
		{"echo '>f' >>g", []string{"echo", ">f", ">>g"}, []bool{false, false, true}},
		{"find . -exec rm {} +", []string{"find", ".", "-exec", "rm", "{}", "+"}, []bool{false, false, false, false, false, false}},
	} {
		segs, ok, _ := shellSegments(tt.in)
		if !ok || len(segs) != 1 || !slices.Equal(segs[0].words, tt.words) || !slices.Equal(segs[0].redir, tt.redir) {
			t.Errorf("shellSegments(%q) = %+v, %v", tt.in, segs, ok)
		}
	}
}
