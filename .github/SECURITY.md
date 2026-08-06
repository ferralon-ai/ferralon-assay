# Security policy

## Reporting a vulnerability in our code

Please **do not open a public issue.** Use GitHub's private vulnerability
reporting on the affected repository:

> **Security** → **Report a vulnerability**

That opens a private channel visible only to us and to you. We will acknowledge
your report, keep you updated as we investigate, and agree a disclosure timeline
with you before anything becomes public. If you would like credit in the
advisory, say so and we will include you.

If private reporting is not available on the repository for some reason, open a
public issue containing **no details** — just "I have a security report, please
open a private channel" — and we will come to you.

## A note specific to this project

Our tools analyse your code and report on vulnerabilities in it. That means the
output can contain sensitive findings about *your* systems.

**Please do not paste unredacted tool output, scan results, or findings about
your own or a third party's software into a public issue.** Before you attach
logs to a bug report, remove:

- tokens, keys, and credentials of any kind
- internal hostnames, repository names, and file paths you would not publish
- specific findings about software you have not yet fixed or disclosed

If you cannot describe the bug without including that material, use the private
vulnerability reporting channel above instead. It works for this too — tell us
it is a support case and we will pick it up there.

## Scope

This policy covers the code in this organisation's repositories. It does not
cover vulnerabilities in third-party software that our tools happen to report
on; those belong with the affected project's own security process, and we are
happy to help you find the right contact.
