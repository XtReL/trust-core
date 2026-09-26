// Separate module so the core stays dependency-free. It checks Trust Core
// against the Go project's reference implementations of signed notes and
// RFC 6962 trees (golang.org/x/mod/sumdb), which witnesses and Tessera
// interoperate with. Run: cd interop && go mod tidy && go test ./...
module github.com/XtReL/trust-core/interop

go 1.22

require (
	github.com/XtReL/trust-core v0.0.0
	golang.org/x/mod v0.22.0
)

replace github.com/XtReL/trust-core => ../
