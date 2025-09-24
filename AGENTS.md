# AGENTS.md

- The default shell is `bash`.
- The following nonstandard command line tools are installed: `bat`, `rg`, `golangci-lint`, `httpie`.
- When adding functionality, always add tests as well.
- Use `GOCACHE=$(pwd)/.gocache` to avoid the sandbox limiting access to coverage analysis.

## Go error variables

Do not use `fmt.Errorf()`. Instead declare exported variables. Where appropriate,
use private error types implementing `errors.Is` and `errors.Unwrap`.

## Go variable declarations

Explicitly declare variables, both return variables and within the body, unless
all of them are contained within the same scope and none escape it.

```go
func JSONStringToInt(s string) (n int, err error) {
  var float64 f
	if f, err = strconv.ParseFloat(s, 64); err == nil {
    n = int(f)
	}
  return
}
```

## Go error handling execution flow

Avoid using early return statements. Instead, nest `if`-statements.
Construct the code so that an error-free execution ends up at the
innermost `if` statement with as few `else` statements as possible.

```go
var ErrIntegerIsNegative = errors.New("integer is negative")

func JSONStringToPositiveInt(s string) (n int, err error) {
  var float64 f
	if f, err = strconv.ParseFloat(s, 64); err == nil {
    err = ErrIntegerIsNegative
    if f >= 0 {
      err = nil
      n = int(f)
    }
	}
  return
}
```
