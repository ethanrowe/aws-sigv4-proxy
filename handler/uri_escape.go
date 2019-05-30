package handler

import (
  "bytes"
  "fmt"
)

// ### Taken from AWS golang SDK and tweaked;
// ### was in github.com/aws/aws-sdk-go/private/protocol/rest/build.go

// Whether the byte value can be sent without escaping in AWS URLs
var noEscape [256]bool
var noEscapeWithSeparators [256]bool

func init() {
  for i := 0; i < len(noEscape); i++ {
    // AWS expects every character except these to be escaped
    noEscape[i] = (i >= 'A' && i <= 'Z') ||
      (i >= 'a' && i <= 'z') ||
      (i >= '0' && i <= '9') ||
      i == '-' ||
      i == '.' ||
      i == '_' ||
      i == '~'
  }
  // noEscapeWithSeparators is similar but doesn't escape the '/'
  // character either
  noEscapeWithSeparators = noEscape
  noEscapeWithSeparators['/'] = true
}

// escape escapes part of a URL path in Amazon style
// Based on EscapePath from private.protocol.rest,
// but adjusted to work against different arrays.
func escape(path string, flags []bool) string {
  var buf bytes.Buffer
  for i := 0; i < len(path); i++ {
    c := path[i]
    if flags[c] {
      buf.WriteByte(c)
    } else {
      fmt.Fprintf(&buf, "%%%02X", c)
    }
  }
  return buf.String()
}

// Amazon-style URL path escape, that includes the separators
// in the escaping.
func EscapePath(path string) string {
  if path[0] == '/' {
    return "/" + escape(path[1:], noEscape[:])
  }
  return escape(path, noEscape[:])
}

// Amazon-style URL path that preserves separators as unescaped.
// It escapes the segments without escaping the separators.
func EscapePathSegments(path string) string {
  return escape(path, noEscapeWithSeparators[:])
}

