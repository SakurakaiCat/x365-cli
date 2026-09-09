//go:build !linux && !darwin && !freebsd

package main

import "runtime"

func osRelease() string { return runtime.GOOS }
