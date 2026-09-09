//go:build linux || darwin || freebsd

package main

import "syscall"

func osRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	var b []byte
	for _, c := range u.Release[:] {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
