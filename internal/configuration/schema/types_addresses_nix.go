//go:build linux || freebsd || darwin || netbsd || solaris

package schema

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

// Listener creates and returns a net.Listener.
func (a *Address) Listener() (ln net.Listener, err error) {
	if a.url == nil {
		return nil, fmt.Errorf("address url is nil")
	}

	if a.descriptor && a.umask != -1 {
		ln, err := systemdListeners()

		if err != nil {
			return nil, fmt.Errorf("failed to retrieve systemd socket: %w", err)
		}

		if len(ln) != 1 {
			return nil, fmt.Errorf("unexpected number of systemd sockets: %d", len(ln))
		}

		return ln[0], nil
	}

	if a.socket && a.umask != -1 {
		umask := syscall.Umask(a.umask)

		ln, err = net.Listen(a.Network(), a.NetworkAddress())

		_ = syscall.Umask(umask)

		return ln, err
	}

	return net.Listen(a.Network(), a.NetworkAddress())
}

// systemdListeners returns a slice of net.Listener for systemd socket activation.
func systemdListeners() ([]net.Listener, error) {
	pid := os.Getpid()

	if _, err := os.Stat(fmt.Sprintf("/proc/%d/fd/0", pid)); err != nil {
		return nil, fmt.Errorf("not running under systemd")
	}

	fdNum, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || fdNum == 0 {
		return nil, fmt.Errorf("LISTEN_FDS not set or invalid")
	}

	listeners := make([]net.Listener, 0, fdNum)

	// File descriptors 0, 1, 2 are reserved.
	for fd := 3; fd < 3+fdNum; fd++ {
		file := os.NewFile(uintptr(fd), "")
		if file == nil {
			continue
		}
		defer file.Close()

		listener, err := net.FileListener(file)
		if err != nil {
			continue
		}

		listeners = append(listeners, listener)
	}

	if len(listeners) == 0 {
		return nil, fmt.Errorf("no valid listeners found")
	}

	return listeners, nil
}
