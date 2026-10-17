package main

import (
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"syscall"
)

// account is the user the gateway runs as once its sockets are bound.
type account struct {
	name     string
	uid, gid int
}

func lookupAccount(name string) (account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return account{}, fmt.Errorf("unknown user %q", name)
		}
		return account{}, fmt.Errorf("cannot look up user %q: %w", name, err)
	}
	uid, uidErr := strconv.Atoi(u.Uid)
	gid, gidErr := strconv.Atoi(u.Gid)
	if uidErr != nil || gidErr != nil {
		return account{}, fmt.Errorf("user %q has no numeric uid/gid (%s/%s)", name, u.Uid, u.Gid)
	}
	return account{name: name, uid: uid, gid: gid}, nil
}

// drop becomes the account: supplementary groups first, then the group, then the user, which takes away the
// right to do the other two.
func (a account) drop() error {
	if err := syscall.Setgroups([]int{a.gid}); err != nil {
		return fmt.Errorf("cannot switch to user %q: setgroups: %w", a.name, err)
	}
	if err := syscall.Setgid(a.gid); err != nil {
		return fmt.Errorf("cannot switch to user %q: setgid: %w", a.name, err)
	}
	if err := syscall.Setuid(a.uid); err != nil {
		return fmt.Errorf("cannot switch to user %q: setuid: %w", a.name, err)
	}
	return nil
}
