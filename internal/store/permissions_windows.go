//go:build windows

package store

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

// Restrict the CLI's own state directory to the current user and SYSTEM. The
// inheritable protected DACL also covers manifests and temporary state files.
func securePlatformDir(path string) error {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errors.New("cannot resolve Windows user for private state directory")
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + tokenUser.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return errors.New("cannot construct private Windows state permissions")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return errors.New("cannot inspect private Windows state permissions")
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return errors.New("cannot restrict Windows state directory ACL")
	}
	return nil
}

func platformLock(f *os.File) (func(), error) {
	overlap := new(windows.Overlapped)
	handle := windows.Handle(f.Fd())
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlap); err != nil {
		return nil, err
	}
	return func() { _ = windows.UnlockFileEx(handle, 0, 1, 0, overlap) }, nil
}
