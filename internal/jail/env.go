package jail

import "strings"

// JailHomeFallback is the HOME handed to the jailed workload when the
// inherited $HOME does not exist inside the jail rootfs.
const JailHomeFallback = "/tmp"

// jailHomeEnv returns env with HOME guaranteed to point at a directory that
// exists inside the jail.
//
// Why this exists: UML's make_umid() (arch/um/os-Linux/umid.c) creates
// $HOME/.uml during early boot to hold the pid/umid files and — an upstream
// bug — never checks make_uml_dir()'s failure. Under sudo HOME=/root, but
// the minimal jail rootfs has no /root, so the mkdir fails, uml_dir becomes
// NULL and the next strscpy(tmp, uml_dir) dereferences it:
//
//	Failed to mkdir '/root/.uml/': No such file or directory
//	Kernel panic - not syncing: Segfault with no mm   (in make_umid)
//
// (CI run 88449954750; the arm64 port survives the NULL but logs the same
// mkdir failure.) SetupJail always creates <root>/tmp and the kernel's
// physmem file already lives there, so /tmp is known writable and
// Landlock-allowed.
//
// The matching entry is REPLACED in place rather than appended: with
// duplicate keys getenv returns the FIRST occurrence, so an appended
// HOME=/tmp would be shadowed by the inherited HOME=/root.
//
// Note on writability: we check existence only, not whether HOME/.uml can
// be created. That is sufficient by construction — post-pivot the only
// directories that can serve as HOME are /tmp (the jail tmpfs, provably
// writable: the kernel's physmem file and the mconsole socket already live
// there) and the read-only system binds (/lib, /usr/lib, ...), which no
// sane caller sets as HOME. Inherited values (/root, /home/runner) never
// exist inside the jail and always take the fallback.
func jailHomeEnv(env []string, dirExists func(string) bool) []string {
	for i, e := range env {
		if strings.HasPrefix(e, "HOME=") {
			home := strings.TrimPrefix(e, "HOME=")
			if home != "" && dirExists(home) {
				return env
			}
			env[i] = "HOME=" + JailHomeFallback
			return env
		}
	}
	// No HOME at all: make_umid prints "no value in environment for $HOME"
	// and hits the same NULL dereference, so always set one.
	return append(env, "HOME="+JailHomeFallback)
}
