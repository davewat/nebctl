package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/davewat/nebctl/internal/keep"
	"github.com/davewat/nebctl/internal/service"
)

// After nebctl rewrites config.yml or replaces the nebula binaries it keeps
// the previous copy as <name>.prev. It never goes back by itself: these
// helpers only check that nebula came back up, say how to restore by hand if
// it did not, and run the restore when the operator asks (restore-config).

// settleDefault is how long nebula must stay up after a restart.
const settleDefault = 2 * time.Second

func (a *app) serviceState() string {
	if a.svcStatus != nil {
		return a.svcStatus()
	}
	return service.Status(a.goos)
}

func (a *app) restartService() error {
	if a.svcRestart != nil {
		return a.svcRestart()
	}
	return service.Restart(a.goos)
}

// verifyRunning checks that the service came up after a restart and stays up
// for a couple of seconds. If not it returns an error with nebula's last log
// lines and the exact commands that put the previous copies back by hand:
// cfg for config.yml.prev, bins for nebula.prev and nebula-cert.prev. It
// changes nothing.
func (a *app) verifyRunning(cfg, bins bool) error {
	settle := settleDefault
	if a.settle != nil {
		settle = *a.settle
	}
	running := func() bool { return strings.HasPrefix(a.serviceState(), "running") }
	up := false
	for i := 0; i < 5 && !up; i++ { // a starting service gets a few tries
		if up = running(); !up {
			time.Sleep(settle)
		}
	}
	if up {
		time.Sleep(settle)
		up = running()
	}
	if up {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "nebula did not stay running after the restart (it is %s).\n", a.serviceState())
	if lines, err := a.nebulaLog(8); err == nil && len(lines) > 0 {
		b.WriteString("Its last log lines:\n")
		for _, l := range lines {
			b.WriteString("  " + l + "\n")
		}
	}
	b.WriteString(a.restoreHelp(cfg, bins))
	return errors.New(strings.TrimRight(b.String(), "\n"))
}

// restoreHelp lists the commands that put the kept copies back, for the
// copies that exist.
func (a *app) restoreHelp(cfg, bins bool) string {
	var b strings.Builder
	restart := service.RestartCommand(a.goos)
	if cfg {
		if prev := keep.Prev(a.cfgFile()); exists(prev) {
			fmt.Fprintf(&b, "The previous config is kept as %s. To go back to it:\n", prev)
			fmt.Fprintf(&b, "  sudo nebctl restore-config\n")
			fmt.Fprintf(&b, "or by hand:\n  sudo cp -p %s %s && %s\n", prev, a.cfgFile(), restart)
			fmt.Fprintf(&b, "(%s still holds the newer answers: `sudo nebctl config` would write them again.)\n", a.stateFile())
		} else {
			b.WriteString("No previous config was kept: this was the first one written here.\n")
		}
	}
	if bins {
		n, c := keep.Prev(a.nebulaBin()), keep.Prev(a.certBin())
		if exists(n) && exists(c) {
			fmt.Fprintf(&b, "The previous nebula is kept as %s and %s. To go back to it:\n", n, c)
			fmt.Fprintf(&b, "  sudo mv -f %s %s && sudo mv -f %s %s && %s\n", n, a.nebulaBin(), c, a.certBin(), restart)
		}
	}
	return b.String()
}

// restoreConfig puts config.yml.prev back as config.yml, only when the
// operator runs `nebctl restore-config`. The kept copy must pass `nebula
// -test` first (a copy nebula rejects is never swapped in), and the config it
// replaces becomes the new .prev, so running it again undoes it. Then it
// restarts nebula and checks it stays up.
func (a *app) restoreConfig() error {
	if err := a.requireRoot(); err != nil {
		return err
	}
	prev := keep.Prev(a.cfgFile())
	if !exists(prev) {
		return fmt.Errorf("there is no previous config at %s: nebctl keeps one each time it rewrites config.yml", prev)
	}
	if err := a.testConfig(prev); err != nil {
		return fmt.Errorf("the previous config does not pass nebula -test, so it was not put back:\n%w", err)
	}
	unlock, err := a.lockState()
	if err != nil {
		return err
	}
	defer unlock()
	if err := keep.Swap(a.cfgFile()); err != nil {
		return err
	}
	a.releaseState()
	a.p.Printf("Put %s back as %s (nebula -test passed); the config it replaced is now %s.\n",
		prev, a.cfgFile(), prev)
	a.p.Printf("%s still holds the newer answers: `sudo nebctl config` would write them again.\n", a.stateFile())
	if !a.manageService() {
		a.p.Printf("Restart nebula to use it: %s\n", service.RestartCommand(a.goos))
		return nil
	}
	if err := a.restartService(); err != nil {
		return err
	}
	if err := a.verifyRunning(true, false); err != nil {
		return err
	}
	a.p.Println("Restarted nebula; it is running on the restored config.")
	return nil
}

// manageService is whether this run starts and stops the real service (not
// under -root or -no-service; tests that fake the service turn it on).
func (a *app) manageService() bool {
	return a.svcRestart != nil || (a.root == "" && !a.noService)
}

func (a *app) testConfig(path string) error {
	if out, err := exec.Command(a.nebulaBin(), "-test", "-config", path).CombinedOutput(); err != nil {
		return errors.New(strings.TrimSpace(string(out)))
	}
	return nil
}
