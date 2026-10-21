//go:build windows

// goblock : neutralise silencieusement une ou plusieurs adresses IP (http(s)://…)
// en posant des règles de pare-feu Windows ciblées sur remoteip.
//
// Double-clic = coupé. Double-clic à nouveau = rétabli.
// Compilation : CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui" -o goblock.exe ./goblock

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const createNoWindow = 0x08000000

// Tout process enfant est créé sans fenêtre => zéro flash noir.
var silent = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}

// Adresses à rendre inopérantes. Modifie cette liste selon ton besoin.
var targets = []string{
	"192.168.1.1",
	"192.168.1.2",
}

// Préfixe des règles de pare-feu, pour les repérer et les supprimer facilement.
const prefix = "GOBLOCK_"

// S-1-5-32-544 = BUILTIN\Administrators
var adminsSid = syscall.SID{
	Revision:            2,
	SubAuthorityCount:   2,
	IdentifierAuthority: syscall.SIDIdentifierAuthority{Value: [6]byte{0, 0, 0, 0, 0, 5}},
	SubAuthority:        [syscall.SID_MAX_SUB_AUTHORITIES]uint32{32, 544},
}

// Lance un process enfant caché, sans récupérer de sortie.
func launch(name string, args ...string) {
	c := exec.Command(name, args...)
	c.SysProcAttr = silent
	_ = c.Run()
}

// Lance un process enfant caché et récupère sa sortie standard.
func capture(name string, args ...string) string {
	c := exec.Command(name, args...)
	c.SysProcAttr = silent
	out, err := c.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// Vrai uniquement si le jeton est réellement élevé (pas juste "membre du groupe").
func isAdmin() bool {
	t, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer t.Close()
	ok, err := t.IsMember(&adminsSid)
	return err == nil && ok
}

// Relance une copie élevée de soi-même (popup UAC), sans fenêtre parasite.
func elevate() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	launch("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", `Start-Process -FilePath "`+exe+`" -Verb RunAs`)
}

func ruleName(ip string) string { return prefix + ip }

func ruleExists(ip string) bool {
	out := capture("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName(ip))
	return strings.Contains(out, ruleName(ip))
}

func addRule(ip string) {
	launch("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName(ip),
		"dir=out",      // sortant uniquement : DHCP et réponses entrantes intacts
		"action=block", // drop silencieux
		"remoteip="+ip, // cible l'adresse de DESTINATION du paquet
		"enable=yes",
		"profile=any", // domain / private / public
	)
}

func delRule(ip string) {
	launch("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName(ip))
}

func main() {
	// Les modifications de pare-feu exigent l'élévation.
	if !isAdmin() {
		elevate()
		return
	}

	// Toggle : si les règles sont déjà toutes présentes -> on rétablit, sinon -> on coupe.
	blocked := 0
	for _, ip := range targets {
		if ruleExists(ip) {
			blocked++
		}
	}

	if blocked == len(targets) {
		for _, ip := range targets {
			delRule(ip)
		}
		return
	}

	for _, ip := range targets {
		delRule(ip) // idempotence
		addRule(ip)
	}
}
