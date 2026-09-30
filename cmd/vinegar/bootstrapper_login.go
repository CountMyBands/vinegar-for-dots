package main

import (
	"errors"
	"strings"

	"codeberg.org/puregotk/puregotk/v4/adw"
	"codeberg.org/puregotk/puregotk/v4/gio"
	"codeberg.org/puregotk/puregotk/v4/gtk"
	. "github.com/pojntfx/go-gettext/pkg/i18n"
	"github.com/vinegarhq/vinegar/internal/gutil"
)

const authScheme = "roblox-studio-auth:"

// promptLogin shows a dialog alongside Studio's browser login, where the
// roblox-studio-auth URI can optionally be pasted in, instead of relying
// on the browser to open it with Vinegar. Must be called from the main thread.
//
// It is shown when Studio is launched without an authenticated user, when
// Studio falls back to browser login, and when Studio opens its sign in
// page in the browser.
func (b *bootstrapper) promptLogin() {
	if b.login != nil {
		return
	}

	entry := gtk.NewEntry()
	entry.SetPlaceholderText(authScheme + "…")
	entry.SetActivatesDefault(true)

	d := adw.NewAlertDialog(L("Sign In with Browser"),
		L("After signing in with your browser, you may optionally paste the "+
			"roblox-studio-auth link given by the browser below, so that the "+
			"browser does not have to open Vinegar."))
	d.SetExtraChild(&entry.Widget)
	d.AddResponses("close", L("Close"), "login", L("Log In"))
	d.SetCloseResponse("close")
	d.SetDefaultResponse("login")
	d.SetResponseAppearance("login", adw.ResponseSuggestedValue)
	b.login = d

	b.Hold()
	var ccb gio.AsyncReadyCallback = func(_ uintptr, resPtr uintptr, _ uintptr) {
		defer b.Release()
		b.login = nil

		res := gio.SimpleAsyncResultNewFromInternalPtr(resPtr)
		uri := strings.TrimSpace(entry.GetText())
		if d.ChooseFinish(res) != "login" || uri == "" {
			return
		}
		if !isAuthURI(uri) {
			b.showError(errors.New(L("The given link is not a roblox-studio-auth link.")))
			return
		}

		b.errThread(func() error {
			return b.execute(uri)
		})
	}

	d.Choose(nil, nil, &ccb, 0)
}

// dismissLogin closes the login prompt, if present, as the
// authentication URI has been received from elsewhere.
func (b *bootstrapper) dismissLogin() {
	gutil.IdleAdd(func() {
		if b.login != nil {
			b.login.ForceClose()
		}
	})
}
