"""@@impersonate view handler."""

from plone import api
from plone.app.layout.viewlets.common import ViewletBase
from plone.base.interfaces.controlpanel import IUserGroupsSettingsSchema
from plone.protect import CheckAuthenticator
from plone.session import tktauth
from Products.Five.browser import BrowserView
from zope.component import getAdapter
from zope.globalrequest import getRequest

import binascii
import time


# While an admin is impersonating somebody, this cookie keeps a ticket for the admin,
# so "Return to admin" can sign them back in without the
# password. It is the ticket plone.session itself signed, so nobody can make
# one up.
RETURN_COOKIE = "__ac_impersonator"

# The saved ticket is not refreshed while the admin is somebody else, so the
# session plugin's own timeout would end it too early. It is good for this
# long instead, then the admin has to log in again.
RETURN_MAX_AGE = 12 * 60 * 60


def _session(context):
    return api.portal.get_tool("acl_users").session


def _cookie_options(session):
    options = {"path": session.path}
    if session.cookie_domain:
        options["domain"] = session.cookie_domain
    return options


def impersonator_id(request, context):
    """User id of the admin who started impersonating, or None.

    Only answers when the saved ticket is really signed by this site, is not
    too old, and its user may still manage the site.
    """
    raw = request.cookies.get(RETURN_COOKIE)
    if not raw:
        return None
    session = _session(context)
    try:
        ticket = binascii.a2b_base64(raw)
        timestamp = tktauth.splitTicket(ticket)[4]
    except (binascii.Error, ValueError, TypeError):
        return None
    if time.time() - timestamp > RETURN_MAX_AGE:
        return None
    # now=timestamp: check the signature only, the age was checked above.
    data = session._validateTicket(ticket, now=timestamp)
    if data is None:
        return None
    userid = data[1]
    user = api.user.get(userid=userid)
    if user is None:
        return None
    if not api.user.has_permission(
        "Manage portal", user=user, obj=api.portal.get()
    ):
        return None
    return userid


def forget_impersonator(request, context):
    request.response.expireCookie(RETURN_COOKIE, **_cookie_options(_session(context)))


def forget_impersonator_on_logout(event):
    """Logging out ends everything: no way back to the admin afterwards."""
    request = getRequest()
    if request is None or not request.cookies.get(RETURN_COOKIE):
        return
    forget_impersonator(request, api.portal.get())


class Impersonate(BrowserView):
    """@@impersonate view."""

    def __call__(self):
        self.actions()
        return super().__call__()

    def actions(self):
        """Login the user"""
        request = self.request
        if request.get("REQUEST_METHOD") != "POST":
            return
        self.errors = {}
        username = (request.form.get("username") or "").strip()
        if not username:
            self.errors["missing"] = True
            return
        if not api.user.get(username=username):
            self.errors["username"] = username
            return
        CheckAuthenticator(request)

        session = _session(self.context)
        self.remember_impersonator(session)
        session._setupSession(username, request.response)
        request.response.redirect(self.context.absolute_url())

    def remember_impersonator(self, session):
        """Keep the admin's own ticket so they can come back."""
        request = self.request
        if impersonator_id(request, self.context):
            # Already impersonating (as another admin): keep the first one.
            return
        admin_id = api.user.get_current().getId()
        # A fresh ticket, signed the way the session plugin signs its own, so
        # the 12 hours count from now and not from the admin's last login.
        ticket = tktauth.createTicket(
            secret=session._getSigningSecret(admin_id),
            userid=admin_id,
            mod_auth_tkt=session.mod_auth_tkt,
        )
        request.response.setCookie(
            RETURN_COOKIE,
            binascii.b2a_base64(ticket).rstrip().decode("ascii"),
            secure=request.get("SERVER_URL", "").startswith("https"),
            http_only=True,
            same_site="Lax",
            **_cookie_options(session),
        )

    def users(self):
        """List all users on this site."""
        results = []
        for user in api.user.get_users():
            results.append(
                {"username": user.id, "fullname": user.getProperty("fullname")}
            )
        results.sort(key=lambda u: u["username"].lower())
        return results

    @property
    def many_users(self):
        return getAdapter(
            api.portal.get(),
            IUserGroupsSettingsSchema,
        ).many_users


class ImpersonateReturn(BrowserView):
    """@@impersonate-return: back to the admin who started impersonating.

    Public on purpose: the person clicking is logged in as somebody without
    admin rights (or not at all, if that session ran out). The signed ticket
    in the cookie is the guard.
    """

    def __call__(self):
        request = self.request
        url = self.context.absolute_url()
        userid = impersonator_id(request, self.context)
        forget_impersonator(request, self.context)
        if userid:
            _session(self.context)._setupSession(userid, request.response)
            url += "/@@impersonate"
        request.response.redirect(url)


class ImpersonatingViewlet(ViewletBase):
    """A bar on every page while impersonating, with the way back."""

    def update(self):
        super().update()
        self.admin_id = impersonator_id(self.request, self.context)
        self.show = False
        if not self.admin_id or api.user.is_anonymous():
            return
        current = api.user.get_current()
        if current.getId() == self.admin_id:
            return
        self.show = True
        self.current_name = current.getProperty("fullname") or current.getId()
        admin = api.user.get(userid=self.admin_id)
        self.admin_name = admin.getProperty("fullname") or self.admin_id
        self.return_url = self.navigation_root_url + "/@@impersonate-return"
