# Copyright (C) 2014 Andrey Antukh <niwi@niwi.be>
# Copyright (C) 2014 Jesús Espino <jespinog@gmail.com>
# Copyright (C) 2014 David Barragán <bameda@dbarragan.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from django.db import transaction as tx
from django.apps import apps

from taiga.base.utils.slug import slugify_uniquely
from taiga.auth.services import make_auth_response_data
from taiga.auth.signals import user_registered as user_registered_signal

from django.contrib.auth import get_user_model
from taiga.base import exceptions as exc
from django.db.models import Q

from . import connector

def get_user_by_username_or_email(username_or_email):
    user_model = get_user_model()
    qs = user_model.objects.filter(Q(username__iexact=username_or_email) |
                                   Q(email__iexact=username_or_email))

    if len(qs) > 1:
        qs = qs.filter(Q(username=username_or_email) |
                       Q(email=username_or_email))

    if len(qs) == 0:
        return None

    user = qs[0]
    return user

@tx.atomic
def ldap_register(username: str, email: str, full_name: str):
    """
    Register a new user from LDAP.

    This can raise `exc.IntegrityError` exceptions in
    case of conflict found.

    :returns: User
    """
    user_model = apps.get_model("users", "User")

    try:
        # LDAP user association exist?
        user = user_model.objects.get(username=username.replace('.', ''))
    except user_model.DoesNotExist:
        # Create a new user
        username_unique = slugify_uniquely(username, user_model, slugfield="username")
        user = user_model.objects.create(email=email,
                                         username=username_unique,
                                         full_name=full_name)
        user_registered_signal.send(sender=user.__class__, user=user)

    return user

def ldap_login_func(request):
    username = request.DATA.get('username', None)
    password = request.DATA.get('password', None)

    user = get_user_by_username_or_email(username)
    if user and user.check_password(password):
        print('Login!!')
    elif user and not user.check_password(password):
         raise exc.WrongArguments(_("Username or password does not matches user."))
    else:
        email, full_name = connector.login(username=username, password=password)
        user = ldap_register(username=username, email=email, full_name=full_name)
        
    data = make_auth_response_data(user)
    return data

