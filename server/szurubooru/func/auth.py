import hashlib
import secrets
import string
import uuid
from collections import OrderedDict
from datetime import datetime
from typing import Optional, Tuple

from nacl import pwhash
from nacl.exceptions import InvalidkeyError

from szurubooru import config, db, errors, model
from szurubooru.func import util

random = secrets.SystemRandom()

RANK_MAP = OrderedDict(
    [
        (model.User.RANK_ANONYMOUS, "anonymous"),
        (model.User.RANK_RESTRICTED, "restricted"),
        (model.User.RANK_REGULAR, "regular"),
        (model.User.RANK_POWER, "power"),
        (model.User.RANK_MODERATOR, "moderator"),
        (model.User.RANK_ADMINISTRATOR, "administrator"),
        (model.User.RANK_NOBODY, "nobody"),
    ]
)


def get_password_hash(password: str) -> Tuple[str, int]:
    """Retrieve argon2id password hash."""
    return (
        pwhash.argon2id.str(
            (config.config["secret"] + password).encode("utf8")
        ).decode("utf8"),
        4,
    )


def create_password() -> str:
    alphabet = string.ascii_letters+string.digits
    return "".join([random.choice(alphabet) for _ in range(16)])


def is_valid_password(user: model.User, password: str) -> bool:
    assert user
    pw = config.config["secret"] + password

    if user.password_revision == 3:
        pw = password

    try:
        ok = pwhash.verify(user.password_hash.encode("utf8"), pw.encode("utf8"))
        if ok and user.password_revision != 4:
            new_hash, revision = get_password_hash(password)
            user.password_hash = new_hash
            user.password_revision = revision
            db.session.commit()
        return ok
    except InvalidkeyError:
        return False


def is_valid_token(user_token: Optional[model.UserToken]) -> bool:
    """
    Token must be enabled and if it has an expiration, it must be
    greater than now.
    """
    if user_token is None:
        return False
    if not user_token.enabled:
        return False
    if (
        user_token.expiration_time is not None
        and user_token.expiration_time < datetime.utcnow()
    ):
        return False
    return True


def has_privilege(user: model.User, privilege_name: str) -> bool:
    assert user
    all_ranks = list(RANK_MAP.keys())
    assert privilege_name in config.config["privileges"]
    assert user.rank in all_ranks
    minimal_rank = util.flip(RANK_MAP)[
        config.config["privileges"][privilege_name]
    ]
    good_ranks = all_ranks[all_ranks.index(minimal_rank) :]
    return user.rank in good_ranks


def verify_privilege(user: model.User, privilege_name: str) -> None:
    assert user
    if not has_privilege(user, privilege_name):
        raise errors.AuthError("Insufficient privileges to do this.")


def generate_authentication_token(user: model.User) -> str:
    """Generate nonguessable challenge (e.g. links in password reminder)."""
    assert user
    digest = hashlib.sha256()
    digest.update(config.config["secret"].encode("utf8"))
    digest.update(user.password_hash.encode("utf8"))
    return digest.hexdigest()


def generate_authorization_token() -> str:
    return uuid.uuid4().__str__()
