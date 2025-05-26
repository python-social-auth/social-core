from uuid import uuid4

from social_core.utils import module_member, slugify

USER_FIELDS = ["username", "email"]


def get_username(strategy, details, backend, user=None, *args, **kwargs):
    if "username" not in backend.setting("USER_FIELDS", USER_FIELDS):
        return None
    storage = strategy.storage

    if not user:
        email_as_username = backend.setting("USERNAME_IS_FULL_EMAIL", False)
        uuid_length = backend.setting("UUID_LENGTH", 16)
        max_length = storage.user.username_max_length()
        do_slugify = backend.setting("SLUGIFY_USERNAMES", False)
        do_clean = backend.setting("CLEAN_USERNAMES", True)

        def identity_func(val):
            return val

        if do_clean:
            override_clean = backend.setting("CLEAN_USERNAME_FUNCTION")
            if override_clean:
                clean_func = module_member(override_clean)
            else:
                clean_func = storage.user.clean_username
        else:
            clean_func = identity_func

        if do_slugify:
            override_slug = backend.setting("SLUGIFY_FUNCTION")
            slug_func = module_member(override_slug) if override_slug else slugify
        else:
            slug_func = identity_func

        if email_as_username and details.get("email"):
            username = details["email"]
        elif details.get("username"):
            username = details["username"]
        else:
            username = uuid4().hex

        short_username = (
            username[: max_length - uuid_length] if max_length is not None else username
        )
        final_username = slug_func(clean_func(username[:max_length]))

        # Generate a unique username for current user using username
        # as base but adding a unique hash at the end. Original
        # username is cut to avoid any field max_length.
        # The final_username may be empty and will skip the loop.
        while not final_username or storage.user.user_exists(username=final_username):
            username = short_username + uuid4().hex[:uuid_length]
            final_username = slug_func(clean_func(username[:max_length]))
    else:
        final_username = storage.user.get_username(user)
    return {"username": final_username}


def create_user(strategy, details, backend, user=None, *args, **kwargs):
    if user:
        return {"is_new": False}

    fields = {
        name: kwargs.get(name, details.get(name))
        for name in backend.setting("USER_FIELDS", USER_FIELDS)
    }
    if not fields:
        return None

    # Allow overriding the email field if desired by application specification
    if backend.setting("FORCE_EMAIL_LOWERCASE", False):
        emailfield = fields.get("email")
        if emailfield:
            fields["email"] = emailfield.lower()

    return {"is_new": True, "user": strategy.create_user(**fields)}


def user_details(strategy, details, backend, user=None, *args, **kwargs) -> None:
    """Update user details using data from provider."""
    if not user:
        return

    changed = False  # flag to track changes

    # Default protected user fields (username, id, pk and email) can be ignored
    # by setting the SOCIAL_AUTH_NO_DEFAULT_PROTECTED_USER_FIELDS to True
    if strategy.setting("NO_DEFAULT_PROTECTED_USER_FIELDS", backend=backend) is True:
        protected = ()
    else:
        protected = (
            "username",
            "id",
            "pk",
            "email",
            "password",
            "is_active",
            "is_staff",
            "is_superuser",
        )

    protected = protected + tuple(
        strategy.setting("PROTECTED_USER_FIELDS", [], backend=backend)
    )

    # Update user model attributes with the new data sent by the current
    # provider. Update on some attributes is disabled by default, for
    # example username and id fields. It's also possible to disable update
    # on fields defined in SOCIAL_AUTH_PROTECTED_USER_FIELDS.
    field_mapping = strategy.setting("USER_FIELD_MAPPING", {}, backend=backend)
    for name, value in details.items():
        # Convert to existing user field if mapping exists
        name = field_mapping.get(name, name)
        if value is None or not hasattr(user, name) or name in protected:
            continue

        current_value = getattr(user, name, None)
        if current_value == value:
            continue

        immutable_fields = tuple(
            strategy.setting("IMMUTABLE_USER_FIELDS", [], backend=backend)
        )
        if name in immutable_fields and current_value:
            continue

        changed = True
        setattr(user, name, value)

    if changed:
        strategy.storage.user.changed(user)
