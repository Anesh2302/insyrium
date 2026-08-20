"""Request validation (marshmallow)."""

from marshmallow import Schema, fields, post_load, validate

PASSWORD_RULE = validate.Regexp(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$",
    error="Password must be 8+ characters with upper, lower and a number.",
)
EMAIL_RULE = validate.Email(error="Please enter a valid email address.")


class RegisterSchema(Schema):
    email = fields.Email(required=True, validate=EMAIL_RULE)
    password = fields.Str(required=True, validate=PASSWORD_RULE)
    name = fields.Str(required=True, validate=validate.Length(min=2, max=120))
    organization = fields.Str(load_default="", validate=validate.Length(max=160))
    phone_number = fields.Str(load_default="", validate=validate.Length(max=20))
    job_title = fields.Str(load_default="", validate=validate.Length(max=120))
    department = fields.Str(load_default="", validate=validate.Length(max=120))
    country = fields.Str(load_default="", validate=validate.Length(max=60))

    @post_load
    def clean(self, data, **kwargs):
        data["email"] = data["email"].strip().lower()
        data["name"] = data["name"].strip()
        data["organization"] = data.get("organization", "").strip()
        data["phone_number"] = data.get("phone_number", "").strip()
        data["job_title"] = data.get("job_title", "").strip()
        data["department"] = data.get("department", "").strip()
        data["country"] = data.get("country", "").strip()
        return data


class LoginSchema(Schema):
    email = fields.Email(required=True, validate=EMAIL_RULE)
    password = fields.Str(required=True, validate=validate.Length(min=1, max=200))

    @post_load
    def clean(self, data, **kwargs):
        data["email"] = data["email"].strip().lower()
        return data


class OtpVerifySchema(Schema):
    email = fields.Email(required=True, validate=EMAIL_RULE)
    code = fields.Str(
        required=True,
        validate=validate.Regexp(r"^\d{6}$", error="Code must be 6 digits."),
    )

    @post_load
    def clean(self, data, **kwargs):
        data["email"] = data["email"].strip().lower()
        return data


class StepUpSchema(Schema):
    password = fields.Str(required=True, validate=validate.Length(min=1, max=200))
    otp = fields.Str(
        load_default=None,
        validate=validate.Regexp(r"^\d{6}$", error="Code must be 6 digits."),
    )
    purpose = fields.Str(
        load_default="step_up", validate=validate.OneOf(["step_up"])
    )


class CreateAdminSchema(Schema):
    email = fields.Email(required=True, validate=EMAIL_RULE)
    name = fields.Str(required=True, validate=validate.Length(min=2, max=120))
    password = fields.Str(required=True, validate=PASSWORD_RULE)
    role = fields.Str(
        required=True,
        validate=validate.OneOf(
            ["admin_support", "admin_content", "admin_platform"],
            error="Only Support, Content and Platform admin roles can be created here.",
        ),
    )
    products = fields.List(
        fields.Str(
            validate=validate.OneOf(
                ["insyrium", "sape_tqm", "decisium", "mirads_builder"]
            )
        ),
        load_default=[],
    )
    organization = fields.Str(load_default="", validate=validate.Length(max=160))
    phone_number = fields.Str(load_default="", validate=validate.Length(max=20))
    job_title = fields.Str(load_default="", validate=validate.Length(max=120))
    department = fields.Str(load_default="", validate=validate.Length(max=120))
    country = fields.Str(load_default="", validate=validate.Length(max=60))

    @post_load
    def clean(self, data, **kwargs):
        data["email"] = data["email"].strip().lower()
        data["name"] = data["name"].strip()
        data["organization"] = data.get("organization", "").strip()
        data["phone_number"] = data.get("phone_number", "").strip()
        data["job_title"] = data.get("job_title", "").strip()
        data["department"] = data.get("department", "").strip()
        data["country"] = data.get("country", "").strip()
        return data


class EditAdminSchema(Schema):
    name = fields.Str(validate=validate.Length(min=2, max=120))
    role = fields.Str(
        validate=validate.OneOf(
            ["admin_support", "admin_content", "admin_platform"]
        )
    )
    status = fields.Str(validate=validate.OneOf(["active", "suspended"]))
    products = fields.List(
        fields.Str(
            validate=validate.OneOf(
                ["insyrium", "sape_tqm", "decisium", "mirads_builder"]
            )
        )
    )
    mfa_enabled = fields.Bool()
    organization = fields.Str(validate=validate.Length(max=160))
    phone_number = fields.Str(validate=validate.Length(max=20))
    job_title = fields.Str(validate=validate.Length(max=120))
    department = fields.Str(validate=validate.Length(max=120))
    country = fields.Str(validate=validate.Length(max=60))

    @post_load
    def clean(self, data, **kwargs):
        for key in ("organization", "phone_number", "job_title", "department", "country"):
            if data.get(key) is not None:
                data[key] = data[key].strip()
        if data.get("name") is not None:
            data["name"] = data["name"].strip()
        return data


class EditUserSchema(Schema):
    name = fields.Str(validate=validate.Length(min=2, max=120))
    organization = fields.Str(validate=validate.Length(max=160))
    status = fields.Str(validate=validate.OneOf(["active", "suspended"]))


class ContentSchema(Schema):
    type = fields.Str(
        required=True,
        validate=validate.OneOf(
            [
                "article",
                "framework",
                "template",
                "knowledge_center",
                "research",
                "video",
                "download",
            ]
        ),
    )
    title = fields.Str(required=True, validate=validate.Length(min=3, max=200))
    body = fields.Str(required=True, validate=validate.Length(min=10))
    product = fields.Str(
        load_default="insyrium",
        validate=validate.OneOf(
            ["insyrium", "sape_tqm", "decisium", "mirads_builder"]
        ),
    )
    file_url = fields.URL(allow_none=True, load_default=None)


class EnquirySchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=2, max=120))
    email = fields.Email(required=True, validate=EMAIL_RULE)
    subject = fields.Str(required=True, validate=validate.Length(min=3, max=200))
    message = fields.Str(required=True, validate=validate.Length(min=10))


class SettingsSchema(Schema):
    portal_name = fields.Str(validate=validate.Length(max=120))
    allow_registration = fields.Bool()
    maintenance_mode = fields.Bool()
    default_mfa_for_admins = fields.Bool()
    alert_email = fields.Email(allow_none=True)
