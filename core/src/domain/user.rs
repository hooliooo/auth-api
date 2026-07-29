use kern::building_blocks::error::error_detail::ErrorDetail;

pub const INVALID_USER_ID_ERROR: ErrorDetail = ErrorDetail::new_const(
    "error.user.invalid-id",
    "User inputted id is not a valid UUID",
);
