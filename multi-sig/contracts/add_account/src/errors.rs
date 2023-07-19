use casper_types::ApiError;

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum UserError {
    InvalidAccount,
}

impl From<UserError> for ApiError {
    fn from(error: UserError) -> Self {
        ApiError::User(error as u16)
    }
}
