#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizedScope {
    SuperAdmin,
    OrganizationAdmin,
    User,
}
