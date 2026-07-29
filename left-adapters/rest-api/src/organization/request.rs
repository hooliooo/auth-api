use std::collections::HashMap;

use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct CreateOrganizationRequest {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub attributes: HashMap<String, Vec<String>>,
}
