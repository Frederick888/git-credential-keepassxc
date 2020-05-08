use super::primitives::*;
use crate::utils::*;
use anyhow::{anyhow, Result};
use crypto_box::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use slog::{info, warn};

pub trait PlainTextRequest<R>
where
    R: PlainTextResponse + DeserializeOwned,
    Self: Serialize,
{
    fn send(&self) -> Result<R> {
        info!(
            crate::LOGGER.get().unwrap(),
            "Sending {} request",
            self.get_action().to_string()
        );
        let request_json = serde_json::to_string(self)?;
        let response_json = exchange_message(request_json)?;
        let response: R = serde_json::from_str(&response_json)?;
        Ok(response)
    }

    fn get_action(&self) -> KeePassAction;
}
pub trait PlainTextResponse {}
pub trait CipherTextRequest<R>
where
    R: CipherTextResponse + DeserializeOwned,
    Self: Serialize,
{
    fn send<T: Into<String>>(&self, client_id: T) -> Result<R> {
        info!(
            crate::LOGGER.get().unwrap(),
            "Sending {} request",
            self.get_action().to_string()
        );
        let (nonce, nonce_b64) = generate_nonce();
        let encrypted_request_json = to_encrypted_json(&self, &nonce)?;
        let request_wrapper = GenericRequestWrapper {
            action: self.get_action(),
            message: encrypted_request_json,
            nonce: nonce_b64,
            client_id: client_id.into(),
        };
        let response_wrapper_json = exchange_message(serde_json::to_string(&request_wrapper)?)?;
        let response_wrapper: GenericResponseWrapper =
            serde_json::from_str(&response_wrapper_json)?;
        response_wrapper.log();
        if response_wrapper.message.is_some() && response_wrapper.nonce.is_some() {
            let (message, nonce) = (
                response_wrapper.message.unwrap(),
                response_wrapper.nonce.unwrap(),
            );
            let decrypted_response_json = to_decrypted_json(message, nonce)?;
            let response: R = serde_json::from_str(&decrypted_response_json)?;
            Ok(response)
        } else {
            Err(anyhow!("Request {} failed", self.get_action().to_string()))
        }
    }

    fn get_action(&self) -> KeePassAction;
}
pub trait CipherTextResponse {}

macro_rules! impl_cipher_text {
    ([$(($request:ident, $response:ident),)*]) => {
        $(
            impl CipherTextRequest<$response> for $request {
                fn get_action(&self) -> KeePassAction {
                    self.action.clone()
                }
            }

            impl CipherTextResponse for $response {}
        )*
    };
}
impl_cipher_text!([
    // (GetDatabaseHashRequest, GetDatabaseHashResponse),
    (AssociateRequest, AssociateResponse),
    (TestAssociateRequest, TestAssociateResponse),
    (GetLoginsRequest, GetLoginsResponse),
    (SetLoginRequest, SetLoginResponse),
    // (GetDatabaseGroupsRequest, GetDatabaseGroupsResponse),
    (CreateNewGroupRequest, CreateNewGroupResponse),
]);

#[derive(Serialize, Deserialize, Debug)]
pub struct GenericRequestWrapper {
    pub action: KeePassAction,
    pub message: String,
    pub nonce: String,
    #[serde(rename = "clientID")]
    pub client_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GenericResponseWrapper {
    pub action: KeePassAction,
    pub message: Option<String>,
    pub nonce: Option<String>,
    pub error: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
}

impl GenericResponseWrapper {
    fn log(&self) {
        if self.message.is_none() {
            warn!(
                crate::LOGGER.get().unwrap(),
                "Request {} failed. Error: {}, Error Code: {}",
                self.action.to_string(),
                self.error.clone().unwrap_or_else(|| "N/A".to_owned()),
                self.error_code.clone().unwrap_or_else(|| "N/A".to_owned())
            );
        }
    }
}

/*
 * change-public-keys
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#change-public-keys
 */

#[derive(Serialize, Debug)]
pub struct ChangePublicKeysRequest {
    pub action: KeePassAction,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub nonce: String,
    #[serde(rename = "clientID")]
    pub client_id: String,
}

impl ChangePublicKeysRequest {
    pub fn new<T: Into<String>>(client_id: T, public_key: &PublicKey) -> Self {
        let (_, nonce) = generate_nonce();
        let public_key = base64::encode(public_key.as_bytes());
        Self {
            action: KeePassAction::ChangePublicKeys,
            public_key,
            nonce,
            client_id: client_id.into(),
        }
    }
}

impl PlainTextRequest<ChangePublicKeysResponse> for ChangePublicKeysRequest {
    fn get_action(&self) -> KeePassAction {
        self.action.clone()
    }
}

#[derive(Deserialize, Debug)]
pub struct ChangePublicKeysResponse {
    pub action: Option<KeePassAction>,
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
    /* generic fields */
    pub version: Option<String>,
    pub success: Option<KeePassBoolean>,
}

impl ChangePublicKeysResponse {
    pub fn get_public_key(&self) -> Option<PublicKey> {
        self.public_key.as_ref().and_then(|k| to_public_key(k).ok())
    }
}

impl PlainTextResponse for ChangePublicKeysResponse {}

/*
 * get-databasehash
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#get-databasehash
 */

// #[derive(Serialize, Deserialize, Debug)]
// pub struct GetDatabaseHashRequest {
//     pub action: KeePassAction,
// }
// 
// impl GetDatabaseHashRequest {
//     pub fn new() -> Self {
//         Self {
//             action: KeePassAction::GetDatabaseHash,
//         }
//     }
// }
// 
// #[derive(Serialize, Deserialize, Debug)]
// pub struct GetDatabaseHashResponse {
//     pub action: String,
//     pub hash: Option<String>,
//     [> generic fields <]
//     pub version: Option<String>,
//     pub success: Option<KeePassBoolean>,
//     pub error: Option<String>,
//     #[serde(rename = "errorCode")]
//     pub error_code: Option<String>,
// }

/*
 * associate
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#associate
 */

#[derive(Serialize, Deserialize, Debug)]
pub struct AssociateRequest {
    pub action: KeePassAction,
    pub key: String,
    #[serde(rename = "idKey")]
    pub id_key: String,
}

impl AssociateRequest {
    pub fn new(key: &PublicKey, id_key: &PublicKey) -> Self {
        Self {
            action: KeePassAction::Associate,
            key: base64::encode(key.as_bytes()),
            id_key: base64::encode(id_key.as_bytes()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AssociateResponse {
    pub hash: Option<String>,
    /* generic fields */
    pub version: Option<String>,
    pub id: Option<String>,
    pub nonce: Option<String>,
    pub success: Option<KeePassBoolean>,
    pub error: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
}

/*
 * test-associate
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#test-associate
 */

#[derive(Serialize, Deserialize, Debug)]
pub struct TestAssociateRequest {
    pub action: KeePassAction,
    pub id: String,
    pub key: String,
}

impl TestAssociateRequest {
    pub fn new<T: Into<String>>(id: T, id_key: T) -> Self {
        Self {
            action: KeePassAction::TestAssociate,
            id: id.into(),
            key: id_key.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestAssociateResponse {
    pub hash: Option<String>,
    /* generic fields */
    pub version: Option<String>,
    pub id: Option<String>,
    pub nonce: Option<String>,
    pub success: Option<KeePassBoolean>,
    pub error: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
}

/*
 * generate-password (not needed)
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#generate-password
 */

// message_req_type!(
//     GeneratePasswordReq,
//     GeneratePassword,
//     "generate-password-req"
// );

/*
 * get-logins
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#get-logins
 */

#[derive(Serialize, Deserialize, Debug)]
pub struct DatabaseIdentificationKeyPair {
    id: String,
    key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetLoginsRequest {
    action: KeePassAction,
    url: String,
    #[serde(rename = "submitUrl", skip_serializing_if = "Option::is_none")]
    submit_url: Option<String>,
    #[serde(rename = "httpAuth", skip_serializing_if = "Option::is_none")]
    http_auth: Option<KeePassBoolean>,
    keys: Vec<DatabaseIdentificationKeyPair>,
}

impl GetLoginsRequest {
    pub fn new<T: Into<String>>(
        url: T,
        submit_url: Option<T>,
        http_auth: Option<KeePassBoolean>,
        keys: &[(&str, &str)],
    ) -> Self {
        Self {
            action: KeePassAction::GetLogins,
            url: url.into(),
            submit_url: submit_url.map(|u| u.into()),
            http_auth,
            keys: keys
                .iter()
                .map(|(id, key)| DatabaseIdentificationKeyPair {
                    id: (*id).to_string(),
                    key: (*key).to_string(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LoginEntry {
    pub login: String,
    pub name: String,
    pub password: String,
    pub uuid: String,
    pub expired: Option<KeePassBoolean>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetLoginsResponse {
    pub count: usize,
    pub entries: Vec<LoginEntry>,
    pub hash: Option<String>,
    /* generic fields */
    pub version: Option<String>,
    pub id: Option<String>,
    pub nonce: Option<String>,
    pub success: Option<KeePassBoolean>,
    pub error: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
}

/*
 * set-login
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#set-login
 */

#[derive(Serialize, Deserialize, Debug)]
pub struct SetLoginRequest {
    pub action: KeePassAction,
    pub url: String,
    #[serde(rename = "submitUrl")]
    pub submit_url: String,
    pub id: String,
    pub nonce: String,
    pub login: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(rename = "groupUuid", skip_serializing_if = "Option::is_none")]
    pub group_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

impl SetLoginRequest {
    pub fn new<T: Into<String>>(
        url: T,
        submit_url: T,
        id: T,
        login: T,
        password: T,
        group: Option<T>,
        group_uuid: Option<T>,
        uuid: Option<T>,
    ) -> Self {
        let (_, nonce) = generate_nonce();
        Self {
            action: KeePassAction::SetLogin,
            url: url.into(),
            submit_url: submit_url.into(),
            id: id.into(),
            nonce,
            login: login.into(),
            password: password.into(),
            group: group.map(|v| v.into()),
            group_uuid: group_uuid.map(|v| v.into()),
            uuid: uuid.map(|v| v.into()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetLoginResponse {
    pub hash: Option<String>,
    /* generic fields */
    pub version: Option<String>,
    pub id: Option<String>,
    pub nonce: Option<String>,
    pub success: Option<KeePassBoolean>,
    pub error: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
}

/*
 * lock-database (not needed)
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#lock-database
 */

// message_req_type!(LockDatabaseReq, LockDatabase, "lock-database-req");

/*
 * get-database-groups
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#get-database-groups
 */

// #[derive(Serialize, Deserialize, Debug)]
// pub struct GetDatabaseGroupsRequest {
//     action: KeePassAction,
// }
// 
// impl GetDatabaseGroupsRequest {
//     pub fn new() -> Self {
//         Self {
//             action: KeePassAction::GetDatabaseGroups,
//         }
//     }
// }
// 
// #[derive(Serialize, Deserialize, Debug)]
// struct InnerGroups {
//     pub groups: Vec<crate::keepassxc::Group>,
// }
// 
// #[derive(Serialize, Deserialize, Debug)]
// pub struct GetDatabaseGroupsResponse {
//     #[serde(rename = "defaultGroup")]
//     pub default_group: Option<String>,
//     #[serde(rename = "defaultGroupAlwaysAllow")]
//     pub default_group_always_allow: Option<bool>,
//     groups: InnerGroups,
//     [> generic fields <]
//     pub version: Option<String>,
//     pub success: Option<KeePassBoolean>,
//     pub error: Option<String>,
//     #[serde(rename = "errorCode")]
//     pub error_code: Option<String>,
// }
// 
// impl GetDatabaseGroupsResponse {
//     pub fn get_groups(&self) -> &[crate::keepassxc::Group] {
//         &self.groups.groups
//     }
// }

/*
 * create-new-group
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#create-new-group
 */

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateNewGroupRequest {
    action: KeePassAction,
    #[serde(rename = "groupName")]
    group_name: String,
}

impl CreateNewGroupRequest {
    pub fn new<T: Into<String>>(group_name: T) -> Self {
        Self {
            action: KeePassAction::CreateNewGroup,
            group_name: group_name.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateNewGroupResponse {
    pub name: String,
    pub uuid: String,
    /* generic fields */
    pub version: Option<String>,
    pub id: Option<String>,
    pub nonce: Option<String>,
    pub success: Option<KeePassBoolean>,
    pub error: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
}

// no specs, need to dig into codes
//
// message_req_type!(DatabaseLockedReq, DatabaseLocked, "database-locked-req");
// message_req_type!(
//     DatabaseUnlockedReq,
//     DatabaseUnlocked,
//     "database-unlocked-req"
// );
