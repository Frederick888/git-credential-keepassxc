use super::super::errors::KeePassError;
use super::primitives::*;
use crate::utils::*;
#[allow(unused_imports)]
use crate::{debug, error, info, warn};
use anyhow::Result;
use crypto_box::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;

pub trait PlainTextRequest<R>
where
    R: PlainTextResponse + DeserializeOwned,
    Self: Serialize,
{
    fn send(&self) -> Result<R> {
        info!("Sending {} request", self.get_action().to_string());
        let request_json = serde_json::to_string(self)?;
        #[cfg(not(test))]
        let response_json = MessengingUtils::exchange_message(request_json)?;
        #[cfg(test)]
        let response_json = MockMessengingUtils::exchange_message(request_json)?;
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
    fn send<T: Into<String>>(&self, client_id: T, trigger_unlock: bool) -> Result<R> {
        info!("Sending {} request", self.get_action().to_string());
        let (nonce, nonce_b64) = nacl_nonce();
        let encrypted_request_json = to_encrypted_json(&self, &nonce)?;
        let trigger_unlock = if trigger_unlock {
            "true".to_owned()
        } else {
            "".to_owned()
        };
        let request_wrapper = GenericRequestWrapper {
            action: self.get_action(),
            message: encrypted_request_json,
            nonce: nonce_b64,
            client_id: client_id.into(),
            trigger_unlock,
        };
        #[cfg(not(test))]
        MessengingUtils::send_message(serde_json::to_string(&request_wrapper)?)?;
        #[cfg(test)]
        MockMessengingUtils::send_message(serde_json::to_string(&request_wrapper)?)?;
        let response_wrapper = loop {
            #[cfg(not(test))]
            let response_wrapper_json = MessengingUtils::receive_message()?;
            #[cfg(test)]
            let response_wrapper_json = MockMessengingUtils::receive_message()?;
            let response_wrapper: GenericResponseWrapper =
                serde_json::from_str(&response_wrapper_json)?;
            if response_wrapper.action == self.get_action() {
                break response_wrapper;
            }
            warn!(
                "Unexpected action {} in response, hence discarded: {}",
                response_wrapper.action.to_string(),
                response_wrapper_json
            );
        };
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
            Err(KeePassError {
                message: response_wrapper.error_message(),
                response: response_wrapper,
            })?
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
    (GetDatabaseHashRequest, GetDatabaseHashResponse),
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
    #[serde(rename = "triggerUnlock", skip_serializing_if = "String::is_empty")]
    pub trigger_unlock: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
            warn!("{}", self.error_message());
        }
    }

    fn error_message(&self) -> String {
        format!(
            "Request {} failed, {} (code: {})",
            self.action.to_string(),
            self.error.clone().unwrap_or_else(|| "N/A".to_owned()),
            self.error_code.clone().unwrap_or_else(|| "N/A".to_owned())
        )
    }
}

/*
 * change-public-keys
 * https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md#change-public-keys
 */

#[derive(Serialize, Clone, Debug)]
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
        let (_, nonce) = nacl_nonce();
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

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct GetDatabaseHashRequest {
    pub action: KeePassAction,
}

impl GetDatabaseHashRequest {
    pub fn new() -> Self {
        Self {
            action: KeePassAction::GetDatabaseHash,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetDatabaseHashResponse {
    pub hash: Option<String>,
    pub nonce: Option<String>,
    /* generic fields */
    pub version: Option<String>,
    pub success: Option<KeePassBoolean>,
    pub error: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
}

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
    #[serde(rename = "stringFields")]
    pub string_fields: Option<Vec<HashMap<String, String>>>,
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
    #[allow(clippy::too_many_arguments)]
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
        let (_, nonce) = nacl_nonce();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_00_exchange_public_keys() {
        let _guard = test_guard().lock().unwrap();
        let host_seckey = test_host_secret_key();
        let host_pubkey = host_seckey.public_key();
        let session_seckey = test_session_secret_key();
        let _ = get_client_box(Some(&host_pubkey), Some(&session_seckey));
        let (_, client_id) = nacl_nonce();

        let exchange_message_context = mock_kpxc_initialise(&host_seckey);
        let change_public_key_request = ChangePublicKeysRequest::new(&client_id, &host_pubkey);
        let change_public_key_response = change_public_key_request.send();
        assert!(change_public_key_response.is_ok());
        let change_public_key_response = change_public_key_response.unwrap();
        assert!(change_public_key_response.public_key.is_some());
        let host_pubkey_b64 = base64::encode(host_pubkey.as_bytes());
        assert_eq!(
            host_pubkey_b64,
            change_public_key_response.public_key.unwrap()
        );
        exchange_message_context.checkpoint();
    }

    #[test]
    fn test_01_successful_test_associate() {
        let _guard = test_guard().lock().unwrap();
        let host_seckey = test_host_secret_key();
        let host_pubkey = host_seckey.public_key();
        let session_seckey = test_session_secret_key();
        let session_pubkey = session_seckey.public_key();
        let _ = get_client_box(Some(&host_pubkey), Some(&session_seckey));
        let (_, client_id) = nacl_nonce();

        // exchange keys
        let (send_message_context, receive_message_context) =
            mock_kpxc_initialise_send_receive(&host_seckey);
        let exchange_message_context = MockMessengingUtils::exchange_message_context();
        let change_public_key_request = ChangePublicKeysRequest::new(&client_id, &host_pubkey);
        {
            let change_public_key_request = change_public_key_request.clone();
            exchange_message_context
                .expect()
                .times(1)
                .return_once(move |_| {
                    MockMessengingUtils::send_message(
                        serde_json::to_string(&change_public_key_request).unwrap(),
                    )
                    .unwrap();
                    MockMessengingUtils::receive_message()
                });
        }
        let change_public_key_response = change_public_key_request.send();
        assert!(change_public_key_response.is_ok());
        let change_public_key_response = change_public_key_response.unwrap();
        assert!(change_public_key_response.public_key.is_some());
        let host_pubkey_b64 = base64::encode(host_pubkey.as_bytes());
        assert_eq!(
            host_pubkey_b64,
            change_public_key_response.public_key.unwrap()
        );
        exchange_message_context.checkpoint();
        receive_message_context.checkpoint();

        // test associate
        let test_associate_request = TestAssociateRequest {
            action: KeePassAction::TestAssociate,
            id: "mock".to_owned(),
            key: base64::encode(session_pubkey.as_bytes()),
        };
        {
            let test_associate_response = TestAssociateResponse {
                hash: Some("mock".to_string()),
                id: Some("mock".to_string()),
                nonce: None,
                version: Some("git-credential-keepassxc mock".to_string()),
                success: Some(KeePassBoolean(true)),
                error: None,
                error_code: None,
            };
            mock_kpxc_with_cipher_response(
                &receive_message_context,
                &host_seckey,
                &session_pubkey,
                KeePassAction::TestAssociate,
                test_associate_response,
            );
        }
        let test_associate_response = test_associate_request.send(&client_id, false);
        assert!(test_associate_response.is_ok());
        receive_message_context.checkpoint();
        send_message_context.checkpoint();
    }
}
