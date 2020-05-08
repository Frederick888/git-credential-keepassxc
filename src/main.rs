mod git;
mod keepassxc;
mod utils;

use anyhow::Result;
use keepassxc::messages::*;
use utils::*;

fn main() -> Result<()> {
    let session_seckey = generate_secret_key();
    let session_pubkey = session_seckey.public_key();
    let session_pubkey_b64 = base64::encode(session_pubkey.as_bytes());

    let (_, client_id) = generate_nonce();

    let cpr_req = ChangePublicKeysRequest::new(&client_id, &session_pubkey);
    let cpr_resp = cpr_req.send()?;

    let host_pubkey = cpr_resp
        .get_public_key()
        .expect("Failed to retrieve host public key");
    let _ = get_client_box(Some(host_pubkey), Some(session_seckey));

    let aso_req = AssociateRequest::new(&session_pubkey, &session_pubkey);
    let aso_resp = aso_req.send(&client_id)?;
    let database_id = aso_resp.id.unwrap();

    let gl_req = GetLoginsRequest::new(
        "https://example.com/foo.git",
        None,
        None,
        &[(&database_id, &session_pubkey_b64)],
    );
    gl_req.send(&client_id)?;

    let sl_req = {
        let (_, nonce) = generate_nonce();
        SetLoginRequest {
            action: KeePassAction::SetLogin,
            url: "https://instance.com/bar.git".to_owned(),
            submit_url: "https://instance.com/bar.git".to_owned(),
            id: database_id,
            nonce,
            login: "user1".to_owned(),
            password: "pwd".to_owned(),
            group: Some("Git".to_owned()),
            group_uuid: None,
            uuid: None,
        }
    };
    sl_req.send(&client_id)?;

    Ok(())
}
