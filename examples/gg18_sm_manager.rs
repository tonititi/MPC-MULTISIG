use std::collections::HashMap;
use std::fs;
use std::sync::RwLock;

use rocket::serde::json::Json;
use rocket::{post, routes, State};
use uuid::Uuid;

mod common;
use common::{Entry, Index, Key, Params, PartySignup};

use curv::elliptic::curves::{secp256_k1::Secp256k1, Point};

#[post("/get", format = "json", data = "<request>")]
fn get(
    db_mtx: &State<RwLock<HashMap<Key, String>>>,
    request: Json<Index>,
) -> Json<Result<Entry, ()>> {
    let index: Index = request.0;
    let hm = db_mtx.read().unwrap();
    if index.key.to_string() == "get_auth_pubkeys" {
        let param_data = fs::read_to_string("params.json").expect(
            "Unable to read params, make sure config file is present in the same folder ",
        );
        let params: Params = serde_json::from_str(&param_data).unwrap();
        let entry = Entry {
            key: index.key,
            value: params.auth_pubkeys,
        };
        Json(Ok(entry))
    } else {
        match hm.get(&index.key) {
            Some(v) => {
                let entry = Entry {
                    key: index.key,
                    value: v.clone(),
                };
                Json(Ok(entry))
            }
            None => Json(Err(())),
        }
    }
}

#[post("/set", format = "json", data = "<request>")]
fn set(db_mtx: &State<RwLock<HashMap<Key, String>>>, request: Json<Entry>) -> Json<Result<(), ()>> {
    let entry: Entry = request.0;
    let mut hm = db_mtx.write().unwrap();
    if entry.key.to_string().contains("auth_pubkey") {
        let key_str = entry.key.to_string();
        let splits: Vec<&str> = (&key_str).split("-").collect();
        if splits.len() >= 3 {
            let splits1 = splits[1];
            if splits1 == "auth_pubkey" {
                let param_data = fs::read_to_string("params.json").expect(
                    "Unable to read params, make sure config file is present in the same folder ",
                );
                let auth_pubkey_str = entry.value.to_owned();
                let mut params: Params = serde_json::from_str(&param_data).unwrap();
                if params.finalized_pubkeys == "" {
                    //in key generation phase
                    let auth_pubkeys = params.auth_pubkeys.to_owned();
                    if !auth_pubkeys.contains(&auth_pubkey_str) {
                        if params.auth_pubkeys != "" {
                            params.auth_pubkeys.push_str("-");
                        }
                        params.auth_pubkeys.push_str(&auth_pubkey_str);
                        fs::write(
                            "params.json".to_string(),
                            serde_json::to_string_pretty(&params).unwrap(),
                        )
                        .expect("Unable to save !");
                    }
                }
            }
        }
    }
    hm.insert(entry.key.clone(), entry.value);
    Json(Ok(()))
}

#[post("/signupkeygen", format = "json")]
fn signup_keygen(db_mtx: &State<RwLock<HashMap<Key, String>>>) -> Json<Result<PartySignup, ()>> {
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let parties = params.parties.parse::<u16>().unwrap();
    let key = "signup-keygen".to_string();

    let party_signup = {
        let hm = db_mtx.read().unwrap();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(value).unwrap();
        if client_signup.number < parties {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    let mut hm = db_mtx.write().unwrap();
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[post("/signupsign", format = "json")]
fn signup_sign(db_mtx: &State<RwLock<HashMap<Key, String>>>) -> Json<Result<PartySignup, ()>> {
    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let threshold = params.threshold.parse::<u16>().unwrap();
    let key = "signup-sign".to_string();

    let party_signup = {
        let hm = db_mtx.read().unwrap();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(value).unwrap();
        if client_signup.number < threshold + 1 {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    let mut hm = db_mtx.write().unwrap();
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[tokio::main]
async fn main() {
    // let mut my_config = Config::development();
    // my_config.set_port(18001);
    let db: HashMap<Key, String> = HashMap::new();
    let db_mtx = RwLock::new(db);
    //rocket::custom(my_config).mount("/", routes![get, set]).manage(db_mtx).launch();

    /////////////////////////////////////////////////////////////////
    //////////////////////////init signups://////////////////////////
    /////////////////////////////////////////////////////////////////

    let keygen_key = "signup-keygen".to_string();
    let sign_key = "signup-sign".to_string();

    let uuid_keygen = Uuid::new_v4().to_string();
    let uuid_sign = Uuid::new_v4().to_string();

    let party1 = 0;
    let party_signup_keygen = PartySignup {
        number: party1,
        uuid: uuid_keygen,
    };
    let party_signup_sign = PartySignup {
        number: party1,
        uuid: uuid_sign,
    };
    {
        let mut hm = db_mtx.write().unwrap();
        hm.insert(
            keygen_key,
            serde_json::to_string(&party_signup_keygen).unwrap(),
        );
        hm.insert(sign_key, serde_json::to_string(&party_signup_sign).unwrap());
    }
    /////////////////////////////////////////////////////////////////
    rocket::build()
        .mount("/", routes![get, set, signup_keygen, signup_sign])
        .manage(db_mtx)
        .launch()
        .await
        .unwrap();
}
