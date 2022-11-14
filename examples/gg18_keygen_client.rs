#![allow(non_snake_case)]
/// to run:
/// 1: go to rocket_server -> cargo run
/// 2: cargo run from PARTIES number of terminals
use curv::{
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, Parameters,
};
use paillier::EncryptionKey;
use reqwest::Client;
use sha2::Sha256;
use std::{env, fs, time};
use std::vec::Vec;

mod common;
use common::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p,
    GroupName, KeygenInput, ParamsInput, Res_Body_Keygen, Params, PartySignup, AEAD, AES_KEY_BYTES_LEN,
};

#[tokio::main]
async fn main() {
    //INPUT PARAMETERS FROM USERS
    // 1. endpoint 2.keyName 3.groupName 4. address 5.parties 6.threshold
    if env::args().nth(7).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(6).is_none() {
        panic!("too few arguments")
    }
    //read parameters:
    let group_name = env::args().nth(3).unwrap_or_else(|| "".to_string());
    let address = env::args().nth(4).unwrap_or_else(|| "".to_string());
    // let data = fs::read_to_string("params.json")
    //     .expect("Unable to read params, make sure config file is present in the same folder ");

    // let params: Params = serde_json::from_str(&data).unwrap();
    //let PARTIES: u16 = params.parties.parse::<u16>().unwrap();
    let partie_env = env::args().nth(5).unwrap_or_else(|| "".to_string());
    let PARTIES: u16 = partie_env.parse::<u16>().unwrap();
    let threshold_env = env::args().nth(6).unwrap_or_else(|| "".to_string());
    let THRESHOLD: u16 = threshold_env.parse::<u16>().unwrap();
    if THRESHOLD > PARTIES {
        panic!("parties should be larger than threshold")
    }
    //let array_address : Vec<String> = Vec::new();
    let array_address_env = env::args().nth(4).unwrap_or_else(|| "".to_string());
    let array_address = array_address_env.split(",").collect::<Vec<&str>>();
    println!("array address : {}",array_address_env);
    println!("array address : {}",array_address_env);
    println!("array_address[0] : {}", array_address[0]);
    println!("array_address length:  {}", array_address.len());
    //let xxx : Vec<u16> = array_address.to_string().encode_to_vec();
    //let mut bcd = vec!(array_address);
    //let mut xxx : [String,3] = bcd; 
    for place in array_address.iter() {
        println!("PLACE: {}", place)
    }
    if array_address.len() > PARTIES as usize {
        panic!("array_address.len() > PARTIES")
    }
    if array_address.len() < PARTIES as usize {
        panic!("array_address.len() < PARTIES")
    }
    //let mut users: Vec<String> = Vec::new();
    
    let client = Client::new();

    // delay:
    let delay = time::Duration::from_millis(25);
    let params = Parameters {
        threshold: THRESHOLD,
        share_count: PARTIES,
    };
    let paramsInput = ParamsInput {
        parties: PARTIES,
        threshold: THRESHOLD,
    };

    // SAVE FILE PARAMS.JSON

    // fs::write(
    //     "PARAMS.JSON",
    //     serde_json::to_string(&(paramsInput)).unwrap(),
    // )
    // .expect("unable to SAVE");
    //let group = GroupName { groupname: group_name };
    // let keygen_input = serde_json::to_string(&(
    //     group,
    //     paramsInput,
    // )).unwrap();


    //signup:
    let res_body1 : Res_Body_Keygen = signup(&client, group_name, address, paramsInput.clone()).await.unwrap();
    let party_num_int = res_body1.number;
    let    uuid = res_body1.uuid;
    // let (party_num_int, uuid) = match signup(&client, group_name, address, paramsInput).OK.unwrap() {
    //     PartySignup { number, uuid } => (number, uuid),
    // };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    let party_keys = Keys::create(party_num_int);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    // send commitment to ephemeral public keys, get round 1 commitments of other parties
    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&bc_i).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    //println!("Before poll_for_broadcasts: client: {:?}, party_num_int : {:?}, PARTIES : {:?}, delay: {:?},  round1: round1, uuid {:?}", &client, party_num_int, PARTIES, delay, uuid.clone());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round1",
        uuid.clone(),
    ).await;
    println!(
        "After: round1_ans_vec: client, party_num, n, delay,  round, sender_uuid,  {:?}",
        round1_ans_vec
    );

    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party_num_int as usize - 1, bc_i);

    // send ephemeral public keys and check commitments correctness
    assert!(broadcast(
        &client,
        party_num_int,
        "round2",
        serde_json::to_string(&decom_i).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round2",
        uuid.clone(),
    ).await;

    let mut j = 0;
    let mut point_vec: Vec<Point<Secp256k1>> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            point_vec.push(decom_i.y_i.clone());
            decom_vec.push(decom_i.clone());
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            point_vec.push(decom_j.y_i.clone());
            decom_vec.push(decom_j.clone());
            let key_bn: BigInt = (decom_j.y_i.clone() * party_keys.u_i.clone())
                .x_coord()
                .unwrap();
            let key_bytes = BigInt::to_bytes(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
            j += 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            )
            .await
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round3",
        uuid.clone(),
    ).await;

    let mut j = 0;
    let mut party_shares: Vec<Scalar<Secp256k1>> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes(&out[..]);
            let out_fe = Scalar::<Secp256k1>::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    // round 4: send vss commitments
    assert!(broadcast(
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        PARTIES,
        delay,
        "round4",
        uuid.clone(),
    ).await;

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<Secp256k1>> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
            let vss_scheme_j: VerifiableSS<Secp256k1> =
                serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            party_num_int,
        )
        .expect("invalid vss");

    // round 5: send dlog proof
    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&dlog_proof).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round5_ans_vec =
        poll_for_broadcasts(&client, party_num_int, PARTIES, delay, "round5", uuid).await;

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof<Secp256k1, Sha256>> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
            let dlog_proof_j: DLogProof<Secp256k1, Sha256> =
                serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }
    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    //save key to file:
    let paillier_key_vec = (0..PARTIES)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let y_sumJson = serde_json::to_string(&y_sum);
    println!("shared_keys: {:?}", y_sumJson);
    println!(
        "shared_keys hex: {:?}",
        BigInt::from_bytes(&y_sum.to_bytes(true)).to_str_radix(16)
    );
    let keygen_json = serde_json::to_string(&(
        party_keys,       // before round 1
        shared_keys,      // after round 4
        party_num_int,    // before round 1
        vss_scheme_vec,   //after round 4
        paillier_key_vec, // after round 5
        y_sum,            // after round 2
        array_address,
        paramsInput.clone(),
    ))
    .unwrap();
    fs::write(env::args().nth(2).unwrap(), keygen_json).expect("Unable to save !");
    println!("SAVE SUCCESS")
}


pub async fn signup(client: &Client, groupName: String, address: String, parameters: ParamsInput) -> Result<Res_Body_Keygen, ()> {
    //let key = "signup-keygen".to_string();
    let groupName = groupName.to_string();
    //let group = GroupName { groupname: groupName };
    let keygen_input = KeygenInput {
        groupname: groupName,
        address: address,
        parties: parameters.parties,
        threshold: parameters.threshold,
    };

    let res_body = postb(client, "signupkeygen", keygen_input).await.unwrap();
    println!("res_body : {}", res_body);
    serde_json::from_str(&res_body).unwrap()
}

