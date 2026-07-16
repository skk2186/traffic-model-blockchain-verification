use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use frost_ed25519 as frost;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::env;

const DOMAIN: &[u8] = b"WECROSS-FROST-ED25519-V1";
const SCHEME: &str = "FROST-ED25519-SHA512";

struct Options {
    policy_id: String,
    business_id: String,
    message: String,
    threshold: u16,
    total_nodes: u16,
    participants: Vec<u16>,
}

fn value(args: &[String], name: &str) -> Result<String> {
    let index = args
        .iter()
        .position(|item| item == name)
        .with_context(|| format!("missing argument {name}"))?;
    args.get(index + 1)
        .cloned()
        .with_context(|| format!("missing value for {name}"))
}

fn decode_text(args: &[String], name: &str) -> Result<String> {
    let encoded = value(args, name)?;
    let bytes = BASE64
        .decode(encoded)
        .with_context(|| format!("{name} must be valid Base64"))?;
    String::from_utf8(bytes).with_context(|| format!("{name} must contain UTF-8 text"))
}

fn parse_options() -> Result<Options> {
    let args: Vec<String> = env::args().skip(1).collect();
    let policy_id = value(&args, "--policy-id")?;
    let business_id = decode_text(&args, "--business-id-base64")?;
    let message = decode_text(&args, "--message-base64")?;
    let threshold: u16 = value(&args, "--threshold")?
        .parse()
        .context("threshold must be an integer")?;
    let total_nodes: u16 = value(&args, "--total-nodes")?
        .parse()
        .context("totalNodes must be an integer")?;
    let mut participants = Vec::new();
    for item in value(&args, "--participants")?.split(',') {
        participants.push(
            item.trim()
                .parse::<u16>()
                .with_context(|| format!("invalid participant id: {item}"))?,
        );
    }

    if policy_id.is_empty() {
        bail!("policyId must not be empty");
    }
    if business_id.is_empty() || message.is_empty() {
        bail!("businessId and message must not be empty");
    }
    if threshold < 2 || threshold > total_nodes {
        bail!("threshold must be between 2 and totalNodes");
    }
    if participants.len() < threshold as usize {
        bail!("participant count must be greater than or equal to threshold");
    }
    if participants.iter().any(|id| *id == 0 || *id > total_nodes) {
        bail!("participant id must be between 1 and totalNodes");
    }
    let unique: BTreeSet<u16> = participants.iter().copied().collect();
    if unique.len() != participants.len() {
        bail!("participant ids must not contain duplicates");
    }
    participants.sort_unstable();

    Ok(Options {
        policy_id,
        business_id,
        message,
        threshold,
        total_nodes,
        participants,
    })
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn canonical_message(options: &Options) -> Vec<u8> {
    let mut output = Vec::new();
    put_bytes(&mut output, DOMAIN);
    put_bytes(&mut output, options.policy_id.as_bytes());
    put_bytes(&mut output, options.business_id.as_bytes());
    output.extend_from_slice(&(options.threshold as u32).to_be_bytes());
    output.extend_from_slice(&(options.total_nodes as u32).to_be_bytes());
    output.extend_from_slice(&(options.participants.len() as u32).to_be_bytes());
    for participant in &options.participants {
        output.extend_from_slice(&(*participant as u32).to_be_bytes());
    }
    put_bytes(&mut output, options.message.as_bytes());
    output
}

fn main() -> Result<()> {
    let options = parse_options()?;
    let mut rng = rand::rngs::OsRng;
    let (shares, public_key_package) = frost::keys::generate_with_dealer(
        options.total_nodes,
        options.threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    let mut key_packages = BTreeMap::new();
    for (identifier, share) in shares {
        key_packages.insert(identifier, frost::keys::KeyPackage::try_from(share)?);
    }

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for participant in &options.participants {
        let identifier = frost::Identifier::try_from(*participant)?;
        let key_package = key_packages
            .get(&identifier)
            .context("missing participant key package")?;
        let (participant_nonces, participant_commitments) =
            frost::round1::commit(key_package.signing_share(), &mut rng);
        nonces.insert(identifier, participant_nonces);
        commitments.insert(identifier, participant_commitments);
    }

    let payload = canonical_message(&options);
    let signing_package = frost::SigningPackage::new(commitments, &payload);
    let mut signature_shares = BTreeMap::new();
    for (identifier, participant_nonces) in &nonces {
        let signature_share = frost::round2::sign(
            &signing_package,
            participant_nonces,
            key_packages
                .get(identifier)
                .context("missing signer key package")?,
        )?;
        signature_shares.insert(*identifier, signature_share);
    }

    let signature = frost::aggregate(&signing_package, &signature_shares, &public_key_package)?;
    public_key_package
        .verifying_key()
        .verify(&payload, &signature)
        .context("generated FROST signature did not verify")?;

    let group_public_key = public_key_package.verifying_key().serialize()?;
    let aggregate_signature = signature.serialize()?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "policy": {
                "policyId": options.policy_id,
                "scheme": SCHEME,
                "threshold": options.threshold,
                "totalNodes": options.total_nodes,
                "groupPublicKey": BASE64.encode(&group_public_key)
            },
            "request": {
                "businessId": options.business_id,
                "message": options.message,
                "threshold": options.threshold,
                "totalNodes": options.total_nodes,
                "participantIds": options.participants,
                "signatureBundle": {
                    "scheme": SCHEME,
                    "policyId": options.policy_id,
                    "aggregateSignature": BASE64.encode(&aggregate_signature)
                },
                "writeLedger": false,
                "ledgerTargets": []
            },
            "diagnostics": {
                "cryptography": "REAL_FROST_ED25519",
                "signerMode": "LOCAL_TEST_TRUSTED_DEALER",
                "round1CommitmentCount": options.participants.len(),
                "round2SignatureShareCount": signature_shares.len(),
                "aggregateSignatureBytes": aggregate_signature.len(),
                "groupPublicKeyBytes": group_public_key.len()
            }
        }))?
    );
    Ok(())
}
