use fips203;

#[repr(C)]
pub struct ml_kem_shared_secret {
    data: [u8; fips203::SSK_LEN],
}

pub const ML_KEM_OK: u8 = 0;
pub const ML_KEM_NULL_PTR_ERROR: u8 = 1;
pub const ML_KEM_SERIALIZATION_ERROR: u8 = 2;
pub const ML_KEM_DESERIALIZATION_ERROR: u8 = 3;
pub const ML_KEM_KEYGEN_ERROR: u8 = 4;
pub const ML_KEM_ENCAPSULATION_ERROR: u8 = 5;
pub const ML_KEM_DECAPSULATION_ERROR: u8 = 6;

// ML-KEM-512

#[repr(C)]
pub struct ml_kem_512_encaps_key {
    data: [u8; fips203::ml_kem_512::EK_LEN],
}
#[repr(C)]
pub struct ml_kem_512_decaps_key {
    data: [u8; fips203::ml_kem_512::DK_LEN],
}
#[repr(C)]
pub struct ml_kem_512_ciphertext {
    data: [u8; fips203::ml_kem_512::CT_LEN],
}

#[no_mangle]
pub extern "C" fn ml_kem_512_keygen(
    encaps_out: Option<&mut ml_kem_512_encaps_key>, decaps_out: Option<&mut ml_kem_512_decaps_key>,
) -> u8 {
    use fips203::traits::{KeyGen, SerDes};

    let (Some(encaps_out), Some(decaps_out)) = (encaps_out, decaps_out) else {
        return ML_KEM_NULL_PTR_ERROR;
    };
    let Ok((ek, dk)) = fips203::ml_kem_512::KG::try_keygen_vt() else {
        return ML_KEM_KEYGEN_ERROR;
    };

    encaps_out.data = ek.into_bytes();
    decaps_out.data = dk.into_bytes();
    return ML_KEM_OK;
}

#[no_mangle]
pub extern "C" fn ml_kem_512_encaps(
    encaps: Option<&ml_kem_512_encaps_key>, ciphertext_out: Option<&mut ml_kem_512_ciphertext>,
    shared_secret_out: Option<&mut ml_kem_shared_secret>,
) -> u8 {
    use fips203::traits::{Encaps, SerDes};

    let (Some(encaps), Some(ciphertext_out), Some(shared_secret_out)) =
        (encaps, ciphertext_out, shared_secret_out)
        else {
        return ML_KEM_NULL_PTR_ERROR;
    };
    let Ok(ek) = fips203::ml_kem_512::EncapsKey::try_from_bytes(encaps.data) else {
        return ML_KEM_DESERIALIZATION_ERROR;
    };
    let Ok((ssk, ct)) = ek.try_encaps_vt() else {
        return ML_KEM_ENCAPSULATION_ERROR;
    };

    shared_secret_out.data = ssk.into_bytes();
    ciphertext_out.data = ct.into_bytes();
    return ML_KEM_OK;
}

#[no_mangle]
pub extern "C" fn ml_kem_512_decaps(
    decaps: Option<&ml_kem_512_decaps_key>, ciphertext: Option<&ml_kem_512_ciphertext>,
    shared_secret_out: Option<&mut ml_kem_shared_secret>,
) -> u8 {
    use fips203::traits::{Decaps, SerDes};

    let (Some(decaps), Some(ciphertext), Some(shared_secret_out)) =
        (decaps, ciphertext, shared_secret_out)
        else {
        return ML_KEM_NULL_PTR_ERROR;
    };
    let Ok(dk) = fips203::ml_kem_512::DecapsKey::try_from_bytes(decaps.data) else {
        return ML_KEM_DESERIALIZATION_ERROR;
    };
    let Ok(ct) = fips203::ml_kem_512::CipherText::try_from_bytes(ciphertext.data) else {
        return ML_KEM_DESERIALIZATION_ERROR;
    };
    let Ok(ssk) = dk.try_decaps_vt(&ct) else {
        return ML_KEM_DECAPSULATION_ERROR;
    };

    shared_secret_out.data = ssk.into_bytes();
    return ML_KEM_OK;
}

// ML-KEM-768

#[repr(C)]
pub struct ml_kem_768_encaps_key {
    data: [u8; fips203::ml_kem_768::EK_LEN],
}
#[repr(C)]
pub struct ml_kem_768_decaps_key {
    data: [u8; fips203::ml_kem_768::DK_LEN],
}
#[repr(C)]
pub struct ml_kem_768_ciphertext {
    data: [u8; fips203::ml_kem_768::CT_LEN],
}

#[no_mangle]
pub extern "C" fn ml_kem_768_keygen(
    encaps_out: Option<&mut ml_kem_768_encaps_key>, decaps_out: Option<&mut ml_kem_768_decaps_key>,
) -> u8 {
    use fips203::traits::{KeyGen, SerDes};

    let (Some(encaps_out), Some(decaps_out)) = (encaps_out, decaps_out) else {
        return ML_KEM_NULL_PTR_ERROR;
    };
    let Ok((ek, dk)) = fips203::ml_kem_768::KG::try_keygen_vt() else {
        return ML_KEM_KEYGEN_ERROR;
    };

    encaps_out.data = ek.into_bytes();
    decaps_out.data = dk.into_bytes();
    return ML_KEM_OK;
}

#[no_mangle]
pub extern "C" fn ml_kem_768_encaps(
    encaps: Option<&ml_kem_768_encaps_key>, ciphertext_out: Option<&mut ml_kem_768_ciphertext>,
    shared_secret_out: Option<&mut ml_kem_shared_secret>,
) -> u8 {
    use fips203::traits::{Encaps, SerDes};

    let (Some(encaps), Some(ciphertext_out), Some(shared_secret_out)) =
        (encaps, ciphertext_out, shared_secret_out)
        else {
        return ML_KEM_NULL_PTR_ERROR;
    };
    let Ok(ek) = fips203::ml_kem_768::EncapsKey::try_from_bytes(encaps.data) else {
        return ML_KEM_DESERIALIZATION_ERROR;
    };
    let Ok((ssk, ct)) = ek.try_encaps_vt() else {
        return ML_KEM_ENCAPSULATION_ERROR;
    };

    shared_secret_out.data = ssk.into_bytes();
    ciphertext_out.data = ct.into_bytes();
    return ML_KEM_OK;
}

#[no_mangle]
pub extern "C" fn ml_kem_768_decaps(
    decaps: Option<&ml_kem_768_decaps_key>, ciphertext: Option<&ml_kem_768_ciphertext>,
    shared_secret_out: Option<&mut ml_kem_shared_secret>,
) -> u8 {
    use fips203::traits::{Decaps, SerDes};

    let (Some(decaps), Some(ciphertext), Some(shared_secret_out)) =
        (decaps, ciphertext, shared_secret_out)
        else {
        return ML_KEM_NULL_PTR_ERROR;
    };
    let Ok(dk) = fips203::ml_kem_768::DecapsKey::try_from_bytes(decaps.data) else {
        return ML_KEM_DESERIALIZATION_ERROR;
    };
    let Ok(ct) = fips203::ml_kem_768::CipherText::try_from_bytes(ciphertext.data) else {
        return ML_KEM_DESERIALIZATION_ERROR;
    };
    let Ok(ssk) = dk.try_decaps_vt(&ct) else {
        return ML_KEM_DECAPSULATION_ERROR;
    };

    shared_secret_out.data = ssk.into_bytes();
    return ML_KEM_OK;
}

// ML-KEM-1024

#[repr(C)]
pub struct ml_kem_1024_encaps_key {
    data: [u8; fips203::ml_kem_1024::EK_LEN],
}
#[repr(C)]
pub struct ml_kem_1024_decaps_key {
    data: [u8; fips203::ml_kem_1024::DK_LEN],
}
#[repr(C)]
pub struct ml_kem_1024_ciphertext {
    data: [u8; fips203::ml_kem_1024::CT_LEN],
}

#[no_mangle]
pub extern "C" fn ml_kem_1024_keygen(
    encaps_out: Option<&mut ml_kem_1024_encaps_key>,
    decaps_out: Option<&mut ml_kem_1024_decaps_key>,
) -> u8 {
    use fips203::traits::{KeyGen, SerDes};

    let (Some(encaps_out), Some(decaps_out)) = (encaps_out, decaps_out) else {
        return ML_KEM_NULL_PTR_ERROR;
    };
    let Ok((ek, dk)) = fips203::ml_kem_1024::KG::try_keygen_vt() else {
        return ML_KEM_KEYGEN_ERROR;
    };

    encaps_out.data = ek.into_bytes();
    decaps_out.data = dk.into_bytes();
    return ML_KEM_OK;
}

#[no_mangle]
pub extern "C" fn ml_kem_1024_encaps(
    encaps: Option<&ml_kem_1024_encaps_key>, ciphertext_out: Option<&mut ml_kem_1024_ciphertext>,
    shared_secret_out: Option<&mut ml_kem_shared_secret>,
) -> u8 {
    use fips203::traits::{Encaps, SerDes};

    let (Some(encaps), Some(ciphertext_out), Some(shared_secret_out)) =
        (encaps, ciphertext_out, shared_secret_out)
        else {
        return ML_KEM_NULL_PTR_ERROR;
    };
    let Ok(ek) = fips203::ml_kem_1024::EncapsKey::try_from_bytes(encaps.data) else {
        return ML_KEM_DESERIALIZATION_ERROR;
    };
    let Ok((ssk, ct)) = ek.try_encaps_vt() else {
        return ML_KEM_ENCAPSULATION_ERROR;
    };

    shared_secret_out.data = ssk.into_bytes();
    ciphertext_out.data = ct.into_bytes();
    return ML_KEM_OK;
}

#[no_mangle]
pub extern "C" fn ml_kem_1024_decaps(
    decaps: Option<&ml_kem_1024_decaps_key>, ciphertext: Option<&ml_kem_1024_ciphertext>,
    shared_secret_out: Option<&mut ml_kem_shared_secret>,
) -> u8 {
    use fips203::traits::{Decaps, SerDes};

    let (Some(decaps), Some(ciphertext), Some(shared_secret_out)) =
        (decaps, ciphertext, shared_secret_out)
        else {
        return ML_KEM_NULL_PTR_ERROR;
    };
    let Ok(dk) = fips203::ml_kem_1024::DecapsKey::try_from_bytes(decaps.data) else {
        return ML_KEM_DESERIALIZATION_ERROR;
    };
    let Ok(ct) = fips203::ml_kem_1024::CipherText::try_from_bytes(ciphertext.data) else {
        return ML_KEM_DESERIALIZATION_ERROR;
    };
    let Ok(ssk) = dk.try_decaps_vt(&ct) else {
        return ML_KEM_DECAPSULATION_ERROR;
    };

    shared_secret_out.data = ssk.into_bytes();
    return ML_KEM_OK;
}
