use std::collections::HashMap;

fn main() {
    let mut features = HashMap::new();

    features.insert("mceliece348864", cfg!(feature = "mceliece348864"));
    features.insert("mceliece348864f", cfg!(feature = "mceliece348864f"));
    features.insert("mceliece460896", cfg!(feature = "mceliece460896"));
    features.insert("mceliece460896f", cfg!(feature = "mceliece460896f"));
    features.insert("mceliece6688128", cfg!(feature = "mceliece6688128"));
    features.insert("mceliece6688128f", cfg!(feature = "mceliece6688128f"));
    features.insert("mceliece6960119", cfg!(feature = "mceliece6960119"));
    features.insert("mceliece6960119f", cfg!(feature = "mceliece6960119f"));
    features.insert("mceliece8192128", cfg!(feature = "mceliece8192128"));
    features.insert("mceliece8192128f", cfg!(feature = "mceliece8192128f"));

    let mut target_feature = "";
    for (feature, used) in features {
        if !target_feature.is_empty() && used {
            panic!("Config error: \n\t{target_feature} and {feature} cannot be used simultaneously!\n\tPlease select only one feature.");
        } else if used {
            target_feature = feature;
        }
    }

    if target_feature.is_empty() {
        println!("cargo:rustc-cfg=feature=\"mceliece348864\"");
    }
}
