// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

fn main() {
    // The imported enclave sources also serve the private native owner fixture.
    // Declare its selector without enabling it or adding a product feature.
    println!("cargo:rustc-check-cfg=cfg(feature, values(\"native-deferred-fixture\"))");
    println!("cargo:rustc-check-cfg=cfg(target_vendor, values(\"teaclave\"))");
}
