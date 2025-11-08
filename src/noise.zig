const std = @import("std");
const crypto = std.crypto;
const posix = std.posix;
const common = @import("common.zig");
const sendAllToFd = common.sendAllToFd;
const recvAllFromFd = common.recvAllFromFd;

/// Debug logging for Noise protocol (disable in production for performance)
const enable_noise_debug = false;

/// Debug print helper - compiles out when disabled
inline fn debugPrint(comptime fmt: []const u8, args: anytype) void {
    if (enable_noise_debug) {
        std.debug.print(fmt, args);
    }
}

test "transport cipher advances nonce and output" {
    var key: [KEY_LEN]u8 = undefined;
    @memset(&key, 0x42);

    var cipher = TransportCipher.init(key, .chacha20poly1305);

    var plaintext: [32]u8 = undefined;
    var idx: usize = 0;
    while (idx < plaintext.len) : (idx += 1) {
        plaintext[idx] = @as(u8, @intCast(idx));
    }

    var ct1: [32 + TAG_LEN]u8 = undefined;
    var ct2: [32 + TAG_LEN]u8 = undefined;

    try cipher.encrypt(plaintext[0..], ct1[0..]);
    try cipher.encrypt(plaintext[0..], ct2[0..]);

    try std.testing.expect(!std.mem.eql(u8, ct1[0..], ct2[0..]));
    try std.testing.expectEqual(@as(u64, 2), cipher.nonce.load(.monotonic));
}

/// Cipher type for Noise transport
pub const CipherType = enum {
    chacha20poly1305,
    aes256gcm,
    aes128gcm,
    aegis128l,
    aegis256,

    pub fn fromString(s: []const u8) !CipherType {
        if (std.mem.eql(u8, s, "chacha20poly1305")) return .chacha20poly1305;
        if (std.mem.eql(u8, s, "aes256gcm")) return .aes256gcm;
        if (std.mem.eql(u8, s, "aes128gcm")) return .aes128gcm;
        if (std.mem.eql(u8, s, "aegis128l")) return .aegis128l;
        if (std.mem.eql(u8, s, "aegis256")) return .aegis256;
        return error.InvalidCipher;
    }

    pub fn nonceLen(self: CipherType) usize {
        return switch (self) {
            .chacha20poly1305, .aes256gcm, .aes128gcm => 12,
            .aegis128l => 16,
            .aegis256 => 32,
        };
    }
};

pub const KEY_LEN = 32;
pub const TAG_LEN = 16;
// Force reconnection before theoretical nonce limit to prevent wraparound
// 2^40 (~1.1 trillion messages) provides 256x safety margin before 2^48 limit
pub const MAX_NONCE = 0xFFFFFFFFFF; // 2^40 - 1
pub const DH_LEN = 32; // X25519 public key length
pub const HASH_LEN = 32; // SHA256 hash length

/// Transport cipher for encrypting/decrypting messages
pub const TransportCipher = struct {
    key: [KEY_LEN]u8,
    nonce: std.atomic.Value(u64),
    cipher_type: CipherType,

    pub fn init(key: [KEY_LEN]u8, cipher_type: CipherType) TransportCipher {
        return .{
            .key = key,
            .nonce = std.atomic.Value(u64).init(0),
            .cipher_type = cipher_type,
        };
    }

    fn makeNonce12(n: u64) [12]u8 {
        var nonce: [12]u8 = undefined;
        @memset(nonce[0..4], 0);
        std.mem.writeInt(u64, nonce[4..12], n, .little);
        return nonce;
    }

    fn makeNonce16(n: u64) [16]u8 {
        var nonce: [16]u8 = undefined;
        @memset(nonce[0..8], 0);
        std.mem.writeInt(u64, nonce[8..16], n, .little);
        return nonce;
    }

    fn makeNonce32(n: u64) [32]u8 {
        var nonce: [32]u8 = undefined;
        @memset(nonce[0..24], 0);
        std.mem.writeInt(u64, nonce[24..32], n, .little);
        return nonce;
    }

    /// Encrypt plaintext into ciphertext (includes 16-byte tag)
    pub fn encrypt(self: *TransportCipher, plaintext: []const u8, ciphertext: []u8) !void {
        if (ciphertext.len != plaintext.len + TAG_LEN) return error.InvalidLength;
        const nonce_val = self.nonce.fetchAdd(1, .monotonic);
        if (nonce_val >= MAX_NONCE) return error.NonceExhausted;

        switch (self.cipher_type) {
            .chacha20poly1305 => {
                const nonce = makeNonce12(nonce_val);
                crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len..][0..TAG_LEN],
                    plaintext,
                    &[_]u8{},
                    nonce,
                    self.key,
                );
            },
            .aes256gcm => {
                const nonce = makeNonce12(nonce_val);
                crypto.aead.aes_gcm.Aes256Gcm.encrypt(
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len..][0..TAG_LEN],
                    plaintext,
                    &[_]u8{},
                    nonce,
                    self.key,
                );
            },
            .aes128gcm => {
                const nonce = makeNonce12(nonce_val);
                const key128 = self.key[0..16].*;
                crypto.aead.aes_gcm.Aes128Gcm.encrypt(
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len..][0..TAG_LEN],
                    plaintext,
                    &[_]u8{},
                    nonce,
                    key128,
                );
            },
            .aegis128l => {
                const nonce = makeNonce16(nonce_val);
                const key128 = self.key[0..16].*;
                crypto.aead.aegis.Aegis128L.encrypt(
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len..][0..TAG_LEN],
                    plaintext,
                    &[_]u8{},
                    nonce,
                    key128,
                );
            },
            .aegis256 => {
                const nonce = makeNonce32(nonce_val);
                crypto.aead.aegis.Aegis256.encrypt(
                    ciphertext[0..plaintext.len],
                    ciphertext[plaintext.len..][0..TAG_LEN],
                    plaintext,
                    &[_]u8{},
                    nonce,
                    self.key,
                );
            },
        }
    }

    /// Decrypt ciphertext into plaintext
    pub fn decrypt(self: *TransportCipher, ciphertext: []const u8, plaintext: []u8) !void {
        if (ciphertext.len < TAG_LEN) return error.InvalidLength;
        if (plaintext.len != ciphertext.len - TAG_LEN) return error.InvalidLength;
        const nonce_val = self.nonce.fetchAdd(1, .monotonic);
        if (nonce_val >= MAX_NONCE) return error.NonceExhausted;

        const ct = ciphertext[0..plaintext.len];
        const tag = ciphertext[plaintext.len..][0..TAG_LEN];

        switch (self.cipher_type) {
            .chacha20poly1305 => {
                const nonce = makeNonce12(nonce_val);
                crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
                    plaintext,
                    ct,
                    tag.*,
                    &[_]u8{},
                    nonce,
                    self.key,
                ) catch return error.AuthenticationFailed;
            },
            .aes256gcm => {
                const nonce = makeNonce12(nonce_val);
                crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                    plaintext,
                    ct,
                    tag.*,
                    &[_]u8{},
                    nonce,
                    self.key,
                ) catch return error.AuthenticationFailed;
            },
            .aes128gcm => {
                const nonce = makeNonce12(nonce_val);
                const key128 = self.key[0..16].*;
                crypto.aead.aes_gcm.Aes128Gcm.decrypt(
                    plaintext,
                    ct,
                    tag.*,
                    &[_]u8{},
                    nonce,
                    key128,
                ) catch return error.AuthenticationFailed;
            },
            .aegis128l => {
                const nonce = makeNonce16(nonce_val);
                const key128 = self.key[0..16].*;
                crypto.aead.aegis.Aegis128L.decrypt(
                    plaintext,
                    ct,
                    tag.*,
                    &[_]u8{},
                    nonce,
                    key128,
                ) catch return error.AuthenticationFailed;
            },
            .aegis256 => {
                const nonce = makeNonce32(nonce_val);
                crypto.aead.aegis.Aegis256.decrypt(
                    plaintext,
                    ct,
                    tag.*,
                    &[_]u8{},
                    nonce,
                    self.key,
                ) catch return error.AuthenticationFailed;
            },
        }
    }
};

/// HKDF-SHA256 key derivation
fn hkdf(output: *[HASH_LEN]u8, chaining_key: [HASH_LEN]u8, input_key_material: []const u8) void {
    // HKDF-Extract
    var temp_key: [HASH_LEN]u8 = undefined;
    crypto.auth.hmac.sha2.HmacSha256.create(&temp_key, input_key_material, &chaining_key);

    // HKDF-Expand (single output block)
    var hmac = crypto.auth.hmac.sha2.HmacSha256.init(&temp_key);
    hmac.update(&[_]u8{1}); // output block counter = 1
    hmac.final(output);
}

/// HKDF with two outputs
fn hkdf2(output1: *[HASH_LEN]u8, output2: *[KEY_LEN]u8, chaining_key: [HASH_LEN]u8, input_key_material: []const u8) void {
    // HKDF-Extract
    var temp_key: [HASH_LEN]u8 = undefined;
    crypto.auth.hmac.sha2.HmacSha256.create(&temp_key, input_key_material, &chaining_key);

    // HKDF-Expand - first output
    var hmac1 = crypto.auth.hmac.sha2.HmacSha256.init(&temp_key);
    hmac1.update(&[_]u8{1});
    hmac1.final(output1);

    // HKDF-Expand - second output
    var hmac2 = crypto.auth.hmac.sha2.HmacSha256.init(&temp_key);
    hmac2.update(output1);
    hmac2.update(&[_]u8{2});
    hmac2.final(output2);
}

/// HKDF with three outputs
fn hkdf3(output1: []u8, output2: []u8, output3: []u8, chaining_key: [HASH_LEN]u8, input_key_material: []const u8) void {
    // HKDF-Extract
    var temp_key: [HASH_LEN]u8 = undefined;
    crypto.auth.hmac.sha2.HmacSha256.create(&temp_key, input_key_material, &chaining_key);

    // HKDF-Expand - first output
    var hmac1 = crypto.auth.hmac.sha2.HmacSha256.init(&temp_key);
    hmac1.update(&[_]u8{1});
    hmac1.final(output1);

    // HKDF-Expand - second output
    var hmac2 = crypto.auth.hmac.sha2.HmacSha256.init(&temp_key);
    hmac2.update(output1);
    hmac2.update(&[_]u8{2});
    hmac2.final(output2);

    // HKDF-Expand - third output
    var hmac3 = crypto.auth.hmac.sha2.HmacSha256.init(&temp_key);
    hmac3.update(output2);
    hmac3.update(&[_]u8{3});
    hmac3.final(output3);
}

/// AEAD encryption helper for handshake
fn aeadEncrypt(
    cipher_type: CipherType,
    ciphertext: []u8,
    tag: *[TAG_LEN]u8,
    plaintext: []const u8,
    ad: []const u8,
    nonce: [12]u8,
    key: [KEY_LEN]u8,
) void {
    switch (cipher_type) {
        .chacha20poly1305 => {
            crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
                ciphertext,
                tag,
                plaintext,
                ad,
                nonce,
                key,
            );
        },
        .aes256gcm => {
            crypto.aead.aes_gcm.Aes256Gcm.encrypt(
                ciphertext,
                tag,
                plaintext,
                ad,
                nonce,
                key,
            );
        },
        .aes128gcm => {
            const key128 = key[0..16].*;
            crypto.aead.aes_gcm.Aes128Gcm.encrypt(
                ciphertext,
                tag,
                plaintext,
                ad,
                nonce,
                key128,
            );
        },
        .aegis128l => {
            const nonce16 = [_]u8{0} ** 16;
            const key128 = key[0..16].*;
            crypto.aead.aegis.Aegis128L.encrypt(
                ciphertext,
                tag,
                plaintext,
                ad,
                nonce16,
                key128,
            );
        },
        .aegis256 => {
            const nonce32 = [_]u8{0} ** 32;
            crypto.aead.aegis.Aegis256.encrypt(
                ciphertext,
                tag,
                plaintext,
                ad,
                nonce32,
                key,
            );
        },
    }
}

/// AEAD decryption helper for handshake
fn aeadDecrypt(
    cipher_type: CipherType,
    plaintext: []u8,
    ciphertext: []const u8,
    tag: [TAG_LEN]u8,
    ad: []const u8,
    nonce: [12]u8,
    key: [KEY_LEN]u8,
) !void {
    switch (cipher_type) {
        .chacha20poly1305 => {
            crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
                plaintext,
                ciphertext,
                tag,
                ad,
                nonce,
                key,
            ) catch return error.DecryptionFailed;
        },
        .aes256gcm => {
            crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                plaintext,
                ciphertext,
                tag,
                ad,
                nonce,
                key,
            ) catch return error.DecryptionFailed;
        },
        .aes128gcm => {
            const key128 = key[0..16].*;
            crypto.aead.aes_gcm.Aes128Gcm.decrypt(
                plaintext,
                ciphertext,
                tag,
                ad,
                nonce,
                key128,
            ) catch return error.DecryptionFailed;
        },
        .aegis128l => {
            const nonce16 = [_]u8{0} ** 16;
            const key128 = key[0..16].*;
            crypto.aead.aegis.Aegis128L.decrypt(
                plaintext,
                ciphertext,
                tag,
                ad,
                nonce16,
                key128,
            ) catch return error.DecryptionFailed;
        },
        .aegis256 => {
            const nonce32 = [_]u8{0} ** 32;
            crypto.aead.aegis.Aegis256.decrypt(
                plaintext,
                ciphertext,
                tag,
                ad,
                nonce32,
                key,
            ) catch return error.DecryptionFailed;
        },
    }
}

/// Handshake helpers
pub const HandshakeResult = struct {
    send_cipher: TransportCipher,
    recv_cipher: TransportCipher,
};

fn computeAuthTag(psk: []const u8, handshake_hash: []const u8, role: u8) [HASH_LEN]u8 {
    var tag: [HASH_LEN]u8 = undefined;
    var hmac = crypto.auth.hmac.sha2.HmacSha256.init(psk);
    hmac.update(handshake_hash);
    hmac.update(&[_]u8{role});
    hmac.final(&tag);
    return tag;
}

/// Noise_XX handshake pattern
/// XX:
///   -> e
///   <- e, ee, s, es
///   -> s, se
pub fn noiseXXHandshake(
    fd: posix.fd_t,
    cipher_type: CipherType,
    is_initiator: bool,
    static_keypair: crypto.dh.X25519.KeyPair,
    psk: []const u8,
) !HandshakeResult {
    if (psk.len == 0) return error.MissingPsk;
    const X25519 = crypto.dh.X25519;

    // Generate ephemeral keypair (static keypair is provided)
    const e_keypair = X25519.KeyPair.generate();
    const s_keypair = static_keypair;

    // Initialize Noise state
    var chaining_key: [HASH_LEN]u8 = undefined;
    var h: [HASH_LEN]u8 = undefined;

    // h = HASH(protocol_name) - build based on actual cipher
    const protocol_name = switch (cipher_type) {
        .chacha20poly1305 => "Noise_XX_25519_ChaChaPoly_SHA256",
        .aes256gcm => "Noise_XX_25519_AESGCM_SHA256",
        .aes128gcm => "Noise_XX_25519_AES128GCM_SHA256",
        .aegis128l => "Noise_XX_25519_AEGIS128L_SHA256",
        .aegis256 => "Noise_XX_25519_AEGIS256_SHA256",
    };
    crypto.hash.sha2.Sha256.hash(protocol_name, &h, .{});
    chaining_key = h;

    if (is_initiator) {
        debugPrint("[NOISE] Initiator: sending ephemeral key ({} bytes)\n", .{e_keypair.public_key.len});
        // -> e
        try sendAllToFd(fd, &e_keypair.public_key);
        debugPrint("[NOISE] Initiator: ephemeral key sent\n", .{});

        // Mix e into handshake hash
        var h_hash = crypto.hash.sha2.Sha256.init(.{});
        h_hash.update(&h);
        h_hash.update(&e_keypair.public_key);
        h_hash.final(&h);

        // <- e, ee, s, es
        debugPrint("[NOISE] Initiator: receiving msg2 ({} bytes)\n", .{DH_LEN + DH_LEN + TAG_LEN + TAG_LEN});
        var msg2: [DH_LEN + DH_LEN + TAG_LEN + TAG_LEN]u8 = undefined;
        try recvAllFromFd(fd, &msg2);
        debugPrint("[NOISE] Initiator: msg2 received\n", .{});

        const re = msg2[0..DH_LEN];
        const encrypted_rs = msg2[DH_LEN .. DH_LEN + DH_LEN + TAG_LEN];

        // Mix re into h
        h_hash = crypto.hash.sha2.Sha256.init(.{});
        h_hash.update(&h);
        h_hash.update(re);
        h_hash.final(&h);

        // ee - MixKey(dh_ee): Updates ck and derives temp_k from DH output
        const dh_ee = X25519.scalarmult(e_keypair.secret_key, re.*) catch return error.DHFailed;

        // Decrypt rs
        var temp_k: [KEY_LEN]u8 = undefined;
        var rs: [DH_LEN]u8 = undefined;
        hkdf2(&chaining_key, &temp_k, chaining_key, &dh_ee);

        const encrypted_rs_ct = encrypted_rs[0..DH_LEN];
        const encrypted_rs_tag = encrypted_rs[DH_LEN .. DH_LEN + TAG_LEN].*;
        try aeadDecrypt(
            cipher_type,
            &rs,
            encrypted_rs_ct,
            encrypted_rs_tag,
            &h,
            [_]u8{0} ** 12,
            temp_k,
        );

        // Mix encrypted_rs into h
        h_hash = crypto.hash.sha2.Sha256.init(.{});
        h_hash.update(&h);
        h_hash.update(encrypted_rs);
        h_hash.final(&h);

        // es - MixKey(dh_es): Updates ck and derives temp_k from DH output
        const dh_es = X25519.scalarmult(e_keypair.secret_key, rs) catch return error.DHFailed;

        // Verify empty payload tag from msg2
        hkdf2(&chaining_key, &temp_k, chaining_key, &dh_es);
        const payload_tag_from_msg2 = msg2[DH_LEN + DH_LEN + TAG_LEN ..].*;
        var decrypted_payload: [0]u8 = undefined;
        try aeadDecrypt(
            cipher_type,
            &decrypted_payload,
            &[_]u8{},
            payload_tag_from_msg2,
            &h,
            [_]u8{0} ** 12,
            temp_k,
        );
        // Note: For empty payloads, nothing is mixed into h after verification

        // -> s, se
        var msg3: [DH_LEN + TAG_LEN + TAG_LEN]u8 = undefined;

        // Encrypt s (using temp_k from previous es operation)
        var encrypted_s: [DH_LEN + TAG_LEN]u8 = undefined;
        aeadEncrypt(
            cipher_type,
            encrypted_s[0..DH_LEN],
            encrypted_s[DH_LEN..][0..TAG_LEN],
            &s_keypair.public_key,
            &h,
            [_]u8{0} ** 12,
            temp_k,
        );
        @memcpy(msg3[0 .. DH_LEN + TAG_LEN], &encrypted_s);

        // Mix encrypted_s into h
        h_hash = crypto.hash.sha2.Sha256.init(.{});
        h_hash.update(&h);
        h_hash.update(&encrypted_s);
        h_hash.final(&h);

        // se - MixKey(dh_se): Updates ck and derives temp_k from DH output
        const dh_se = X25519.scalarmult(s_keypair.secret_key, re.*) catch return error.DHFailed;
        hkdf2(&chaining_key, &temp_k, chaining_key, &dh_se);

        // Encrypt empty payload (using temp_k from se operation)
        var payload_tag: [TAG_LEN]u8 = undefined;
        aeadEncrypt(
            cipher_type,
            &[_]u8{},
            &payload_tag,
            &[_]u8{},
            &h,
            [_]u8{0} ** 12,
            temp_k,
        );
        @memcpy(msg3[DH_LEN + TAG_LEN ..], &payload_tag);

        debugPrint("[NOISE] Initiator: sending msg3 ({} bytes)\n", .{msg3.len});
        try sendAllToFd(fd, &msg3);
        debugPrint("[NOISE] Initiator: msg3 sent\n", .{});

        // Split into transport keys
        var key1: [KEY_LEN]u8 = undefined;
        var key2: [KEY_LEN]u8 = undefined;
        hkdf2(&key1, &key2, chaining_key, &[_]u8{});

        const result = HandshakeResult{
            .send_cipher = TransportCipher.init(key1, cipher_type),
            .recv_cipher = TransportCipher.init(key2, cipher_type),
        };

        const handshake_hash: []const u8 = h[0..];
        const local_tag = computeAuthTag(psk, handshake_hash, 'I');
        debugPrint("[NOISE] Initiator: sending PSK auth tag ({} bytes)\n", .{local_tag.len});
        try sendAllToFd(fd, local_tag[0..]);
        debugPrint("[NOISE] Initiator: PSK auth tag sent\n", .{});
        var peer_tag_buf: [HASH_LEN]u8 = undefined;
        debugPrint("[NOISE] Initiator: waiting for server PSK auth tag ({} bytes)\n", .{peer_tag_buf.len});
        try recvAllFromFd(fd, peer_tag_buf[0..]);
        debugPrint("[NOISE] Initiator: received server PSK auth tag\n", .{});
        const expected_peer = computeAuthTag(psk, handshake_hash, 'R');
        // Use constant-time comparison to prevent timing attacks on PSK authentication
        if (!common.constantTimeEqual(peer_tag_buf[0..], expected_peer[0..])) return error.AuthenticationFailed;

        return result;
    } else {
        debugPrint("[NOISE] Responder: waiting for ephemeral key ({} bytes)\n", .{DH_LEN});
        // <- e
        var re: [DH_LEN]u8 = undefined;
        try recvAllFromFd(fd, &re);
        debugPrint("[NOISE] Responder: ephemeral key received\n", .{});

        // Mix re into h
        var h_hash = crypto.hash.sha2.Sha256.init(.{});
        h_hash.update(&h);
        h_hash.update(&re);
        h_hash.final(&h);

        // -> e, ee, s, es
        var msg2: [DH_LEN + DH_LEN + TAG_LEN + TAG_LEN]u8 = undefined;
        @memcpy(msg2[0..DH_LEN], &e_keypair.public_key);

        // Mix e into h
        h_hash = crypto.hash.sha2.Sha256.init(.{});
        h_hash.update(&h);
        h_hash.update(&e_keypair.public_key);
        h_hash.final(&h);

        // ee - MixKey(dh_ee): Updates ck and derives temp_k from DH output
        const dh_ee = X25519.scalarmult(e_keypair.secret_key, re) catch return error.DHFailed;
        var temp_k: [KEY_LEN]u8 = undefined;
        hkdf2(&chaining_key, &temp_k, chaining_key, &dh_ee);

        // Encrypt s (using temp_k from ee operation)
        var encrypted_s: [DH_LEN + TAG_LEN]u8 = undefined;
        aeadEncrypt(
            cipher_type,
            encrypted_s[0..DH_LEN],
            encrypted_s[DH_LEN..][0..TAG_LEN],
            &s_keypair.public_key,
            &h,
            [_]u8{0} ** 12,
            temp_k,
        );
        @memcpy(msg2[DH_LEN .. DH_LEN + DH_LEN + TAG_LEN], &encrypted_s);

        // Mix encrypted_s into h
        h_hash = crypto.hash.sha2.Sha256.init(.{});
        h_hash.update(&h);
        h_hash.update(&encrypted_s);
        h_hash.final(&h);

        // es - MixKey(dh_es): Updates ck and derives temp_k from DH output
        const dh_es = X25519.scalarmult(s_keypair.secret_key, re) catch return error.DHFailed;
        hkdf2(&chaining_key, &temp_k, chaining_key, &dh_es);

        // Encrypt empty payload (using temp_k from es operation)
        var payload_tag: [TAG_LEN]u8 = undefined;
        aeadEncrypt(
            cipher_type,
            &[_]u8{},
            &payload_tag,
            &[_]u8{},
            &h,
            [_]u8{0} ** 12,
            temp_k,
        );
        @memcpy(msg2[DH_LEN + DH_LEN + TAG_LEN ..], &payload_tag);

        debugPrint("[NOISE] Responder: sending msg2 ({} bytes)\n", .{msg2.len});
        try sendAllToFd(fd, &msg2);
        debugPrint("[NOISE] Responder: msg2 sent\n", .{});

        // <- s, se
        debugPrint("[NOISE] Responder: waiting for msg3 ({} bytes)\n", .{DH_LEN + TAG_LEN + TAG_LEN});
        var msg3: [DH_LEN + TAG_LEN + TAG_LEN]u8 = undefined;
        try recvAllFromFd(fd, &msg3);
        debugPrint("[NOISE] Responder: msg3 received\n", .{});

        // Decrypt s (using temp_k from previous es operation)
        debugPrint("[NOISE] Responder: decrypting static key\n", .{});
        const encrypted_rs = msg3[0 .. DH_LEN + TAG_LEN];
        var rs: [DH_LEN]u8 = undefined;

        const encrypted_rs_ct = encrypted_rs[0..DH_LEN];
        const encrypted_rs_tag = encrypted_rs[DH_LEN..].*;
        aeadDecrypt(
            cipher_type,
            &rs,
            encrypted_rs_ct,
            encrypted_rs_tag,
            &h,
            [_]u8{0} ** 12,
            temp_k,
        ) catch |err| {
            debugPrint("[NOISE] Responder: static key decryption failed: {}\n", .{err});
            return error.DecryptionFailed;
        };
        debugPrint("[NOISE] Responder: static key decrypted successfully\n", .{});

        // Mix encrypted_rs into h
        h_hash = crypto.hash.sha2.Sha256.init(.{});
        h_hash.update(&h);
        h_hash.update(encrypted_rs);
        h_hash.final(&h);

        // se - MixKey(dh_se): Updates ck and derives temp_k from DH output
        const dh_se = X25519.scalarmult(e_keypair.secret_key, rs) catch return error.DHFailed;
        hkdf2(&chaining_key, &temp_k, chaining_key, &dh_se);

        // Decrypt empty payload (verify tag using temp_k from se operation)
        const payload_tag2 = msg3[DH_LEN + TAG_LEN ..].*;
        var decrypted: [0]u8 = undefined;
        try aeadDecrypt(
            cipher_type,
            &decrypted,
            &[_]u8{},
            payload_tag2,
            &h,
            [_]u8{0} ** 12,
            temp_k,
        );

        // Split into transport keys (reversed for responder)
        var key1: [KEY_LEN]u8 = undefined;
        var key2: [KEY_LEN]u8 = undefined;
        hkdf2(&key1, &key2, chaining_key, &[_]u8{});

        const result = HandshakeResult{
            .send_cipher = TransportCipher.init(key2, cipher_type),
            .recv_cipher = TransportCipher.init(key1, cipher_type),
        };

        const handshake_hash: []const u8 = h[0..];
        var peer_tag_buf: [HASH_LEN]u8 = undefined;
        debugPrint("[NOISE] Responder: waiting for client PSK auth tag ({} bytes)\n", .{peer_tag_buf.len});
        try recvAllFromFd(fd, peer_tag_buf[0..]);
        debugPrint("[NOISE] Responder: received client PSK auth tag\n", .{});
        const expected_peer = computeAuthTag(psk, handshake_hash, 'I');
        // Use constant-time comparison to prevent timing attacks on PSK authentication
        if (!common.constantTimeEqual(peer_tag_buf[0..], expected_peer[0..])) return error.AuthenticationFailed;

        const local_tag = computeAuthTag(psk, handshake_hash, 'R');
        debugPrint("[NOISE] Responder: sending PSK auth tag ({} bytes)\n", .{local_tag.len});
        try sendAllToFd(fd, local_tag[0..]);
        debugPrint("[NOISE] Responder: PSK auth tag sent\n", .{});

        return result;
    }
}
