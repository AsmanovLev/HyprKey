import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate fixed deterministic or random attestation keypair for HyprKey
attest_key = ec.generate_private_key(ec.SECP256R1())
attest_priv = attest_key.private_numbers().private_value.to_bytes(32, 'big')

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HyprKey Open Source FIDO"),
    x509.NameAttribute(NameOID.COMMON_NAME, "HyprKey U2F Root CA"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    attest_key.public_key()
).serial_number(
    1337
).not_valid_before(
    datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
).not_valid_after(
    datetime.datetime(2045, 1, 1, tzinfo=datetime.timezone.utc)
).sign(attest_key, hashes.SHA256())

cert_der = cert.public_bytes(serialization.Encoding.DER)

header = f"""/* Auto-generated HyprKey Attestation Key & Certificate */
#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <stdint.h>

static const uint8_t HYPRKEY_ATTEST_PRIVKEY[32] = {{
"""

for i, b in enumerate(attest_priv):
    if i % 12 == 0:
        header += "    "
    header += f"0x{b:02X}, "
    if i % 12 == 11 or i == len(attest_priv) - 1:
        header += "\n"

header += f"""}};

static const uint8_t HYPRKEY_ATTEST_CERT[{len(cert_der)}] = {{
"""

for i, b in enumerate(cert_der):
    if i % 12 == 0:
        header += "    "
    header += f"0x{b:02X}, "
    if i % 12 == 11 or i == len(cert_der) - 1:
        header += "\n"

header += """};

#endif /* ATTESTATION_H */
"""

with open(r"s:\hyprkey\firmware\nfc_fido\attestation.h", "w", encoding="utf-8") as f:
    f.write(header)

print(f"Generated attestation.h with cert size {len(cert_der)} bytes.")
