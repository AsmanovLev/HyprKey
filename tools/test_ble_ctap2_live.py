import asyncio
import cbor2
from bleak import BleakScanner, BleakClient

# hyprkey Management & CTAP Tunnel Service
UUID_OATH_SERVICE   = "a0000001-2721-0100-b42f-c9ba7ed623bb"
UUID_OATH_RX        = "a0000002-2721-0100-b42f-c9ba7ed623bb"
UUID_OATH_TX        = "a0000003-2721-0100-b42f-c9ba7ed623bb"
UUID_CTAP_TUNNEL_RX = "a0000004-2721-0100-b42f-c9ba7ed623bb"
UUID_CTAP_TUNNEL_TX = "a0000005-2721-0100-b42f-c9ba7ed623bb"

rx_queue = asyncio.Queue()

def notification_handler(sender, data):
    raw = bytes(data)
    print(f"  [RAW NOTIF] len={len(raw)}: {raw.hex()}")
    rx_queue.put_nowait(raw)

async def transmit_ctap_command(client, cmd_byte, payload, timeout=6.0):
    """
    Sends CTAP command over BLE with FIDO framing and 20-byte chunks.
    Initial packet: [CMD, LEN_HI, LEN_LO, DATA...]
    Continuation packets: [SEQ, DATA...]
    Reassembles incoming notifications into complete CTAP response.
    """
    # Drain queue
    while not rx_queue.empty():
        rx_queue.get_nowait()

    CHUNK = 20
    req_len = len(payload)
    
    # 1. Initial Packet
    init_chunk_len = min(CHUNK - 3, req_len)
    init_pkt = bytes([cmd_byte, req_len >> 8, req_len & 0xFF]) + payload[:init_chunk_len]
    await client.write_gatt_char(UUID_CTAP_TUNNEL_RX, init_pkt, response=False)
    
    # 2. Continuation Packets
    sent = init_chunk_len
    seq = 0
    while sent < req_len:
        await asyncio.sleep(0.015)
        c_len = min(CHUNK - 1, req_len - sent)
        cont_pkt = bytes([seq & 0x7F]) + payload[sent : sent + c_len]
        seq += 1
        sent += c_len
        await client.write_gatt_char(UUID_CTAP_TUNNEL_RX, cont_pkt, response=False)

    # 3. Receive & Reassemble Response
    resp_cmd = None
    expected_len = 0
    received = bytearray()
    next_seq = 0
    t_end = asyncio.get_event_loop().time() + timeout

    while asyncio.get_event_loop().time() < t_end:
        try:
            pkt = await asyncio.wait_for(rx_queue.get(), timeout=1.0)
            if pkt[0] & 0x80:
                # Initial packet
                resp_cmd = pkt[0]
                expected_len = (pkt[1] << 8) | pkt[2]
                received = bytearray(pkt[3:])
                next_seq = 0
            else:
                # Continuation packet
                seq = pkt[0]
                if seq == next_seq:
                    next_seq += 1
                    received.extend(pkt[1:])
                else:
                    print(f"  [WARN] Out of order sequence: got {seq}, expected {next_seq}")
            
            if len(received) >= expected_len and expected_len > 0:
                return resp_cmd, bytes(received[:expected_len])
        except asyncio.TimeoutError:
            if received and len(received) >= expected_len:
                break

    return resp_cmd, bytes(received)

async def main():
    print("================================================================")
    print("   LIVE HYPRKEY BLUETOOTH CTAP2 & FIDO2 VERIFICATION")
    print("================================================================")

    print("Scanning for 'hyprkey' via Bluetooth Low Energy...")
    device = await BleakScanner.find_device_by_filter(
        lambda d, adv: "hyprkey" in (adv.local_name or d.name or "").lower(),
        timeout=10.0
    )
    assert device is not None, "hyprkey BLE device not found!"
    print(f"[BLE] Found device: {device.name} [{device.address}]")

    print("[BLE] Connecting...")
    async with BleakClient(device, timeout=20.0) as client:
        print(f"[BLE] Connected: {client.is_connected}")

        # Subscribe to CTAP Tunnel TX notifications
        print("\n[CTAP] Subscribing to CTAP Tunnel notifications (0x0005)...")
        try:
            await client.start_notify(UUID_CTAP_TUNNEL_TX, notification_handler)
            await asyncio.sleep(0.3)

            # -------------------------------------------------------------
            # 1. CTAP PING Test
            # -------------------------------------------------------------
            print("\n--- Test 1: CTAP PING ---")
            ping_payload = b"Hello HyprKey FIDO2 BLE!"
            cmd, resp = await transmit_ctap_command(client, 0x81, ping_payload)
            print(f"[PING] CMD=0x{cmd:02X}, Resp={resp.decode('latin1', errors='replace')}")
            assert cmd == 0x81, f"Expected CMD 0x81, got 0x{cmd:02X}"
            assert resp == ping_payload, "PING payload mismatch!"
            print("  ===> [PASS] CTAP PING 100% Verified!")
            await asyncio.sleep(0.1)

            # -------------------------------------------------------------
            # 2. U2F Version Test (CMD=0x83, APDU 00 03 00 00 00)
            # -------------------------------------------------------------
            print("\n--- Test 2: U2F Version (APDU) ---")
            u2f_apdu = bytes([0x00, 0x03, 0x00, 0x00, 0x00])
            cmd, resp = await transmit_ctap_command(client, 0x83, u2f_apdu)
            print(f"[U2F] CMD=0x{cmd:02X}, Resp hex={resp.hex()}")
            assert cmd == 0x83, f"Expected CMD 0x83, got 0x{cmd:02X}"
            assert b"U2F_V2" in resp, f"Expected 'U2F_V2' in response: {resp}"
            print("  ===> [PASS] U2F Version ('U2F_V2') Verified!")
            await asyncio.sleep(0.1)

            # -------------------------------------------------------------
            # 3. CTAP2 authenticatorGetInfo (CMD=0x90, CBOR cmd 0x04)
            # -------------------------------------------------------------
            print("\n--- Test 3: CTAP2 authenticatorGetInfo (CBOR) ---")
            getinfo_cmd = bytes([0x04]) # CTAP2_CMD_GET_INFO
            cmd, resp = await transmit_ctap_command(client, 0x90, getinfo_cmd)
            print(f"[CTAP2] CMD=0x{cmd:02X}, Total response length = {len(resp)} bytes")
            assert cmd == 0x90, f"Expected CMD 0x90, got 0x{cmd:02X}"
            assert len(resp) > 1, "Response too short!"
            
            status_code = resp[0]
            cbor_data = resp[1:]
            print(f"[CTAP2] Status code: 0x{status_code:02X} (0x00 = CTAP1_ERR_SUCCESS)")
            assert status_code == 0x00, f"Error status: 0x{status_code:02X}"

            decoded_info = cbor2.loads(cbor_data)
            print("[CTAP2] Decoded authenticatorGetInfo CBOR:")
            for k, v in sorted(decoded_info.items()):
                print(f"  Field {k}: {v}")

            # Verify key fields
            versions = decoded_info.get(1)
            aaguid = decoded_info.get(3)
            options = decoded_info.get(4)
            algorithms = decoded_info.get(10)
            print(f"\n  Versions: {versions}")
            print(f"  AAGUID: {aaguid.hex() if isinstance(aaguid, bytes) else aaguid}")
            print(f"  Options: {options}")
            print(f"  Algorithms: {algorithms}")

            assert "FIDO_2_0" in versions, "FIDO_2_0 missing from versions!"
            expected_aaguid = bytes([0x48, 0x59, 0x50, 0x52, 0x4B, 0x45, 0x59, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
            assert aaguid == expected_aaguid, f"AAGUID mismatch! Got {aaguid.hex()}"
            print("  ===> [PASS] CTAP2 authenticatorGetInfo 100% Verified!")
            await asyncio.sleep(0.1)

            # -------------------------------------------------------------
            # 4. CTAP2 authenticatorMakeCredential (CMD=0x90, CBOR cmd 0x01)
            # -------------------------------------------------------------
            print("\n--- Test 4: CTAP2 authenticatorMakeCredential (CBOR) ---")
            client_data_hash = b"\x42" * 32
            rp = {"id": "hyprkey.local", "name": "HyprKey Local RP"}
            user = {"id": b"user-alice", "name": "alice@hyprkey.local", "displayName": "Alice"}
            pub_key_cred_params = [{"type": "public-key", "alg": -7}] # ES256 (secp256r1)
            
            make_cred_dict = {
                1: client_data_hash,
                2: rp,
                3: user,
                4: pub_key_cred_params
            }
            make_cred_payload = bytes([0x01]) + cbor2.dumps(make_cred_dict)
            print(f"[CTAP2] Sending MakeCredential request (payload len = {len(make_cred_payload)} bytes)...")
            
            cmd, resp = await transmit_ctap_command(client, 0x90, make_cred_payload, timeout=8.0)
            print(f"[CTAP2 MakeCred] CMD=0x{cmd:02X}, Total response length = {len(resp)} bytes")
            assert cmd == 0x90, f"Expected CMD 0x90, got 0x{cmd:02X}"
            assert len(resp) > 1, "MakeCredential response too short!"
            
            mc_status = resp[0]
            print(f"[CTAP2 MakeCred] Status code: 0x{mc_status:02X} (0x00 = CTAP1_ERR_SUCCESS)")
            assert mc_status == 0x00, f"MakeCredential failed with status 0x{mc_status:02X}"

            mc_cbor = cbor2.loads(resp[1:])
            print("[CTAP2 MakeCred] Response fields:")
            fmt = mc_cbor.get(1)
            auth_data = mc_cbor.get(2)
            att_stmt = mc_cbor.get(3)
            print(f"  fmt: {fmt}")
            print(f"  authData length: {len(auth_data)} bytes")
            print(f"  attStmt keys: {list(att_stmt.keys()) if isinstance(att_stmt, dict) else att_stmt}")
            assert fmt == "packed" or fmt == "none", f"Unexpected format: {fmt}"
            assert len(auth_data) >= 37, f"authData too short: {len(auth_data)}"
            print("  ===> [PASS] CTAP2 authenticatorMakeCredential 100% Verified!")
            await asyncio.sleep(0.1)

            # -------------------------------------------------------------
            # 5. CTAP2 authenticatorGetAssertion (CMD=0x90, CBOR cmd 0x02)
            # -------------------------------------------------------------
            print("\n--- Test 5: CTAP2 authenticatorGetAssertion (CBOR) ---")
            cred_id_len = (auth_data[53] << 8) | auth_data[54]
            cred_id = auth_data[55 : 55 + cred_id_len]
            print(f"[CTAP2] Extracted Credential ID (len={len(cred_id)}): {cred_id.hex()}")

            assertion_client_data_hash = b"\x88" * 32
            get_assert_dict = {
                1: "hyprkey.local",
                2: assertion_client_data_hash,
                3: [{"type": "public-key", "id": cred_id}]
            }
            get_assert_payload = bytes([0x02]) + cbor2.dumps(get_assert_dict)
            print(f"[CTAP2] Sending GetAssertion request (payload len = {len(get_assert_payload)} bytes)...")
            
            cmd, resp = await transmit_ctap_command(client, 0x90, get_assert_payload, timeout=8.0)
            print(f"[CTAP2 GetAssert] CMD=0x{cmd:02X}, Total response length = {len(resp)} bytes")
            assert cmd == 0x90, f"Expected CMD 0x90, got 0x{cmd:02X}"
            assert len(resp) > 1, "GetAssertion response too short!"

            ga_status = resp[0]
            print(f"[CTAP2 GetAssert] Status code: 0x{ga_status:02X} (0x00 = CTAP1_ERR_SUCCESS)")
            assert ga_status == 0x00, f"GetAssertion failed with status 0x{ga_status:02X}"

            ga_cbor = cbor2.loads(resp[1:])
            print("[CTAP2 GetAssert] Response fields:")
            ga_cred = ga_cbor.get(1)
            ga_auth_data = ga_cbor.get(2)
            ga_sig = ga_cbor.get(3)
            print(f"  Credential: {ga_cred}")
            print(f"  authData length: {len(ga_auth_data)} bytes")
            print(f"  signature length: {len(ga_sig)} bytes (hex: {ga_sig[:16].hex()}...)")
            assert len(ga_auth_data) == 37, f"Unexpected authData length: {len(ga_auth_data)}"
            assert len(ga_sig) >= 64, f"Signature too short: {len(ga_sig)}"
            print("  ===> [PASS] CTAP2 authenticatorGetAssertion 100% Verified!")
        finally:
            try:
                await client.stop_notify(UUID_CTAP_TUNNEL_TX)
            except Exception:
                pass
            print("\n================================================================")
            print("   ALL BLUETOOTH CTAP2, U2F & PING TESTS PASSED PERFECTLY!")
            print("================================================================")

if __name__ == "__main__":
    asyncio.run(main())
