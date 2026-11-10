package com.hyprkey.debug;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.os.Vibrator;
import android.util.Log;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;

public class MainActivity extends Activity implements NfcAdapter.ReaderCallback {
    private static final String TAG = "HyprNfc";

    /* AID Definitions */
    private static final byte[] OPENPGP_AID_SELECT = new byte[] {
        0x00, (byte)0xA4, 0x04, 0x00, 0x06,
        (byte)0xD2, 0x76, 0x00, 0x01, 0x24, 0x01
    };

    private static final byte[] OATH_AID_SELECT = new byte[] {
        0x00, (byte)0xA4, 0x04, 0x00, 0x07,
        (byte)0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01
    };

    private static final byte[] FIDO_AID_SELECT = new byte[] {
        0x00, (byte)0xA4, 0x04, 0x00, 0x08,
        (byte)0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
    };

    private NfcAdapter nfcAdapter;
    private TextView tvBadge;
    private TextView tvStatusDetails;
    private TextView tvLog;
    private Vibrator vibrator;
    private final StringBuilder logHistory = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        setContentView(R.layout.activity_main);

        tvBadge = findViewById(R.id.tv_badge);
        tvStatusDetails = findViewById(R.id.tv_status_details);
        tvLog = findViewById(R.id.tv_log);
        Button btnClear = findViewById(R.id.btn_clear);
        vibrator = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);

        btnClear.setOnClickListener(v -> {
            logHistory.setLength(0);
            tvLog.setText("");
        });

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter == null) {
            appendLog("[ERROR] NFC is not supported on this device!");
            tvBadge.setText("NO NFC HARDWARE");
            tvBadge.setTextColor(Color.RED);
            return;
        }

        if (!nfcAdapter.isEnabled()) {
            appendLog("[WARN] NFC is disabled! Please enable it in Settings.");
            tvBadge.setText("NFC DISABLED");
            tvBadge.setTextColor(Color.RED);
        } else {
            appendLog("[OK] NFC Adapter ready. Enabling Reader Mode...");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        enableNfcReader();
    }

    private void enableNfcReader() {
        if (nfcAdapter != null && nfcAdapter.isEnabled()) {
            try {
                int flags = NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;
                Bundle options = new Bundle();
                options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

                nfcAdapter.enableReaderMode(this, this, flags, options);
                tvBadge.setText("READER MODE: ACTIVE");
                tvBadge.setTextColor(Color.parseColor("#00E5FF"));
                tvStatusDetails.setText("Listening for hyprkey NFC...\nTap phone to PN532 antenna.");
                appendLog("[NFC] Reader Mode enabled.");
            } catch (Exception e) {
                appendLog("[ERROR] enableReaderMode failed: " + e.getMessage());
                tvBadge.postDelayed(this::enableNfcReader, 1000);
            }
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) {
            nfcAdapter.disableReaderMode(this);
            appendLog("[NFC] Reader Mode paused.");
        }
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        processTag(tag);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (tag != null) processTag(tag);
    }

    private void processTag(Tag tag) {
        byte[] id = tag.getId();
        String uidHex = bytesToHex(id);
        String[] techs = tag.getTechList();

        appendLog("\n========================================");
        appendLog(">>> TAG DETECTED: UID " + uidHex + " <<<");

        boolean hasIsoDep = false;
        StringBuilder sb = new StringBuilder("Techs: ");
        for (String t : techs) {
            String shortTech = t.substring(t.lastIndexOf('.') + 1);
            sb.append(shortTech).append(" ");
            if ("IsoDep".equals(shortTech)) hasIsoDep = true;
        }
        appendLog(sb.toString());

        NfcA nfcA = NfcA.get(tag);
        if (nfcA != null) {
            try {
                appendLog("NfcA ATQA: " + bytesToHex(nfcA.getAtqa()) + " | SAK: 0x" + String.format("%02X", nfcA.getSak()));
            } catch (Exception ignored) {}
        }

        if (hasIsoDep) {
            appendLog(">>> ISO-DEP (ISO 14443-4) PRESENT! <<<");
            runMultiAppletSuite(tag);
        } else {
            appendLog("[INFO] Physical tag without ISO-DEP.");
        }

        if (vibrator != null) vibrator.vibrate(80);
    }

    private byte[] transceiveApdu(IsoDep iso, byte[] apdu) throws IOException {
        byte[] rsp = iso.transceive(apdu);
        if (rsp == null) return null;

        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        while (rsp.length >= 2 && rsp[rsp.length - 2] == 0x61) {
            int rem = rsp[rsp.length - 1] & 0xFF;
            baos.write(rsp, 0, rsp.length - 2);
            byte le = (byte)(rem == 0 ? 0x00 : rem);
            byte[] getRspCmd = new byte[] { 0x00, (byte)0xC0, 0x00, 0x00, le };
            rsp = iso.transceive(getRspCmd);
            if (rsp == null) break;
        }
        if (rsp != null) {
            baos.write(rsp, 0, rsp.length);
        }
        return baos.toByteArray();
    }

    private void runMultiAppletSuite(Tag tag) {
        IsoDep iso = IsoDep.get(tag);
        if (iso == null) {
            appendLog("[ERROR] IsoDep is null!");
            return;
        }

        runOnUiThread(() -> {
            tvBadge.setText("RUNNING MULTI-APPLET SUITE...");
            tvBadge.setTextColor(Color.parseColor("#FFD600"));
        });

        int passedChecks = 0;
        int totalChecks = 16;
        long totalTime = 0;

        try {
            iso.connect();
            iso.setTimeout(3500);
            appendLog("[ISO-DEP] Connected! MaxTransceive: " + iso.getMaxTransceiveLength() + " bytes");

            // =========================================================================
            // SECTION 1: OpenPGP Card 3.4
            // =========================================================================
            appendLog("\n--- [1/3] OpenPGP Card 3.4 Suite ---");

            // 1. SELECT OpenPGP AID
            long t0 = System.currentTimeMillis();
            byte[] rsp = transceiveApdu(iso, OPENPGP_AID_SELECT);
            long dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [1/16] SELECT OpenPGP AID (%dms): %s", dt, bytesToHex(rsp)));
            if (isStatusOk(rsp)) {
                appendLog("         ✔ OpenPGP AID Selected (90 00)");
                passedChecks++;
            } else {
                appendLog("         ✘ SELECT OpenPGP AID failed!");
            }

            // 2. GET DATA 00 4F (AID)
            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, new byte[] { 0x00, (byte)0xCA, 0x00, 0x4F, 0x00 });
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [2/16] GET DATA 00 4F (AID) (%dms): %s", dt, bytesToHex(rsp)));
            if (isStatusOk(rsp) && rsp.length >= 18) {
                appendLog("         ✔ Full OpenPGP AID: " + bytesToHex(Arrays.copyOfRange(rsp, 0, rsp.length - 2)));
                passedChecks++;
            } else {
                appendLog("         ✘ GET DATA 00 4F failed!");
            }

            // 3. GET DATA 00 6E (Application Related Data)
            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, new byte[] { 0x00, (byte)0xCA, 0x00, 0x6E, 0x00 });
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [3/16] GET DATA 00 6E (App Data) (%dms): len=%dB SW=%02X%02X", dt, rsp.length,
                    rsp[rsp.length - 2], rsp[rsp.length - 1]));
            if (isStatusOk(rsp) && rsp[0] == 0x6E) {
                appendLog("         ✔ DO 6E Received OK");
                passedChecks++;
            } else {
                appendLog("         ✘ GET DATA 00 6E failed!");
            }

            // 4. GET DATA 00 C4 (PW Status Bytes)
            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, new byte[] { 0x00, (byte)0xCA, 0x00, (byte)0xC4, 0x00 });
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [4/16] GET DATA 00 C4 (PW Status) (%dms): %s", dt, bytesToHex(rsp)));
            if (isStatusOk(rsp)) {
                appendLog("         ✔ PW Status: " + bytesToHex(Arrays.copyOfRange(rsp, 0, rsp.length - 2)));
                passedChecks++;
            } else {
                appendLog("         ✘ GET DATA 00 C4 failed!");
            }

            // 5. GET DATA 00 C5 (Fingerprints - 60 bytes)
            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, new byte[] { 0x00, (byte)0xCA, 0x00, (byte)0xC5, 0x00 });
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [5/16] GET DATA 00 C5 (Fingerprints) (%dms): len=%dB", dt, rsp.length - 2));
            if (isStatusOk(rsp) && rsp.length - 2 == 60) {
                appendLog("         ✔ Fingerprints (Sig/Dec/Aut): 60B verified");
                passedChecks++;
            } else {
                appendLog("         ✘ Fingerprints length mismatch: " + (rsp.length - 2));
            }

            // 6. Read Public Key SIG (00 47 81 00 02 B6 00)
            t0 = System.currentTimeMillis();
            byte[] readPkApdu = new byte[] { 0x00, 0x47, (byte)0x81, 0x00, 0x02, (byte)0xB6, 0x00 };
            rsp = transceiveApdu(iso, readPkApdu);
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [6/16] Read SIG PubKey (%dms): len=%dB", dt, rsp.length));

            byte[] sigPubRaw = null;
            PublicKey sigPublicKey = null;
            if (isStatusOk(rsp)) {
                // Find tag 86: 86 41 04 ...
                for (int i = 0; i < rsp.length - 66; i++) {
                    if (rsp[i] == (byte)0x86 && rsp[i + 1] == 0x41 && rsp[i + 2] == 0x04) {
                        sigPubRaw = Arrays.copyOfRange(rsp, i + 2, i + 2 + 65);
                        break;
                    }
                }
                if (sigPubRaw != null) {
                    sigPublicKey = decodeEcPublicKey(sigPubRaw);
                    appendLog("         ✔ PubKey secp256r1 extracted: " + bytesToHex(sigPubRaw).substring(0, 24) + "...");
                    passedChecks++;
                } else {
                    appendLog("         ✘ PubKey format not recognized: " + bytesToHex(rsp));
                }
            } else {
                appendLog("         ✘ Read PubKey failed: " + bytesToHex(rsp));
            }

            // 7. VERIFY PW1 (123456)
            t0 = System.currentTimeMillis();
            byte[] verifyPw1Apdu = new byte[] { 0x00, 0x20, 0x00, (byte)0x81, 0x06, '1', '2', '3', '4', '5', '6' };
            rsp = transceiveApdu(iso, verifyPw1Apdu);
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [7/16] VERIFY PW1 (123456) (%dms): %s", dt, bytesToHex(rsp)));
            if (isStatusOk(rsp)) {
                appendLog("         ✔ PIN PW1 Accepted (90 00)");
                passedChecks++;
            } else {
                appendLog("         ✘ VERIFY PW1 failed!");
            }

            // 8. PSO: CDS (Compute Digital Signature) & Verify ECDSA signature
            byte[] pgpMsg = "hyprkey NFC OpenPGP Live Test Message".getBytes();
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] pgpDigest = sha.digest(pgpMsg);

            byte[] psoCdsApdu = new byte[5 + 32];
            psoCdsApdu[0] = 0x00; psoCdsApdu[1] = 0x2A; psoCdsApdu[2] = (byte)0x9E; psoCdsApdu[3] = (byte)0x9A;
            psoCdsApdu[4] = 0x20;
            System.arraycopy(pgpDigest, 0, psoCdsApdu, 5, 32);

            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, psoCdsApdu);
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [8/16] PSO: CDS Signature (%dms): len=%dB", dt, rsp.length));

            if (isStatusOk(rsp) && rsp.length >= 66 && sigPublicKey != null) {
                byte[] rawSig = Arrays.copyOfRange(rsp, 0, 64);
                byte[] derSig = rawEcdsaToDer(rawSig);

                Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(sigPublicKey);
                verifier.update(pgpMsg);
                boolean validSig = verifier.verify(derSig);

                if (validSig) {
                    appendLog("         ✔ OpenPGP ECDSA Signature CRYPTO VERIFIED!");
                    passedChecks++;
                } else {
                    appendLog("         ✘ Signature verification failed!");
                }
            } else {
                appendLog("         ✘ PSO: CDS failed: " + bytesToHex(rsp));
            }

            // =========================================================================
            // SECTION 2: Yubico OATH TOTP/HOTP
            // =========================================================================
            appendLog("\n--- [2/3] Yubico OATH Suite ---");

            // 9. SELECT OATH AID
            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, OATH_AID_SELECT);
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [9/16] SELECT OATH AID (%dms): %s", dt, bytesToHex(rsp)));
            if (isStatusOk(rsp)) {
                appendLog("         ✔ OATH Applet Selected (Version: " + bytesToHex(rsp) + ")");
                passedChecks++;
            } else {
                appendLog("         ✘ SELECT OATH AID failed!");
            }

            // 10. OATH CALCULATE_ALL (00 A4 00 01 0A 74 08 [timestamp])
            long nowSeconds = System.currentTimeMillis() / 1000L;
            long step = nowSeconds / 30L;
            byte[] challenge = ByteBuffer.allocate(8).putLong(step).array();
            byte[] calcAllApdu = new byte[5 + 10];
            calcAllApdu[0] = 0x00; calcAllApdu[1] = (byte)0xA4; calcAllApdu[2] = 0x00; calcAllApdu[3] = 0x01;
            calcAllApdu[4] = 0x0A;
            calcAllApdu[5] = 0x74;
            calcAllApdu[6] = 0x08;
            System.arraycopy(challenge, 0, calcAllApdu, 7, 8);

            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, calcAllApdu);
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [10/16] OATH CALCULATE_ALL (%dms): len=%dB", dt, rsp.length));
            if (isStatusOk(rsp) && rsp.length >= 8) {
                appendLog("          ✔ TOTP Calculated: " + bytesToHex(rsp));
                passedChecks++;
            } else {
                appendLog("          ✘ CALCULATE_ALL failed: " + bytesToHex(rsp));
            }

            // =========================================================================
            // SECTION 3: FIDO2 / WebAuthn / U2F
            // =========================================================================
            appendLog("\n--- [3/3] FIDO2 / WebAuthn Suite ---");

            // 11. SELECT FIDO AID
            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, FIDO_AID_SELECT);
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [11/16] SELECT FIDO AID (%dms): %s (%s)", dt, bytesToHex(rsp), bytesToAscii(rsp)));
            if (isStatusOk(rsp) && bytesToAscii(rsp).startsWith("U2F_V2")) {
                appendLog("          ✔ FIDO Selected (U2F_V2 returned)");
                passedChecks++;
            } else {
                appendLog("          ✘ SELECT FIDO AID failed!");
            }

            // 12. U2F VERSION
            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, new byte[] { 0x00, 0x03, 0x00, 0x00, 0x00 });
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [12/16] U2F_VERSION (%dms): %s", dt, bytesToAscii(rsp)));
            if (isStatusOk(rsp) && bytesToAscii(rsp).startsWith("U2F_V2")) {
                appendLog("          ✔ U2F_VERSION OK");
                passedChecks++;
            } else {
                appendLog("          ✘ U2F_VERSION failed!");
            }

            // 13. CTAP2 GET_INFO
            t0 = System.currentTimeMillis();
            rsp = transceiveApdu(iso, new byte[] { (byte)0x80, 0x10, 0x00, 0x00, 0x01, 0x04, 0x00 });
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [13/16] CTAP2 GET_INFO (%dms): len=%dB", dt, rsp.length));
            if (isStatusOk(rsp) && rsp[0] == 0x00) {
                appendLog("          ✔ CTAP2 GET_INFO OK");
                passedChecks++;
            } else {
                appendLog("          ✘ CTAP2 GET_INFO failed!");
            }

            // Test vectors for U2F Register & Authenticate
            byte[] testChallenge = sha.digest("HyprKey_NFC_Test_12345".getBytes());
            byte[] testAppId = sha.digest("https://hyprkey.local".getBytes());

            // 14. U2F REGISTER
            byte[] regApdu = new byte[5 + 64 + 1];
            regApdu[0] = 0x00; regApdu[1] = 0x01; regApdu[2] = 0x03; regApdu[3] = 0x00; regApdu[4] = 0x40;
            System.arraycopy(testChallenge, 0, regApdu, 5, 32);
            System.arraycopy(testAppId, 0, regApdu, 37, 32);
            regApdu[69] = 0x00;

            t0 = System.currentTimeMillis();
            byte[] regRsp = transceiveApdu(iso, regApdu);
            dt = System.currentTimeMillis() - t0;
            totalTime += dt;
            appendLog(String.format(Locale.US, "  [14/16] U2F_REGISTER (%dms): len=%dB", dt, regRsp.length));

            byte[] fidoUserPub = null;
            byte[] keyHandle = null;

            if (isStatusOk(regRsp) && regRsp.length > 67 && regRsp[0] == 0x05) {
                fidoUserPub = Arrays.copyOfRange(regRsp, 1, 66);
                int khLen = regRsp[66] & 0xFF;
                keyHandle = Arrays.copyOfRange(regRsp, 67, 67 + khLen);

                int certStart = 67 + khLen;
                int certLen = findDerCertLength(regRsp, certStart);
                if (certLen > 0) {
                    byte[] certBytes = Arrays.copyOfRange(regRsp, certStart, certStart + certLen);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                    int sigStart = certStart + certLen;
                    int sigLen = regRsp.length - 2 - sigStart;
                    byte[] sigBytes = Arrays.copyOfRange(regRsp, sigStart, sigStart + sigLen);

                    byte[] dataToVerify = new byte[1 + 32 + 32 + khLen + 65];
                    dataToVerify[0] = 0x00;
                    System.arraycopy(testAppId, 0, dataToVerify, 1, 32);
                    System.arraycopy(testChallenge, 0, dataToVerify, 33, 32);
                    System.arraycopy(keyHandle, 0, dataToVerify, 65, khLen);
                    System.arraycopy(fidoUserPub, 0, dataToVerify, 65 + khLen, 65);

                    Signature fidoVerifier = Signature.getInstance("SHA256withECDSA");
                    fidoVerifier.initVerify(cert.getPublicKey());
                    fidoVerifier.update(dataToVerify);
                    boolean attestValid = fidoVerifier.verify(sigBytes);

                    if (attestValid) {
                        appendLog("          ✔ Attestation Certificate & Signature CRYPTO VERIFIED!");
                        passedChecks++;
                    } else {
                        appendLog("          ✘ Attestation Signature Verification FAILED!");
                    }
                }
            } else {
                appendLog("          ✘ U2F_REGISTER failed: " + bytesToHex(regRsp));
            }

            // 15. U2F AUTHENTICATE (Check-Only)
            if (keyHandle != null) {
                byte[] authCheckApdu = new byte[5 + 64 + 1 + keyHandle.length + 1];
                authCheckApdu[0] = 0x00; authCheckApdu[1] = 0x02; authCheckApdu[2] = 0x07; authCheckApdu[3] = 0x00;
                authCheckApdu[4] = (byte)(64 + 1 + keyHandle.length);
                System.arraycopy(testChallenge, 0, authCheckApdu, 5, 32);
                System.arraycopy(testAppId, 0, authCheckApdu, 37, 32);
                authCheckApdu[69] = (byte)keyHandle.length;
                System.arraycopy(keyHandle, 0, authCheckApdu, 70, keyHandle.length);
                authCheckApdu[authCheckApdu.length - 1] = 0x00;

                t0 = System.currentTimeMillis();
                rsp = transceiveApdu(iso, authCheckApdu);
                dt = System.currentTimeMillis() - t0;
                totalTime += dt;
                appendLog(String.format(Locale.US, "  [15/16] U2F AUTH Check (%dms): %s", dt, bytesToHex(rsp)));
                if (rsp.length >= 2 && rsp[0] == 0x69 && rsp[1] == (byte)0x85) {
                    appendLog("          ✔ KeyHandle Recognized (69 85 Touch needed)");
                    passedChecks++;
                } else {
                    appendLog("          ✘ Check failed: " + bytesToHex(rsp));
                }
            }

            // 16. U2F AUTHENTICATE (Sign)
            if (keyHandle != null && fidoUserPub != null) {
                byte[] authSignApdu = new byte[5 + 64 + 1 + keyHandle.length + 1];
                authSignApdu[0] = 0x00; authSignApdu[1] = 0x02; authSignApdu[2] = 0x03; authSignApdu[3] = 0x00;
                authSignApdu[4] = (byte)(64 + 1 + keyHandle.length);
                System.arraycopy(testChallenge, 0, authSignApdu, 5, 32);
                System.arraycopy(testAppId, 0, authSignApdu, 37, 32);
                authSignApdu[69] = (byte)keyHandle.length;
                System.arraycopy(keyHandle, 0, authSignApdu, 70, keyHandle.length);
                authSignApdu[authSignApdu.length - 1] = 0x00;

                t0 = System.currentTimeMillis();
                rsp = transceiveApdu(iso, authSignApdu);
                dt = System.currentTimeMillis() - t0;
                totalTime += dt;
                appendLog(String.format(Locale.US, "  [16/16] U2F AUTH Sign (%dms): len=%dB", dt, rsp.length));

                if (isStatusOk(rsp) && rsp.length >= 7) {
                    byte upFlag = rsp[0];
                    byte[] sigBytes = Arrays.copyOfRange(rsp, 5, rsp.length - 2);

                    byte[] authDataToVerify = new byte[32 + 1 + 4 + 32];
                    System.arraycopy(testAppId, 0, authDataToVerify, 0, 32);
                    authDataToVerify[32] = upFlag;
                    authDataToVerify[33] = rsp[1];
                    authDataToVerify[34] = rsp[2];
                    authDataToVerify[35] = rsp[3];
                    authDataToVerify[36] = rsp[4];
                    System.arraycopy(testChallenge, 0, authDataToVerify, 37, 32);

                    PublicKey userPublicKey = decodeEcPublicKey(fidoUserPub);
                    Signature authVerifier = Signature.getInstance("SHA256withECDSA");
                    authVerifier.initVerify(userPublicKey);
                    authVerifier.update(authDataToVerify);
                    boolean authValid = authVerifier.verify(sigBytes);

                    if (authValid) {
                        appendLog("          ✔ Assertion Signature CRYPTO VERIFIED!");
                        passedChecks++;
                    } else {
                        appendLog("          ✘ Assertion verification failed!");
                    }
                } else {
                    appendLog("          ✘ Auth sign failed: " + bytesToHex(rsp));
                }
            }

            iso.close();
            appendLog("\n[ISO-DEP] All tests completed! Passed: " + passedChecks + "/" + totalChecks);

            final int finalPassed = passedChecks;
            final long finalTotalTime = totalTime;
            runOnUiThread(() -> {
                if (finalPassed == totalChecks) {
                    tvBadge.setText("✔ 100% PASS: OPENPGP + OATH + FIDO2 (" + finalPassed + "/" + totalChecks + ")");
                    tvBadge.setTextColor(Color.parseColor("#00E676"));
                    tvStatusDetails.setText(String.format(Locale.US, "All Applets Live & Verified over NFC!\nTotal APDU time: %d ms", finalTotalTime));
                    if (vibrator != null) vibrator.vibrate(new long[] { 0, 100, 100, 200 }, -1);
                } else {
                    tvBadge.setText("RESULT: " + finalPassed + "/" + totalChecks + " PASSED");
                    tvBadge.setTextColor(Color.parseColor("#FF9100"));
                    tvStatusDetails.setText("Passed " + finalPassed + " of " + totalChecks + " checks.");
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "Multi-applet suite error", e);
            appendLog("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            runOnUiThread(() -> {
                tvBadge.setText("EXCHANGE ERROR");
                tvBadge.setTextColor(Color.RED);
            });
        }
    }

    private static boolean isStatusOk(byte[] apduRsp) {
        if (apduRsp == null || apduRsp.length < 2) return false;
        return apduRsp[apduRsp.length - 2] == (byte)0x90 && apduRsp[apduRsp.length - 1] == 0x00;
    }

    private static byte[] rawEcdsaToDer(byte[] rawSig) {
        if (rawSig == null || rawSig.length != 64) return rawSig;
        byte[] rBytes = Arrays.copyOfRange(rawSig, 0, 32);
        byte[] sBytes = Arrays.copyOfRange(rawSig, 32, 64);
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        byte[] rDer = r.toByteArray();
        byte[] sDer = s.toByteArray();

        int totalLen = 2 + rDer.length + 2 + sDer.length;
        byte[] der = new byte[2 + totalLen];
        der[0] = 0x30;
        der[1] = (byte) totalLen;
        der[2] = 0x02;
        der[3] = (byte) rDer.length;
        System.arraycopy(rDer, 0, der, 4, rDer.length);
        int sOffset = 4 + rDer.length;
        der[sOffset] = 0x02;
        der[sOffset + 1] = (byte) sDer.length;
        System.arraycopy(sDer, 0, der, sOffset + 2, sDer.length);
        return der;
    }

    private static int findDerCertLength(byte[] buf, int offset) {
        if (offset + 4 >= buf.length) return -1;
        if (buf[offset] != 0x30) return -1;
        int lenByte = buf[offset + 1] & 0xFF;
        if ((lenByte & 0x80) == 0) {
            return 2 + lenByte;
        }
        int numLenBytes = lenByte & 0x7F;
        if (numLenBytes == 1) {
            return 3 + (buf[offset + 2] & 0xFF);
        } else if (numLenBytes == 2) {
            return 4 + (((buf[offset + 2] & 0xFF) << 8) | (buf[offset + 3] & 0xFF));
        }
        return -1;
    }

    private static PublicKey decodeEcPublicKey(byte[] pubKeyBytes) throws Exception {
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        System.arraycopy(pubKeyBytes, 1, x, 0, 32);
        System.arraycopy(pubKeyBytes, 33, y, 0, 32);
        ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, ecSpec));
    }

    private void appendLog(String msg) {
        String timeStr = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(new Date());
        String fullMsg = "[" + timeStr + "] " + msg;
        Log.i(TAG, msg);

        runOnUiThread(() -> {
            logHistory.append(fullMsg).append("\n");
            tvLog.setText(logHistory.toString());
        });
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X ", b));
        return sb.toString().trim();
    }

    private static String bytesToAscii(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            if (b >= 32 && b <= 126) sb.append((char)b);
            else sb.append('.');
        }
        return sb.toString();
    }
}
