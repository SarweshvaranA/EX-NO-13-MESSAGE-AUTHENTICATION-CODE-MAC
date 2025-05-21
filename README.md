# EX-NO-13-MESSAGE-AUTHENTICATION-CODE-MAC
## Name:SARWESHVARAN A
## Regno:212223230198

## AIM:
To implement MESSAGE AUTHENTICATION CODE(MAC)

## ALGORITHM:

1. Message Authentication Code (MAC) is a cryptographic technique used to verify the integrity and authenticity of a message by using a secret key.

2. Initialization:
   - Choose a cryptographic hash function \( H \) (e.g., SHA-256) and a secret key \( K \).
   - The message \( M \) to be authenticated is input along with the secret key \( K \).

3. MAC Generation:
   - Compute the MAC by applying the hash function to the combination of the message \( M \) and the secret key \( K \): 
     \[
     \text{MAC}(M, K) = H(K || M)
     \]
     where \( || \) denotes concatenation of \( K \) and \( M \).

4. Verification:
   - The recipient, who knows the secret key \( K \), computes the MAC using the received message \( M \) and the same hash function.
   - The recipient compares the computed MAC with the received MAC. If they match, the message is authentic and unchanged.

5. Security: The security of the MAC relies on the secret key \( K \) and the strength of the hash function \( H \), ensuring that an attacker cannot forge a valid MAC without knowledge of the key.

## Program:
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAC_SIZE 32  // MAC size in bytes

// Function to compute a simple MAC using XOR
void compute_mac(const char *key, const char *message, unsigned char *mac) {
    size_t key_len = strlen(key);
    size_t msg_len = strlen(message);

    for (int i = 0; i < MAC_SIZE; i++) {
        mac[i] = key[i % key_len] ^ message[i % msg_len];
    }
}

// Helper function to convert hex string to bytes
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != MAC_SIZE * 2) return 0; // wrong length

    for (size_t i = 0; i < MAC_SIZE; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bytes[i]) != 1) {
            return 0;
        }
    }
    return 1;
}

int main() {
    char key[256], message[256], received_mac_hex[MAC_SIZE * 2 + 1];
    unsigned char mac[MAC_SIZE], received_mac[MAC_SIZE];

    // Step 1: Input secret key
    printf("Enter the secret key: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = 0; // remove newline

    // Step 2: Input the message
    printf("Enter the message: ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = 0; // remove newline

    // Step 3: Compute the MAC
    compute_mac(key, message, mac);

    // Step 4: Display computed MAC in hexadecimal
    printf("Computed MAC (in hex): ");
    for (int i = 0; i < MAC_SIZE; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");

    // Step 5: Input received MAC
    printf("Enter the received MAC (as hex): ");
    fgets(received_mac_hex, sizeof(received_mac_hex), stdin);
    received_mac_hex[strcspn(received_mac_hex, "\n")] = 0; // remove newline

    if (!hex_to_bytes(received_mac_hex, received_mac, MAC_SIZE)) {
        printf("Invalid hex format.\n");
        return 1;
    }

    // Step 6: Compare MACs
    if (memcmp(mac, received_mac, MAC_SIZE) == 0) {
        printf("MAC verification successful. Message is authentic.\n");
    } else {
        printf("MAC verification failed. Message is not authentic.\n");
    }

    return 0;
}


```



## Output:
![image](https://github.com/user-attachments/assets/df840088-030e-484b-945d-7462c0b9f2f7)


## Result:
The program is executed successfully.
