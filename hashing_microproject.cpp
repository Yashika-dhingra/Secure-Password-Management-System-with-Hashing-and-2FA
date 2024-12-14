#include <iostream>
#include <string>
#include <random>
#include <openssl/sha.h> 
#include <iomanip>
#include <sstream>

using namespace std; 

// computing SHA-256 hash
string computeHash(const string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH]; 
    SHA256((unsigned char *)input.c_str(), input.size(), hash);

    // Convert hash to a readable hexadecimal string
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int computeChecksum(const string &input) {
    int checksum = 0;
    for (char ch : input) {
        checksum += static_cast<int>(ch); // Sum of ASCII values
    }
    return checksum % 256; // Returning checksum as a single byte value
}

bool validatePassword(const string &password) {
    if (password.length() < 8) {
        cout << "Password must be at least 8 characters long.\n";
        return false;
    }
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    for (char ch : password) {
        if (isupper(ch)) hasUpper = true;
        if (islower(ch)) hasLower = true;
        if (isdigit(ch)) hasDigit = true;
        if (ispunct(ch)) hasSpecial = true;
    }
    if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) {
        cout << "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.\n";
        return false;
    }
    return true;
}

int generateOTP() {
    std::default_random_engine rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(100000, 999999); // 6-digit OTP
    return dist(rng);
}

bool verifyOTP(int generatedOTP) {
    int enteredOTP;
    cout << "Enter the OTP sent to your device: ";
    cin >> enteredOTP;
    return enteredOTP == generatedOTP;
}

void passwordVerification() {
    string password;
    cout << "Enter a password to hash and store securely: ";
    cin >> password;

    while (!validatePassword(password)) {
        cout << "Please enter a stronger password: ";
        cin >> password;
    }

    string hashedPassword = computeHash(password);
    int checksum = computeChecksum(password);

    cout << "Password hashed and stored as: " << hashedPassword << endl;
    cout << "Checksum stored as: " << checksum << endl;

    string inputPassword;
    cout << "\nEnter the password to verify: ";
    cin >> inputPassword;

    string hashedInput = computeHash(inputPassword);
    int checksumInput = computeChecksum(inputPassword);

    if (hashedInput == hashedPassword && checksumInput == checksum) {
        cout << "Password verification successful! Data integrity verified.\n";

        int generatedOTP = generateOTP();
        cout << "Generated OTP: " << generatedOTP << endl; 
        if (verifyOTP(generatedOTP)) {
            cout << "Two-Factor Authentication successful!\n";
        } else {
            cout << "Two-Factor Authentication failed! Access denied.\n";
        }
    } else {
        cout << "Password verification failed or data integrity compromised!\n";
    }
}

int main() {
    cout << "=== PASSWORD HANDLING ===\n" << endl;
    passwordVerification();
    return 0;
}
