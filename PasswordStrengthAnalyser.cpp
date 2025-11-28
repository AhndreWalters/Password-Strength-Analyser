#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <ctime>

// Hash Table for storing common passwords
class PasswordHashTable {
private:
    struct Node {
        std::string password;
        Node* next;
        Node(const std::string& pwd) : password(pwd), next(nullptr) {}
    };
    
    std::vector<Node*> table;
    int capacity;
    
    int hashFunction(const std::string& password) {
        int hash = 0;
        for (char c : password) {
            hash = (hash * 31 + static_cast<unsigned char>(c)) % capacity;
        }
        return hash;
    }
    
public:
    PasswordHashTable(int cap = 100) : capacity(cap) {
        table.resize(capacity, nullptr);
    }
    
    void addPassword(const std::string& password) {
        if (password.empty()) return;
        int index = hashFunction(password);
        Node* newNode = new Node(password);
        newNode->next = table[index];
        table[index] = newNode;
    }
    
    bool contains(const std::string& password) {
        if (password.empty()) return false;
        int index = hashFunction(password);
        Node* current = table[index];
        
        while (current != nullptr) {
            if (current->password == password) {
                return true;
            }
            current = current->next;
        }
        return false;
    }
};

// Trie for dictionary word checking
class DictionaryTrie {
private:
    struct TrieNode {
        std::vector<TrieNode*> children;
        bool isEndOfWord;
        TrieNode() : children(128, nullptr), isEndOfWord(false) {}
    };
    
    TrieNode* root;
    
public:
    DictionaryTrie() {
        root = new TrieNode();
    }
    
    void insert(const std::string& word) {
        if (word.empty()) return;
        TrieNode* current = root;
        for (char c : word) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 128) continue;
            if (current->children[uc] == nullptr) {
                current->children[uc] = new TrieNode();
            }
            current = current->children[uc];
        }
        current->isEndOfWord = true;
    }
    
    std::vector<std::string> findWordsInPassword(const std::string& password) {
        std::vector<std::string> foundWords;
        if (password.empty()) return foundWords;
        
        for (size_t i = 0; i < password.length(); i++) {
            TrieNode* current = root;
            std::string currentWord;
            for (size_t j = i; j < password.length(); j++) {
                unsigned char uc = static_cast<unsigned char>(password[j]);
                if (uc >= 128 || current->children[uc] == nullptr) break;
                
                current = current->children[uc];
                currentWord += password[j];
                
                if (current->isEndOfWord && currentWord.length() >= 3) {
                    foundWords.push_back(currentWord);
                }
            }
        }
        return foundWords;
    }
};

// Password Generator with Fisher-Yates Shuffle Algorithm
class PasswordGenerator {
private:
    std::vector<char> uppercase = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};
    std::vector<char> lowercase = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'};
    std::vector<char> digits = {'0','1','2','3','4','5','6','7','8','9'};
    std::vector<char> special = {'!','@','#','$','%','^','&','*','(',')','-','_','=','+'};
    
    // Fisher-Yates shuffle algorithm - O(n) time complexity
    void shuffleVector(std::vector<char>& vec) {
        for (int i = vec.size() - 1; i > 0; i--) {
            int j = rand() % (i + 1);
            std::swap(vec[i], vec[j]);
        }
    }
    
public:
    std::string generateStrongPassword(int length = 16) {
        std::string password;
        
        // Ensure at least one of each type
        password += uppercase[rand() % uppercase.size()];
        password += lowercase[rand() % lowercase.size()];
        password += digits[rand() % digits.size()];
        password += special[rand() % special.size()];
        
        // Fill remaining characters randomly
        std::vector<char> allChars;
        allChars.insert(allChars.end(), uppercase.begin(), uppercase.end());
        allChars.insert(allChars.end(), lowercase.begin(), lowercase.end());
        allChars.insert(allChars.end(), digits.begin(), digits.end());
        allChars.insert(allChars.end(), special.begin(), special.end());
        
        shuffleVector(allChars);
        
        while (password.length() < length) {
            password += allChars[rand() % allChars.size()];
        }
        
        // Final shuffle using Fisher-Yates algorithm
        std::vector<char> temp(password.begin(), password.end());
        shuffleVector(temp);
        return std::string(temp.begin(), temp.end());
    }
};

// Main Password Analyser
class PasswordStrengthAnalyser {
private:
    PasswordHashTable commonPasswords;
    DictionaryTrie dictionary;
    
public:
    PasswordStrengthAnalyser() {
        initializeCommonPasswords();
        initializeDictionary();
    }
    
    void initializeCommonPasswords() {
        std::vector<std::string> weakPasswords = {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "sunshine", "password1",
            "12345678", "123456789", "12345", "1234567", "1234567890",
            "abc123", "football", "master", "hello", "freedom"
        };
        
        for (const auto& pwd : weakPasswords) {
            commonPasswords.addPassword(pwd);
        }
    }
    
    void initializeDictionary() {
        std::vector<std::string> commonWords = {
            "password", "admin", "user", "login", "secret",
            "hello", "welcome", "qwerty", "keyboard", "computer",
            "system", "account", "access", "security", "network"
        };
        
        for (const auto& word : commonWords) {
            dictionary.insert(word);
        }
    }
    
    struct StrengthResult {
        int score;
        std::string strength;
        std::vector<std::string> feedback;
    };
    
    StrengthResult analysePassword(const std::string& password) {
        StrengthResult result;
        result.score = 0;
        result.feedback.clear();
        
        if (password.empty()) {
            result.strength = "Very Weak";
            result.feedback.push_back("✗ Password cannot be empty");
            return result;
        }
        
        // Length check
        if (password.length() >= 16) {
            result.score += 4;
            result.feedback.push_back("✓ Excellent password length (16+ characters)");
        } else if (password.length() >= 12) {
            result.score += 3;
            result.feedback.push_back("✓ Good password length (12+ characters)");
        } else if (password.length() >= 8) {
            result.score += 2;
            result.feedback.push_back("✓ Acceptable password length (8+ characters)");
        } else {
            result.feedback.push_back("✗ Password too short (minimum 8 characters recommended)");
        }
        
        // Character variety
        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
        
        for (char c : password) {
            if (std::isupper(static_cast<unsigned char>(c))) hasUpper = true;
            else if (std::islower(static_cast<unsigned char>(c))) hasLower = true;
            else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit = true;
            else hasSpecial = true;
        }
        
        if (hasUpper && hasLower) {
            result.score += 1;
            result.feedback.push_back("✓ Contains both uppercase and lowercase letters");
        } else {
            result.feedback.push_back("✗ Include both uppercase and lowercase letters");
        }
        
        if (hasDigit) {
            result.score += 1;
            result.feedback.push_back("✓ Contains numbers");
        } else {
            result.feedback.push_back("✗ Include numbers");
        }
        
        if (hasSpecial) {
            result.score += 2;
            result.feedback.push_back("✓ Contains special characters");
        } else {
            result.feedback.push_back("✗ Include special characters");
        }
        
        // Check common passwords
        if (commonPasswords.contains(password)) {
            result.score = 0;
            result.feedback.push_back("✗ This is a very common password");
        }
        
        // Dictionary word check
        bool hasLetters = false;
        for (char c : password) {
            if (std::isalpha(static_cast<unsigned char>(c))) {
                hasLetters = true;
                break;
            }
        }
        
        if (hasLetters) {
            auto dictionaryWords = dictionary.findWordsInPassword(password);
            if (!dictionaryWords.empty()) {
                result.score = std::max(0, result.score - 2);
                result.feedback.push_back("✗ Avoid using dictionary words");
            }
        }
        
        // Long password bonus
        if (password.length() > 20) {
            result.score += 2;
            result.feedback.push_back("✓ Bonus for very long password");
        }
        
        // Determine strength
        if (result.score >= 9) result.strength = "Very Strong";
        else if (result.score >= 7) result.strength = "Strong";
        else if (result.score >= 5) result.strength = "Moderate";
        else if (result.score >= 3) result.strength = "Weak";
        else result.strength = "Very Weak";
        
        return result;
    }
};

int main() {
    // Initialize random seed for password generation
    srand(static_cast<unsigned int>(time(0)));
    
    PasswordStrengthAnalyser analyser;
    PasswordGenerator generator;
    
    std::cout << "~ Password Strength Analyser ~" << std::endl;
    std::cout << "Commands: 'analyse', 'generate', 'quit'" << std::endl;
    
    std::string command;
    while (true) {
        std::cout << "\nEnter command: ";
        std::getline(std::cin, command);
        
        if (command == "quit") break;
        else if (command == "generate") {
            std::string strongPassword = generator.generateStrongPassword();
            std::cout << "Generated password: " << strongPassword << std::endl;
            
            // Auto-analyse the generated password
            auto result = analyser.analysePassword(strongPassword);
            std::cout << "Strength: " << result.strength << " (Score: " << result.score << "/10)" << std::endl;
        }
        else if (command == "analyse") {
            std::cout << "Enter password to analyse: ";
            std::string password;
            std::getline(std::cin, password);
            
            auto result = analyser.analysePassword(password);
            
            std::cout << "\nStrength: " << result.strength << " (Score: " << result.score << "/10)" << std::endl;
            std::cout << "Analysis:" << std::endl;
            for (const auto& feedback : result.feedback) {
                std::cout << "  " << feedback << std::endl;
            }
        }
        else {
            std::cout << "Unknown command. Use 'analyse', 'generate', or 'quit'" << std::endl;
        }
    }
    
    std::cout << "Thank you for using this password strength analyser!" << std::endl;
    return 0;
}