#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// Node structure for the hash map
typedef struct Node {
    char key[100];
    struct Node* next;
} Node;

// Hash map structure
typedef struct {
    Node** buckets;
    size_t size;
} HashMap;

#define FILTER_SIZE 1800 // Adjust the size as needed
#define NUM_HASH_FUNCTIONS 3 // Number of hash functions
#define SCORE_THRESHOLD 0.3 // Adjust as needed

unsigned char bloom_filter[FILTER_SIZE / 8] = {0}; // Initialize with all 0s

unsigned long hash_with_probe(const char *str, int probe) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    // Quadratic probing: move to the next slot using a quadratic function
    return (hash + probe * probe) % FILTER_SIZE;
}

bool is_spam_keyword_bloom(const char *keyword) {
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        unsigned long h = hash_with_probe(keyword, i);
        if ((bloom_filter[h / 8] & (1 << (h % 8))) == 0) {
            return false; // If any bit is not set, it's not in the Bloom filter
        }
    }
    return true; // All bits are set, so the keyword may be in the filter
}

void add_spam_keyword(const char *keyword) {
    for (int i = 0; i < NUM_HASH_FUNCTIONS; i++) {
        unsigned long h = hash_with_probe(keyword, i);
        bloom_filter[h / 8] |= (1 << (h % 8));
    }
}

void add_spam_keywords_from_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    char line[100]; // Adjust the buffer size as needed
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0'; // Remove trailing newline character
        if (line[0] != '\0') { // Skip empty lines
            add_spam_keyword(line);
        }
    }

    fclose(file);
}

typedef Node* NodePtr;

HashMap* create_hash_map(size_t size) {
    HashMap* map = (HashMap*)malloc(sizeof(HashMap));
    if (map == NULL) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }

    map->buckets = (NodePtr*)malloc(sizeof(NodePtr) * size);
    if (map->buckets == NULL) {
        perror("Memory allocation error");
        free(map);
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < size; i++) {
        map->buckets[i] = NULL;
    }

    map->size = size;

    return map;
}

void insert_into_hash_map(HashMap* map, const char* key) {
    size_t index = hash_with_probe(key, 0) % map->size;

    Node* newNode = (Node*)malloc(sizeof(Node));
    if (newNode == NULL) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }

    strncpy(newNode->key, key, sizeof(newNode->key));
    newNode->next = map->buckets[index];
    map->buckets[index] = newNode;
}

bool search_in_hash_map(HashMap* map, const char* key) {
    size_t index = hash_with_probe(key, 0) % map->size;

    Node* current = map->buckets[index];
    while (current != NULL) {
        if (strcmp(key, current->key) == 0) {
            return true; // Key found in hash map
        }
        current = current->next;
    }

    return false; // Key not found in hash map
}

void remove_from_hash_map(HashMap* map, const char* key) {
    size_t index = hash_with_probe(key, 0) % map->size;

    Node* current = map->buckets[index];
    Node* prev = NULL;

    while (current != NULL) {
        if (strcmp(key, current->key) == 0) {
            if (prev == NULL) {
                // The key to be removed is in the first node
                map->buckets[index] = current->next;
            } else {
                prev->next = current->next;
            }

            free(current);
            return; // Key found and removed
        }

        prev = current;
        current = current->next;
    }
}

void destroy_hash_map(HashMap* map) {
    for (size_t i = 0; i < map->size; i++) {
        Node* current = map->buckets[i];
        while (current != NULL) {
            Node* temp = current;
            current = current->next;
            free(temp);
        }
    }

    free(map->buckets);
    free(map);
}

bool is_whitelisted(HashMap* whitelist, const char *email_address) {
    return search_in_hash_map(whitelist, email_address);
}

bool is_blacklisted(HashMap* blacklist, const char *email_address) {
    return search_in_hash_map(blacklist, email_address);
}

void add_to_whitelist(HashMap* whitelist, const char* email_address) {
    // Append the email address to the whitelist text file
    FILE *file = fopen("whitelist.txt", "a");
    if (file == NULL) {
        perror("Error opening whitelist file");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "%s\n", email_address);
    fclose(file);

    // Insert the email into the whitelist hash map
    insert_into_hash_map(whitelist, email_address);

    printf("Email address added to whitelist: %s\n", email_address);
}

void add_to_blacklist(HashMap* blacklist, const char* email_address) {
    // Append the email address to the blacklist text file
    FILE *file = fopen("blacklist.txt", "a");
    if (file == NULL) {
        perror("Error opening blacklist file");
        exit(EXIT_FAILURE);
    }
    fprintf(file, "%s\n", email_address);
    fclose(file);

    // Insert the email into the blacklist hash map
    insert_into_hash_map(blacklist, email_address);

    printf("Email address added to blacklist: %s\n", email_address);
}

void remove_from_both_maps(HashMap* whitelist, HashMap* blacklist, const char* email_address) {
    // Remove from whitelist
    remove_from_hash_map(whitelist, email_address);

    // Remove from blacklist
    remove_from_hash_map(blacklist, email_address);

    // Remove from whitelist text file
    FILE *whitelistFile = fopen("whitelist.txt", "r");
    FILE *tempWhitelistFile = fopen("whitelist_temp.txt", "w");

    if (whitelistFile == NULL || tempWhitelistFile == NULL) {
        perror("Error opening files");
        exit(EXIT_FAILURE);
    }

    char line[100];
    while (fgets(line, sizeof(line), whitelistFile)) {
        line[strcspn(line, "\n")] = '\0'; // Remove trailing newline character

        if (strcmp(line, email_address) != 0) {
            fprintf(tempWhitelistFile, "%s\n", line);
        }
    }

    fclose(whitelistFile);
    fclose(tempWhitelistFile);

    remove("whitelist.txt");
    rename("whitelist_temp.txt", "whitelist.txt");

    // Remove from blacklist text file
    FILE *blacklistFile = fopen("blacklist.txt", "r");
    FILE *tempBlacklistFile = fopen("blacklist_temp.txt", "w");

    if (blacklistFile == NULL || tempBlacklistFile == NULL) {
        perror("Error opening files");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof(line), blacklistFile)) {
        line[strcspn(line, "\n")] = '\0'; // Remove trailing newline character

        if (strcmp(line, email_address) != 0) {
            fprintf(tempBlacklistFile, "%s\n", line);
        }
    }

    fclose(blacklistFile);
    fclose(tempBlacklistFile);

    remove("blacklist.txt");
    rename("blacklist_temp.txt", "blacklist.txt");

    printf("Email address removed from both whitelist and blacklist: %s\n", email_address);
}



bool is_spam_email(const char *email_content, const char *email_address, HashMap* whitelist, HashMap* blacklist) {
    bool isWhitelisted = is_whitelisted(whitelist, email_address);
    bool isBlacklisted = is_blacklisted(blacklist, email_address);

    if (isWhitelisted && isBlacklisted) {
        // Email is present in both whitelist and blacklist
        printf("This email address is present in both whitelist and blacklist. Choose an action:\n");
        printf("1. Remove from both whitelist and blacklist.\n");
        printf("2. Add to whitelist.\n");
        printf("3. Add to blacklist.\n");
        printf("Enter your choice (1, 2, or 3): ");

        int choice;
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                remove_from_both_maps(whitelist, blacklist, email_address);
                break;
            case 2:
                remove_from_both_maps(whitelist, blacklist, email_address);
                add_to_whitelist(whitelist, email_address);
                return false;
                break;
            case 3:
                remove_from_both_maps(whitelist, blacklist, email_address);
                add_to_blacklist(blacklist, email_address);
                return true;
                break;
            default:
                printf("Invalid choice. Email address not removed or added.\n");
        }

    }
     bool isWhitelisted1 = is_whitelisted(whitelist, email_address);
    bool isBlacklisted1 = is_blacklisted(blacklist, email_address);


    if (isWhitelisted1) {
        printf("Email address is whitelisted. Not spam.\n");
        return false; // Email address is whitelisted
    }

    if (isBlacklisted1) {
        printf("Email address is blacklisted. Spam!\n");
        return true; // Email address is blacklisted
    }

    // Tokenize the email content and check each token against the Bloom filter
    char *token = strtok((char *)email_content, " \t\n\r\f\v.,;:!?'\"()[]{}<>");
    double totalScore = 0.0;

    while (token != NULL) {
        // Convert the token to lowercase for case-insensitive matching
        for (int i = 0; token[i]; i++) {
            token[i] = tolower(token[i]);
        }

        if (is_spam_keyword_bloom(token)) {
            printf("Potential spam keyword detected: %s\n", token);
            totalScore += 0.1; // Increase the score for each matched keyword
        }
        token = strtok(NULL, " \t\n\r\f\v.,;:!?'\"()[]{}<>");
    }

    // Adjust the threshold score as needed
    if (totalScore >= SCORE_THRESHOLD) {
        printf("Potential spam detected for email address: %s\n", email_address);
        printf("Is this email spam? (1 for Yes, 0 for No): ");
        int isSpam;
        scanf("%d", &isSpam);

        if (isSpam) {
            add_to_blacklist(blacklist, email_address);
            return true;
        } else {
            add_to_whitelist(whitelist, email_address);
            return false;
        }

        return true; // It's potential spam
    }

    printf("Not spam for email address: %s\n", email_address);
    return false; // Not spam
}

void load_emails_into_hash_map(HashMap* map, const char* filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    char line[100]; // Adjust the buffer size as needed
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0'; // Remove trailing newline character
        if (line[0] != '\0') { // Skip empty lines
            insert_into_hash_map(map, line);
        }
    }

    fclose(file);
}

int main() {
    // Initialize the Bloom filter with 0s
    memset(bloom_filter, 0, sizeof(bloom_filter));

    // Create and populate the hash maps for whitelist and blacklist
    printf("Enter the filename for the whitelist: ");
    char whitelist_filename[100];
    scanf("%s", whitelist_filename);
    HashMap *whitelist = create_hash_map(100);
    load_emails_into_hash_map(whitelist, whitelist_filename);

    printf("Enter the filename for the blacklist: ");
    char blacklist_filename[100];
    scanf("%s", blacklist_filename);
    HashMap *blacklist = create_hash_map(100);
    load_emails_into_hash_map(blacklist, blacklist_filename);

    // Load spam keywords into the Bloom filter
    add_spam_keywords_from_file("spam_keywords.txt");

    // Sample email content and address
    char email_address[100];
    char email_content[1000]; // Adjust the buffer size as needed
    
    printf("Enter the email address: ");
    scanf("%s", email_address);

    printf("Enter the email content: ");
    scanf(" %[^\n]s", email_content);

    // Check if the email is spam
    if (is_spam_email(email_content, email_address, whitelist, blacklist)) {
        printf("The email is spam.\n");
    } else {
        printf("The email is not spam.\n");
    }

    // Clean up the hash maps
    destroy_hash_map(whitelist);
    destroy_hash_map(blacklist);

    return 0;
}

