#include "M5Cardputer.h"
#include "USB.h"
#include "USBHIDKeyboard.h"
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <SD.h>
#include <SPI.h>

// CRYPTO LIBRARIES
#include <AES.h>
#include <CBC.h>
#include <SHA256.h>

// --- SD Card Pin Definitions (M5Cardputer Specific) ---
#define SD_SPI_SCK_PIN 40
#define SD_SPI_MISO_PIN 39
#define SD_SPI_MOSI_PIN 14
#define SD_SPI_CS_PIN 12

// --- MISSING HID CONSTANT DEFINITIONS (FIX FOR COMPILATION ERROR) ---
#define KEY_DELETE 76
#define KEY_UP_ARROW 0x52
#define KEY_DOWN_ARROW 0x51
#define KEY_LEFT_ARROW 0x50
#define KEY_RIGHT_ARROW 0x4F
#define KEY_ESC 41
#define KEY_MOD_LSHIFT 0x02
#define KEY_MOD_RSHIFT 0x20
#define KEY_BACKSPACE 0x2a 
// -------------------------------------------------------------------

// Define the USB Keyboard object globally
USBHIDKeyboard Keyboard;

// --- State Definitions ---
enum State {
    STATE_KEYBOARD,
    STATE_PROMPT,
    STATE_TOP_MENU, // New state for the top-level menu
    STATE_PASS_MENU, // Password list menu (formerly STATE_MAIN_MENU)
    STATE_PASS_EDIT_MENU,
    STATE_NOTE_MENU, // Note list menu (Placeholder for future note functionality)
    STATE_CHANGE_MASTER
};

// Set the initial state
State currentState = STATE_KEYBOARD;

// --- Configuration Constants ---
const int BUTTON_HEIGHT = 20;
const int MAX_VISIBLE_BUTTONS = 5;
String MASTER_PASSWORD = "m5pass"; 
const unsigned long FN_CTRL_DEBOUNCE_MS = 500;
// Timer Constant: 15 seconds
const uint32_t MENU_TIMEOUT_MS = 15000; 

// Key Repeat Constants
const uint32_t KEY_REPEAT_DELAY_MS = 500; 
const uint32_t KEY_REPEAT_RATE_MS = 75; 

// SD Card Constants
const char* SD_FILE_PATH = "/vault.txt";

// CRYPTO CONSTANTS
const size_t AES_KEY_SIZE = 32;
const size_t AES_BLOCK_SIZE = 16;
const size_t HMAC_TAG_SIZE = SHA256::HASH_SIZE; 
const size_t PBKDF2_ITERATIONS = 10000;

// Fixed Initialization Vector (IV) and Salt
uint8_t IV[AES_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
const uint8_t PBKDF2_SALT[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};


// --- Data Structure ---
struct PasswordEntry {
    String label;
    String username;
    String password;
};

// Data Structure for Top Menu
struct MenuEntry {
    String label;
    State targetState;
    void (*action)(); // Function pointer for custom actions
};

M5Canvas canvas(&M5Cardputer.Display);

// Top-Level Menu Items
std::vector<MenuEntry> TopMenuItems = {
    {"!! Change Vault Pass !!", STATE_CHANGE_MASTER, nullptr},
    {"-- Notes --", STATE_NOTE_MENU, nullptr},
    {"-- Passwords --", STATE_PASS_MENU, nullptr},
};

// Password Data (Now only holds entries, without menu control entries)
std::vector<PasswordEntry> PassEntries;

// Internal Menu Items for Passwords (Dynamically generated)
std::vector<String> PassMenuDisplayItems; 


// --- Global Indexes and Offsets ---
int SelectedMenuIndex = 0; // Used for all list menus (Top, Pass, Note)
int PassDataIndex = 0; // Used for the Edit Menu fields
int currentEditIndex = -1; // Index into PassEntries being edited
int visibleOffset = 0; // Used for scrolling list menus

unsigned long lastFnCtrlTime = 0; 

// GLOBAL FLAG: Tracks SD Card Status
bool isSDInitialized = false; 

// Global AES/SHA objects 
CBC<AES256> aes_cbc; 
SHA256 sha256_hmac;

// Global variable to hold the raw encrypted data from the file
String ENCRYPTED_VAULT_STRING = "";

// Timer Management Globals (Millis Polling)
unsigned long lastActivityTime = 0; 

// Key Repeat Globals
unsigned long lastKeyPressTime = 0;
unsigned long lastKeyRepeatTime = 0;
uint8_t repeatingKey = 0; 
std::vector<uint8_t> currentPressedKeys; 


// =================================================================
// 1. FUNCTION PROTOTYPES (Declarations)
// =================================================================

// UI/Menu Prototypes
void drawPromptScreen(const char* title, const String& input_masked, const char* status_msg);
void drawMenuList(const String& title, const std::vector<String>& items, int selectedIndex);
void drawTopMenu();
void drawPassMenu();
void drawPassEditMenu();
void drawNoteMenu(); 

// Logic/State Prototypes
void runKeyboard();
void runPrompt();
void runTopMenu();
void runPassMenu();
void runNoteMenu();
void runPassEditMenu();
void runChangeMaster();

// Modular Logic Core
bool handleMenuAction(State currentState, int selectedIndex);
bool handleMenuNavigation(const std::vector<String>& items, int& selectedIndex, void (*drawFunction)()); 
void buildPassMenuDisplayItems(); // New helper to manage dynamic list

// Helper Prototypes
String getEntryInput(const char* prompt);
String getPasswordInput(const char* prompt, const String& expected_password = "");
bool checkForUniversalExit(); 
void sendEntryOverUSB(const String& data);
void timeoutToKeyboard();
void startMenuTimer();
void resetMenuTimer();
void playBeep(int freq, int duration);

// Crypto/Storage Prototypes
void deriveKey(const String& masterPass, uint8_t* key_out);
String encryptAES(const String& data, const String& masterPass);
String decryptAES(const String& encryptedData, const String& masterPass);
void initializeVaultFile(); 
bool saveData();
bool loadEncryptedData();
String generateStrongPassword();


// =================================================================
// 2. SETUP 
// =================================================================
void setup() {
    auto cfg = M5.config();
    M5Cardputer.Display.setBrightness(0);
    M5Cardputer.Display.clear();
    M5Cardputer.begin(cfg);

    // --- Initialize Random Seed using Analog Noise (Entropy) ---
    pinMode(1, INPUT);
    long randomSeedValue = analogRead(1); 
    srand(randomSeedValue);

    // Initialize USB/HID
    Keyboard.begin();
    USB.begin();

    // Setup Canvas
    canvas.createSprite(M5Cardputer.Display.width(), M5Cardputer.Display.height());
    canvas.setTextFont(&fonts::FreeMonoBold12pt7b);
    canvas.setTextSize(0.8);

    // --- Initialize SD Card ---
    SPI.begin(SD_SPI_SCK_PIN, SD_SPI_MISO_PIN, SD_SPI_MOSI_PIN, -1);

    if(SD.begin(SD_SPI_CS_PIN, SPI, 25000000)) {
        isSDInitialized = true;
    } else {
        isSDInitialized = false;
    } 
    
    if (isSDInitialized) {
        initializeVaultFile();
    }

    playBeep(1000, 50); 
    
    if (isSDInitialized) {
        delay(200); 
        playBeep(1500, 50); 
    }

    currentState = STATE_KEYBOARD; 
}

// =================================================================
// 3. MAIN LOOP
// =================================================================
void loop() {
    M5Cardputer.update();
    
    if (currentState != STATE_KEYBOARD && (millis() - lastActivityTime >= MENU_TIMEOUT_MS)) {
        timeoutToKeyboard();
    }

    switch (currentState) {
        case STATE_KEYBOARD:
            runKeyboard();
            break;
        case STATE_PROMPT:
            runPrompt();
            break;
        case STATE_TOP_MENU:
            runTopMenu();
            break;
        case STATE_PASS_MENU:
            runPassMenu();
            break;
        case STATE_NOTE_MENU:
            runNoteMenu();
            break;
        case STATE_PASS_EDIT_MENU:
            runPassEditMenu();
            break;
        case STATE_CHANGE_MASTER:
            runChangeMaster();
            break;
    }
}

// =================================================================
// HELPER FUNCTIONS (Timer/Control)
// =================================================================

void timeoutToKeyboard() {
    if (currentState != STATE_KEYBOARD) {
        M5Cardputer.Display.clear();
        M5Cardputer.Display.setBrightness(0);
        currentState = STATE_KEYBOARD;
        repeatingKey = 0;
        currentPressedKeys.clear();
    }
}

void startMenuTimer() {
    lastActivityTime = millis();
}

void resetMenuTimer() {
    lastActivityTime = millis();
}

void playBeep(int freq, int duration) {
    M5Cardputer.Speaker.tone(freq, duration); 
    delay(duration); 
}

void sendEntryOverUSB(const String& data) {
    Keyboard.print(data);
    delay(50); 
}

bool checkForUniversalExit() {
    if ((currentState != STATE_KEYBOARD) && 
        (millis() - lastFnCtrlTime < 200)) { 
        return false; 
    }
    
    if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN) &&
        M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL) &&
        (millis() - lastFnCtrlTime > FN_CTRL_DEBOUNCE_MS)) {

        lastFnCtrlTime = millis();
        M5Cardputer.Display.clear();
        M5Cardputer.Display.setBrightness(0);
        currentState = STATE_KEYBOARD;
        repeatingKey = 0;
        currentPressedKeys.clear();
        return true;
    }
    return false;
}

// =================================================================
// 4. DRAWING FUNCTIONS
// =================================================================

void drawPromptScreen(const char* title, const String& input_masked, const char* status_msg) {
    canvas.fillScreen(BLACK);
    canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

    canvas.setTextSize(0.8);
    canvas.setTextColor(RED, BLACK);

    int titleWidth = canvas.textWidth(title);
    int titleX = (canvas.width() - titleWidth) / 2;
    canvas.drawString(title, titleX, 30);

    canvas.setTextSize(1.0);
    canvas.setTextColor(RED, BLACK);

    int inputWidth = canvas.textWidth(input_masked);
    int inputX = (canvas.width() - inputWidth) / 2;

    canvas.drawString(input_masked, inputX, 70);

    if (strlen(status_msg) > 0) {
        canvas.setTextSize(1.0);
        canvas.setTextColor(RED, BLACK);
        int statusWidth = canvas.textWidth(status_msg);
        int statusX = (canvas.width() - statusWidth) / 2;
        canvas.drawString(status_msg, statusX, 110);
    }

    canvas.pushSprite(0, 0);
}

void drawMenuList(const String& title, const std::vector<String>& items, int selectedIndex) {
    canvas.fillScreen(BLACK);
    canvas.setTextFont(&fonts::FreeMonoBold12pt7b);
    canvas.setTextSize(0.8);

    int startY = 0;
    if (title.length() > 0) {
        canvas.setTextColor(RED, BLACK);
        int titleWidth = canvas.textWidth(title);
        int titleX = (canvas.width() - titleWidth) / 2;
        canvas.drawString(title, titleX, 5);
        startY = 25; 
    }

    for (int i = 0; i < MAX_VISIBLE_BUTTONS; i++) {
        int itemIndex = i + visibleOffset;

        if (itemIndex >= items.size()) {
            break;
        }

        int yPos = startY + i * BUTTON_HEIGHT;

        if (itemIndex == selectedIndex) {
            canvas.fillRect(0, yPos, canvas.width(), BUTTON_HEIGHT, RED);
            canvas.setTextColor(WHITE, RED);
        } else {
            // Highlight special entries (e.g., Back/Add/Change Master)
            if (items[itemIndex].startsWith("!!") || items[itemIndex].startsWith("<-") || items[itemIndex].startsWith("->") || items[itemIndex].startsWith("🔑")) {
                 canvas.setTextColor(RED, BLACK);
            } else {
                 canvas.setTextColor(WHITE, BLACK);
            }
        }

        canvas.drawString(items[itemIndex], 5, yPos + 3);
    }
    canvas.pushSprite(0, 0);
}

// ------------------- DRAWING WRAPPERS -------------------

void drawTopMenu() {
    std::vector<String> labels;
    for (const auto& entry : TopMenuItems) {
        labels.push_back(entry.label);
    }
    drawMenuList("MAIN VAULT MENU", labels, SelectedMenuIndex);
}

void drawPassMenu() {
    drawMenuList("PASSWORD ENTRIES", PassMenuDisplayItems, SelectedMenuIndex);
}

void drawNoteMenu() {
    // Placeholder - will show a generic message for now
    std::vector<String> items = {"<- BACK", "!! NOTES NOT IMPLEMENTED YET !!"};
    drawMenuList("NOTE ENTRIES", items, SelectedMenuIndex);
}

void drawPassEditMenu() {
    canvas.fillScreen(BLACK);
    canvas.setTextFont(&fonts::FreeMonoBold12pt7b);
    canvas.setTextSize(0.8);

    if (currentEditIndex < 0 || currentEditIndex >= PassEntries.size()) {
        canvas.drawString("ERROR: Invalid Index", 10, 10);
        canvas.pushSprite(0, 0);
        return;
    }

    PasswordEntry& entry = PassEntries[currentEditIndex];
    
    // **********************************************
    // FIX APPLIED HERE: Show full password, username, and label
    // **********************************************
    String fields[] = {
        "<- BACK", 
        "1. LABEL: " + entry.label, 
        "2. USER: " + entry.username, 
        "3. PASS: " + entry.password, // Show full unmasked password
        "!! GENERATE PASS !!", 
        "!! DELETE ENTRY !!" 
    };

    for (int i = 0; i < 6; i++) { 
        int yPos = i * BUTTON_HEIGHT;

        bool is_special_option = (i == 0 || i == 4 || i == 5);

        if (i == PassDataIndex) {
            canvas.fillRect(0, yPos, canvas.width(), BUTTON_HEIGHT, RED);
            canvas.setTextColor(WHITE, RED);
        } else {
            if (is_special_option) {
                canvas.setTextColor(RED, BLACK);
            } else {
                canvas.setTextColor(WHITE, BLACK);
            }
        }

        canvas.drawString(fields[i], 5, yPos + 3);
    }

    canvas.pushSprite(0, 0);
}


// =================================================================
// 5. MODULAR LOGIC CORE
// =================================================================

/**
 * @brief Dynamically rebuilds the list of display items for the Passwords Menu.
 */
void buildPassMenuDisplayItems() {
    PassMenuDisplayItems.clear();
    PassMenuDisplayItems.push_back("<- BACK TO MAIN");
    for (const auto& entry : PassEntries) {
        PassMenuDisplayItems.push_back(entry.label);
    }
    PassMenuDisplayItems.push_back("-> ADD ENTRY <-");
}


/**
 * @brief Handles the action when ENTER is pressed on a menu item.
 */
bool handleMenuAction(State state, int index) {
    if (state == STATE_TOP_MENU) {
        if (index < TopMenuItems.size()) {
            State target = TopMenuItems[index].targetState;
            SelectedMenuIndex = 0; 
            visibleOffset = 0;
            
            if (target == STATE_CHANGE_MASTER) {
                currentState = STATE_CHANGE_MASTER;
            } else if (target == STATE_PASS_MENU) {
                buildPassMenuDisplayItems();
                currentState = STATE_PASS_MENU;
                drawPassMenu();
            } else if (target == STATE_NOTE_MENU) {
                // Placeholder logic for notes menu
                currentState = STATE_NOTE_MENU;
                drawNoteMenu();
            }
            resetMenuTimer();
            return true;
        }
    } 
    
    else if (state == STATE_PASS_MENU) {
        if (index == 0) {
            // <- BACK TO MAIN
            currentState = STATE_TOP_MENU;
            drawTopMenu();
            resetMenuTimer();
            return true;
        } else if (index == PassMenuDisplayItems.size() - 1) {
            // -> ADD ENTRY <-
            String label = getEntryInput("Enter Label:");
            if (currentState == STATE_KEYBOARD) return true;

            if (label.length() > 0) {
                String user = getEntryInput("Enter Username:");
                if (currentState == STATE_KEYBOARD) return true;
                String pass = getEntryInput("Enter Password (or Enter to Generate):");
                if (currentState == STATE_KEYBOARD) return true;

                if (pass.length() == 0) {
                    pass = generateStrongPassword();
                }

                PasswordEntry newEntry = {label, user, pass};
                PassEntries.push_back(newEntry);
                
                if (!saveData()) {
                    drawPromptScreen("ERROR", "", "Save Failed!");
                    delay(1000);
                    PassEntries.pop_back(); 
                } else {
                    buildPassMenuDisplayItems(); // Refresh list
                    SelectedMenuIndex = PassMenuDisplayItems.size() - 2;
                    if (SelectedMenuIndex >= visibleOffset + MAX_VISIBLE_BUTTONS) {
                        visibleOffset = SelectedMenuIndex - MAX_VISIBLE_BUTTONS + 1;
                    }
                }
            }
            if (currentState != STATE_KEYBOARD) { 
                 drawPassMenu(); 
                 resetMenuTimer(); 
            }
            return true;
        } else {
            // Selected a Password Entry (index 1 to N-2)
            currentEditIndex = index - 1; // Adjust index: 1st menu entry is 0th PassEntry
            PassDataIndex = 1; 
            currentState = STATE_PASS_EDIT_MENU;
            drawPassEditMenu();
            resetMenuTimer();
            return true;
        }
    }

    else if (state == STATE_NOTE_MENU) {
        if (index == 0) {
            // <- BACK TO MAIN
            currentState = STATE_TOP_MENU;
            drawTopMenu();
            resetMenuTimer();
            return true;
        }
        // Placeholder for future Note actions
        return false;
    }
    return false;
}


/**
 * @brief Handles up/down scrolling and ENTER/select for a generic menu.
 */
bool handleMenuNavigation(const std::vector<String>& items, int& selectedIndex, void (*drawFunction)()) {

    if (!M5Cardputer.Keyboard.isChange()) {
        return false;
    }

    resetMenuTimer(); 
    
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

    bool is_up_pressed = status.fn && (std::find(status.word.begin(), status.word.end(), ';') != status.word.end());
    bool is_down_pressed = status.fn && (std::find(status.word.begin(), status.word.end(), '.') != status.word.end());
    bool is_enter_pressed = status.enter; 

    if (is_up_pressed || is_down_pressed) {
        if (is_up_pressed) {
            if (selectedIndex > 0) {
                selectedIndex--;
                
                // FIX: When scrolling up, if the selected item goes above the visible window,
                // shift the visible window up by one.
                if (selectedIndex < visibleOffset) {
                    visibleOffset = selectedIndex;
                }
                
                drawFunction();
                delay(150);
            }
        } else { // is_down_pressed
            if (selectedIndex < items.size() - 1) {
                selectedIndex++;
                
                // FIX: When scrolling down, if the selected item goes below the visible window,
                // shift the visible window down by one.
                if (selectedIndex >= visibleOffset + MAX_VISIBLE_BUTTONS) {
                    visibleOffset++;
                }
                
                drawFunction();
                delay(150);
            }
        }
    }
    
    else if (is_enter_pressed) {
        handleMenuAction(currentState, selectedIndex);
        delay(150); 
    }

    return true;
}

// =================================================================
// 6. STATE LOGIC
// =================================================================

void runKeyboard() {
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    unsigned long currentMillis = millis();

    // TRANSITION CHECK (Fn+Ctrl)
    if (isSDInitialized) {
        if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN) &&
            M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL) &&
            (currentMillis - lastFnCtrlTime > FN_CTRL_DEBOUNCE_MS)) {

            lastFnCtrlTime = currentMillis;
            M5Cardputer.Display.clear();
            M5Cardputer.Display.setBrightness(100);
            
            loadEncryptedData();
            
            repeatingKey = 0;
            currentPressedKeys.clear(); 
            
            currentState = STATE_PROMPT;
            startMenuTimer();
            return;
        }
    }
    
    bool keySetChanged = false;
    
    if (status.hid_keys.size() != currentPressedKeys.size()) {
        keySetChanged = true;
    } else {
        std::vector<uint8_t> status_keys_sorted = status.hid_keys;
        std::vector<uint8_t> current_keys_sorted = currentPressedKeys;
        
        std::sort(status_keys_sorted.begin(), status_keys_sorted.end());
        std::sort(current_keys_sorted.begin(), current_keys_sorted.end());
        
        if (status_keys_sorted.size() == current_keys_sorted.size() &&
            !std::equal(status_keys_sorted.begin(), status_keys_sorted.end(), current_keys_sorted.begin())) {
            keySetChanged = true;
        }
    }
    
    if (keySetChanged) {
        currentPressedKeys.clear();
        for(uint8_t key_code : status.hid_keys) {
            currentPressedKeys.push_back(key_code);
        }

        KeyReport report = {0};
        report.modifiers = status.modifiers;

        uint8_t index = 0;
        for (auto i : status.hid_keys) {
            report.keys[index] = i;
            index++;
            if (index > 5) break;
        }
        
        bool isFnCombo = false;
        uint8_t virtualKey = 0;
        
        if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN) && status.hid_keys.size() == 1 && status.modifiers == 0) {
            uint8_t key_code = status.hid_keys[0];

            if (key_code == 0x2a) { virtualKey = KEY_DELETE; isFnCombo = true; }
            else if (key_code == 0x36) { virtualKey = KEY_LEFT_ARROW; isFnCombo = true; }
            else if (key_code == 0x33) { virtualKey = KEY_UP_ARROW; isFnCombo = true; }
            else if (key_code == 0x37) { virtualKey = KEY_DOWN_ARROW; isFnCombo = true; }
            else if (key_code == 0x38) { virtualKey = KEY_RIGHT_ARROW; isFnCombo = true; }
            else if (key_code == 0x35) { virtualKey = KEY_ESC; isFnCombo = true; }
            
            if (isFnCombo) {
                KeyReport fnReport = {0};
                fnReport.keys[0] = virtualKey;
                Keyboard.sendReport(&fnReport);
                Keyboard.releaseAll(); 
            }
        }
        
        if (!isFnCombo) {
            Keyboard.sendReport(&report);
            if (report.modifiers != 0 || report.keys[0] != 0) {
                 Keyboard.releaseAll();
            }
        }
        
        uint8_t newRepeatingKey = 0;
        
        if (status.hid_keys.size() == 1) {
             if (status.modifiers == 0 || status.modifiers == KEY_MOD_LSHIFT || status.modifiers == KEY_MOD_RSHIFT) {
                 newRepeatingKey = status.hid_keys[0];
             }
        } 
        
        else if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN) && status.modifiers == 0) {
             if (status.hid_keys.size() == 1) { 
                 uint8_t key_code = status.hid_keys[0];

                 if (key_code == 0x2a) { newRepeatingKey = KEY_DELETE; }
                 else if (key_code == 0x36) { newRepeatingKey = KEY_LEFT_ARROW; }
                 else if (key_code == 0x33) { newRepeatingKey = KEY_UP_ARROW; }
                 else if (key_code == 0x37) { newRepeatingKey = KEY_DOWN_ARROW; }
                 else if (key_code == 0x38) { newRepeatingKey = KEY_RIGHT_ARROW; }
                 else if (key_code == 0x35) { newRepeatingKey = KEY_ESC; }
             }
        }
        
        else if (status.hid_keys.size() > 1 && (status.modifiers & ~KEY_MOD_LSHIFT & ~KEY_MOD_RSHIFT) != 0) {
            if (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_BACKSPACE) != status.hid_keys.end()) {
                 newRepeatingKey = KEY_BACKSPACE;
            }
        }


        if (newRepeatingKey != repeatingKey) {
             repeatingKey = newRepeatingKey;
             if (repeatingKey != 0) {
                 lastKeyPressTime = currentMillis; 
                 lastKeyRepeatTime = currentMillis;
             } else {
                 lastKeyPressTime = 0;
             }
        }
    }

    if (repeatingKey != 0) {
        if (currentMillis - lastKeyPressTime >= KEY_REPEAT_DELAY_MS) {
            if (currentMillis - lastKeyRepeatTime >= KEY_REPEAT_RATE_MS) {
                
                KeyReport repeatReport = {0};
                repeatReport.keys[0] = repeatingKey;
                
                Keyboard_Class::KeysState current_status = M5Cardputer.Keyboard.keysState();
                
                repeatReport.modifiers = current_status.modifiers; 
                
                Keyboard.sendReport(&repeatReport);
                Keyboard.releaseAll();
                
                lastKeyRepeatTime = currentMillis; 
            }
        }
    }
}

void runPrompt() {
    if (checkForUniversalExit()) return;
    
    const char* prompt_msg = "ENTER VAULT PASSWORD";
    
    String input = getPasswordInput(prompt_msg);

    if (currentState == STATE_KEYBOARD) {
        return; 
    }

    if (input.length() > 0) {
        if (ENCRYPTED_VAULT_STRING.length() == 0) {
             loadEncryptedData();
        }

        String decryptedData = "";
        
        if (ENCRYPTED_VAULT_STRING.length() > 0) {
            decryptedData = decryptAES(ENCRYPTED_VAULT_STRING, input);
        } 

        if (decryptedData.length() > 0) {
            
            PassEntries.clear(); 

            int masterEnd = decryptedData.indexOf('|');
            if (masterEnd == -1) {
                MASTER_PASSWORD = decryptedData;
            } else {
                MASTER_PASSWORD = decryptedData.substring(0, masterEnd);
                String entriesString = decryptedData.substring(masterEnd + 1);

                int currentPos = 0;
                while(currentPos < entriesString.length()) {
                    int entryEnd = entriesString.indexOf('|', currentPos);
                    if (entryEnd == -1) entryEnd = entriesString.length();

                    String entry = entriesString.substring(currentPos, entryEnd);

                    int labelEnd = entry.indexOf(',');
                    int userEnd = entry.indexOf(',', labelEnd + 1);

                    if (labelEnd != -1 && userEnd != -1) {
                        PasswordEntry newEntry;
                        newEntry.label = entry.substring(0, labelEnd);
                        newEntry.username = entry.substring(labelEnd + 1, userEnd);
                        newEntry.password = entry.substring(userEnd + 1);
                        PassEntries.push_back(newEntry);
                    }

                    currentPos = entryEnd + 1;
                    if (entryEnd == entriesString.length()) break;
                }
            }
            
            M5Cardputer.Display.clear();
            
            SelectedMenuIndex = 0; 
            visibleOffset = 0; 

            currentState = STATE_TOP_MENU; // Transition to the NEW top menu state
            drawTopMenu(); 
            
            lastFnCtrlTime = millis(); 
            resetMenuTimer(); 
            return;
            
        } else {
            drawPromptScreen("INCORRECT", "", "Try Again.");
            delay(1000);
            resetMenuTimer(); 
        }
    }
}

void runTopMenu() {
    if (checkForUniversalExit()) return;
    if (!isSDInitialized) return; 

    std::vector<String> labels;
    for (const auto& entry : TopMenuItems) {
        labels.push_back(entry.label);
    }
    handleMenuNavigation(labels, SelectedMenuIndex, drawTopMenu);
}

void runPassMenu() {
    if (checkForUniversalExit()) return;
    if (!isSDInitialized) return; 

    // Uses the dynamically built PassMenuDisplayItems for navigation
    handleMenuNavigation(PassMenuDisplayItems, SelectedMenuIndex, drawPassMenu);
}

void runNoteMenu() {
    if (checkForUniversalExit()) return;
    if (!isSDInitialized) return; 

    // Navigation for the placeholder Note menu
    std::vector<String> items = {"<- BACK", "!! NOTES NOT IMPLEMENTED YET !!"};
    handleMenuNavigation(items, SelectedMenuIndex, drawNoteMenu);
}

void runPassEditMenu() {
    if (checkForUniversalExit()) return;
    if (!isSDInitialized) return; 

    PasswordEntry& entry = PassEntries[currentEditIndex];
    
    if (M5Cardputer.Keyboard.isChange()) { 
       
        resetMenuTimer(); 
        
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

        bool is_up_pressed = status.fn && (std::find(status.word.begin(), status.word.end(), ';') != status.word.end());
        bool is_down_pressed = status.fn && (std::find(status.word.begin(), status.word.end(), '.') != status.word.end());
        bool is_enter_pressed = status.enter; 

        if (is_up_pressed && PassDataIndex > 0) {
            PassDataIndex--;
            drawPassEditMenu();
            delay(150);
        } else if (is_down_pressed && PassDataIndex < 5) {
            PassDataIndex++;
            drawPassEditMenu();
            delay(150);
        }

        else if (is_enter_pressed && status.fn) {
            // Fn + Enter: Copy Field
            String data_to_send = "";
            switch (PassDataIndex) {
                case 1: data_to_send = entry.label; break;
                case 2: data_to_send = entry.username; break;
                case 3: data_to_send = entry.password; break;
            }

            if (data_to_send.length() > 0) {
                sendEntryOverUSB(data_to_send);
            } 
            drawPassEditMenu();
            resetMenuTimer();
            return;
        }

        else if (is_enter_pressed) {
            
            String new_value = "";
            bool saved = false;

            switch (PassDataIndex) {
                case 0: 
                    // Back
                    buildPassMenuDisplayItems(); // Refresh list to show potential label changes
                    currentState = STATE_PASS_MENU;
                    drawPassMenu();
                    resetMenuTimer();
                    return;

                case 1: 
                    // Edit Label
                    new_value = getEntryInput("NEW LABEL:");
                    if (currentState == STATE_KEYBOARD) return;
                    if (new_value.length() > 0) {
                        entry.label = new_value;
                        saved = saveData();
                    }
                    break;

                case 2: 
                    // Edit Username
                    new_value = getEntryInput("NEW USERNAME:");
                    if (currentState == STATE_KEYBOARD) return;
                    if (new_value.length() > 0) {
                        entry.username = new_value;
                        saved = saveData();
                    }
                    break;

                case 3: 
                    // Edit Password
                    new_value = getEntryInput("NEW PASSWORD (Leave blank to generate):"); 
                    if (currentState == STATE_KEYBOARD) return;
                    if (new_value.length() == 0) {
                        entry.password = generateStrongPassword();
                        saved = saveData();
                    } else if (new_value.length() > 0) {
                        entry.password = new_value;
                        saved = saveData();
                    }
                    break;

                case 4: 
                    // Generate Password
                    entry.password = generateStrongPassword();
                    saved = saveData();
                    break;

                case 5: { 
                    // Delete Entry
                    PassEntries.erase(PassEntries.begin() + currentEditIndex);
                    saved = saveData();
                    
                    if (saved) {
                        buildPassMenuDisplayItems(); // Refresh list after deletion
                        SelectedMenuIndex = 1; // Default to the first entry
                        currentState = STATE_PASS_MENU;
                        drawPassMenu();
                        resetMenuTimer();
                        return;
                    } else {
                        drawPromptScreen("SAVE FAILED", "", "Could not delete.");
                        delay(1000);
                        // Cannot easily restore, assume state needs user to manually fix data
                        currentState = STATE_PASS_MENU; 
                        drawPassMenu();
                        resetMenuTimer();
                        return;
                    }
                }
            }
            
            if (PassDataIndex >= 1 && PassDataIndex <= 4 && !saved) {
                 drawPromptScreen("ERROR", "", "Save Failed!");
                 delay(1000);
            }
            
            drawPassEditMenu();
            resetMenuTimer();
            delay(150);
        }
    }
}

void runChangeMaster() {
    if (checkForUniversalExit()) return;
    if (!isSDInitialized) {
        currentState = STATE_TOP_MENU; 
        drawTopMenu(); 
        resetMenuTimer(); 
        return;
    }

    String newPass1 = getPasswordInput("NEW PASSWORD");
    if (currentState == STATE_KEYBOARD) return; 

    if (newPass1.length() == 0) { 
        currentState = STATE_TOP_MENU;
        drawTopMenu();
        resetMenuTimer(); 
        return;
    }

    String newPass2 = getPasswordInput("CONFIRM NEW");
    if (currentState == STATE_KEYBOARD) return; 
    
    resetMenuTimer(); 

    if (newPass1 == newPass2) {
        
        String oldPass = MASTER_PASSWORD;
        MASTER_PASSWORD = newPass1; 

        if (!saveData()) {
             MASTER_PASSWORD = oldPass;
             drawPromptScreen("SAVE FAILED", "", "Using OLD PASS");
             delay(1000);
             resetMenuTimer();
        } else {
             drawPromptScreen("SUCCESS", "", "Master Password Changed");
             delay(1000);
             resetMenuTimer();
        }

    } else {
        drawPromptScreen("FAIL", "", "Passwords didn't match.");
        delay(1000);
        resetMenuTimer();
    }

    currentState = STATE_TOP_MENU;
    drawTopMenu();
}


// =================================================================
// 7. CRYPTO/STORAGE/INPUT FUNCTIONS (Kept from previous version)
// =================================================================

void initializeVaultFile() {
    if (SD.exists(SD_FILE_PATH)) {
        return;
    }
    
    String temp_master = MASTER_PASSWORD; 
    String rawData = temp_master; 
    String encryptedData = encryptAES(rawData, temp_master);

    File dataFile = SD.open(SD_FILE_PATH, FILE_WRITE);

    if (dataFile) {
        dataFile.print(encryptedData);
        dataFile.close();
    }
}

void deriveKey(const String& masterPass, uint8_t* key_out) {
    if (masterPass.length() == 0) {
        memset(key_out, 0, AES_KEY_SIZE);
        return;
    }

    SHA256 sha256;
    const uint8_t* password = (const uint8_t*)masterPass.c_str();
    size_t passwordLen = masterPass.length();
    
    uint8_t T[SHA256::HASH_SIZE]; 
    uint8_t U[SHA256::HASH_SIZE]; 
    uint8_t i_be[4]; 
    
    size_t numBlocks = 1; 

    for (size_t block = 1; block <= numBlocks; ++block) {
        
        i_be[0] = (uint8_t)(block >> 24);
        i_be[1] = (uint8_t)(block >> 16);
        i_be[2] = (uint8_t)(block >> 8);
        i_be[3] = (uint8_t)block;

        sha256.resetHMAC(password, passwordLen);
        sha256.update(PBKDF2_SALT, sizeof(PBKDF2_SALT));
        sha256.update(i_be, 4);
        sha256.finalizeHMAC(password, passwordLen, T, SHA256::HASH_SIZE);
        
        memcpy(U, T, SHA256::HASH_SIZE); 
        
        for (size_t j = 2; j <= PBKDF2_ITERATIONS; ++j) {
            
            sha256.resetHMAC(password, passwordLen);
            sha256.update(U, SHA256::HASH_SIZE);
            sha256.finalizeHMAC(password, passwordLen, U, SHA256::HASH_SIZE);

            for (size_t k = 0; k < SHA256::HASH_SIZE; ++k) {
                T[k] ^= U[k];
            }
        }
        
        memcpy(key_out, T, SHA256::HASH_SIZE);
    }
}

String encryptAES(const String& data, const String& masterPass) {
    if (data.length() == 0) return "";

    uint8_t key[AES_KEY_SIZE];
    deriveKey(masterPass, key);

    size_t dataLen = data.length();
    size_t paddedLen = dataLen + (AES_BLOCK_SIZE - (dataLen % AES_BLOCK_SIZE));
    
    uint8_t buffer[paddedLen];
    uint8_t cipherText[paddedLen];
    
    memcpy(buffer, data.c_str(), dataLen);
    uint8_t pad_val = paddedLen - dataLen;
    memset(buffer + dataLen, pad_val, pad_val); 

    uint8_t local_IV[AES_BLOCK_SIZE];
    memcpy(local_IV, IV, AES_BLOCK_SIZE); 
    
    aes_cbc.setKey(key, AES_KEY_SIZE);
    aes_cbc.setIV(local_IV, AES_BLOCK_SIZE);
    aes_cbc.encrypt(cipherText, buffer, paddedLen);

    uint8_t hmac_tag[HMAC_TAG_SIZE];
    sha256_hmac.resetHMAC(key, AES_KEY_SIZE);
    sha256_hmac.update(cipherText, paddedLen);
    sha256_hmac.finalizeHMAC(key, AES_KEY_SIZE, hmac_tag, HMAC_TAG_SIZE);

    String hexString = "";

    for (size_t i = 0; i < paddedLen; i++) {
        char hex[3];
        sprintf(hex, "%02X", cipherText[i]);
        hexString += hex;
    }
    for (size_t i = 0; i < HMAC_TAG_SIZE; i++) {
        char hex[3];
        sprintf(hex, "%02X", hmac_tag[i]);
        hexString += hex;
    }

    return String(dataLen) + ":" + hexString;
}

String decryptAES(const String& encryptedData, const String& masterPass) {
    if (encryptedData.length() == 0) return "";

    int separatorPos = encryptedData.indexOf(':');
    if (separatorPos == -1) return "";

    size_t actualDataLen = encryptedData.substring(0, separatorPos).toInt();
    String hexString = encryptedData.substring(separatorPos + 1);

    if (hexString.length() % 2 != 0) return "";

    size_t totalHexLen = hexString.length() / 2;
    size_t hmac_size = HMAC_TAG_SIZE;
    
    if (totalHexLen < hmac_size || (totalHexLen - hmac_size) % AES_BLOCK_SIZE != 0) return "";

    size_t cipherTextLen = totalHexLen - hmac_size;

    uint8_t buffer[cipherTextLen]; 
    uint8_t received_tag[hmac_size];

    for (size_t i = 0; i < cipherTextLen; i++) {
        String byteStr = hexString.substring(i * 2, i * 2 + 2);
        buffer[i] = (uint8_t)strtol(byteStr.c_str(), NULL, 16);
    }
    for (size_t i = 0; i < hmac_size; i++) {
        String byteStr = hexString.substring((cipherTextLen + i) * 2, (cipherTextLen + i) * 2 + 2);
        received_tag[i] = (uint8_t)strtol(byteStr.c_str(), NULL, 16);
    }

    uint8_t key[AES_KEY_SIZE];
    deriveKey(masterPass, key);

    uint8_t expected_tag[hmac_size];
    sha256_hmac.resetHMAC(key, AES_KEY_SIZE);
    sha256_hmac.update(buffer, cipherTextLen);
    sha256_hmac.finalizeHMAC(key, AES_KEY_SIZE, expected_tag, hmac_size);

    bool auth_success = true;
    for(size_t i = 0; i < hmac_size; ++i) {
        if (received_tag[i] != expected_tag[i]) {
            auth_success = false;
            break;
        }
    }

    if (!auth_success) {
        return ""; 
    }

    uint8_t local_IV[AES_BLOCK_SIZE];
    memcpy(local_IV, IV, AES_BLOCK_SIZE);

    aes_cbc.setKey(key, AES_KEY_SIZE);
    aes_cbc.setIV(local_IV, AES_BLOCK_SIZE);

    aes_cbc.decrypt(buffer, buffer, cipherTextLen);

    size_t paddingLen = buffer[cipherTextLen - 1];

    if (paddingLen < 1 || paddingLen > AES_BLOCK_SIZE || actualDataLen != (cipherTextLen - paddingLen)) {
        for(size_t i = 1; i <= paddingLen; ++i) {
            if(buffer[cipherTextLen - i] != paddingLen) {
                return ""; 
            }
        }
        if (actualDataLen != (cipherTextLen - paddingLen)) {
             return "";
        }
    }
    
    buffer[actualDataLen] = '\0';
    return String((char*)buffer); 
}

bool saveData() {
    if (!isSDInitialized) return false;
    
    // Save Master Password first
    String rawData = MASTER_PASSWORD;

    // Then save all Password Entries
    for (size_t i = 0; i < PassEntries.size(); ++i) {
        rawData += "|";
        rawData += PassEntries[i].label + "," + PassEntries[i].username + "," + PassEntries[i].password;
    }
    // Add placeholder for Notes or future data types if necessary, though currently, we only save passwords.

    String encryptedData = encryptAES(rawData, MASTER_PASSWORD);

    File dataFile = SD.open(SD_FILE_PATH, FILE_WRITE);

    if (dataFile) {
        dataFile.print(encryptedData);
        dataFile.close();
        ENCRYPTED_VAULT_STRING = encryptedData; 
        return true;
    }

    return false;
}

bool loadEncryptedData() {
    if (!isSDInitialized) {
        ENCRYPTED_VAULT_STRING = "";
        return false;
    }

    File dataFile = SD.open(SD_FILE_PATH);

    if (!dataFile || dataFile.isDirectory()) {
        ENCRYPTED_VAULT_STRING = ""; 
        return false;
    }

    ENCRYPTED_VAULT_STRING = "";
    while (dataFile.available()) {
        ENCRYPTED_VAULT_STRING += (char)dataFile.read();
    }
    dataFile.close();

    return ENCRYPTED_VAULT_STRING.length() > 0;
}

String generateStrongPassword() {
    const char* upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char* lower = "abcdefghijklmnopqrstuvwxyz";
    const char* numbers = "0123456789";
    const char* symbols = "!@#$%^&*()-_+=[]{}<>,.?/~";

    String all_chars = String(upper) + String(lower) + String(lower) + String(numbers) + String(symbols);
    int len = all_chars.length();

    String password = "";
    const int PASSWORD_LENGTH = 16;

    password += upper[rand() % strlen(upper)];
    password += lower[rand() % strlen(lower)];
    password += numbers[rand() % strlen(numbers)];
    password += symbols[rand() % strlen(symbols)];

    while (password.length() < PASSWORD_LENGTH) {
        password += all_chars[rand() % len];
    }

    char password_arr[PASSWORD_LENGTH + 1];
    password.toCharArray(password_arr, PASSWORD_LENGTH + 1);
    for(int i = PASSWORD_LENGTH - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        char temp = password_arr[i];
        password_arr[i] = password_arr[j];
        password_arr[j] = temp;
    }
    return String(password_arr);
}

String getPasswordInput(const char* prompt, const String& expected_password) {
    String input = "";
    const char* status_msg = "";

    drawPromptScreen(prompt, "", status_msg);

    while (true) {
        M5Cardputer.update();
        if (checkForUniversalExit()) return "";
        
        if (millis() - lastActivityTime >= MENU_TIMEOUT_MS) {
            timeoutToKeyboard();
            return "";
        }

        if (M5Cardputer.Keyboard.isChange()) {
            
            resetMenuTimer(); 
            
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

            if (M5Cardputer.Keyboard.isPressed()) {

                for (auto c : status.word) {
                    input += c;
                }

                if (status.del && input.length() > 0) {
                    input.remove(input.length() - 1);
                }

                if (status.enter) {
                    if (expected_password.length() > 0 && input != expected_password) {
                        input = "";
                        drawPromptScreen(prompt, "", "INCORRECT");
                        delay(500);
                        status_msg = "";
                        continue;
                    }
                    return input;
                }

                String masked_input = "";
                for(int i=0; i < input.length(); i++) {
                    masked_input += '*';
                }
                drawPromptScreen(prompt, masked_input, status_msg);
                
                delay(100);
            }
        }
    }
}

String getEntryInput(const char* prompt) {
    String input = "";

    // --- Switch from Display to Canvas for consistency ---
    canvas.fillScreen(BLACK);
    canvas.setTextFont(&fonts::FreeMonoBold12pt7b);
    canvas.setTextSize(1.0); 

    // Draw the prompt text
    canvas.setTextColor(RED, BLACK); 
    canvas.drawString(prompt, 10, 10);
    canvas.pushSprite(0, 0); // Display the initial prompt

    while (true) {
        M5Cardputer.update();
        if (checkForUniversalExit()) return "";

        if (millis() - lastActivityTime >= MENU_TIMEOUT_MS) {
            timeoutToKeyboard();
            return "";
        }

        if (M5Cardputer.Keyboard.isChange()) {
            
            resetMenuTimer();
            
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

            if (M5Cardputer.Keyboard.isPressed()) {
                for (auto c : status.word) {
                    input += c;
                }
                if (status.del && input.length() > 0) {
                    input.remove(input.length() - 1);
                }
                if (status.enter) {
                    // Clear the input area before returning
                    canvas.fillScreen(BLACK);
                    canvas.pushSprite(0, 0);
                    return input;
                }

                // --- Drawing logic using Canvas ---
                // Clear the previous input line on the canvas
                canvas.fillRect(0, 30, canvas.width(), 20, BLACK);
                
                // Draw the new input string
                canvas.setTextColor(WHITE, BLACK); 
                canvas.drawString(input, 10, 30);
                
                // Push the updated canvas to the display
                canvas.pushSprite(0, 0); 
                // --- End Canvas Drawing Logic ---
                
                delay(100);
            }
        }
    }
}